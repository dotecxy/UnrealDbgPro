// ApcInject32 —— 32 位 APC 注入辅助进程
//
// 为什么需要它：
//   64 位进程对 WOW64 线程调用 QueueUserAPC 时，APC 会在该线程的 64 位上下文里执行，
//   32 位 stub 会被按 x64 解码，目标进程直接崩溃（实测 KERNELBASE 0xC0000005）。
//   让同为 32 位的进程来排队，APC 才会落到 32 位上下文，LoadLibraryW 才能正常执行。
//
// 用法：ApcInject32.exe <pid> <dll 绝对路径>
// 退出码：0 成功 / 1 参数错误 / 2 打开进程失败 / 3 目标不是 32 位进程
//        4 DLL 不是 32 位模块 / 5 申请内存失败 / 6 写入失败
//        7 没有可排队的线程 / 8 等待模块加载超时

#include <windows.h>
#include <tlhelp32.h>

#include <string>
#include <vector>

namespace
{
    constexpr size_t kPageSize = 0x2000;
    constexpr size_t kPathOffset = 0x000;
    constexpr size_t kStubOffset = 0x800;
    constexpr size_t kResultOffset = 0x1000;
    constexpr DWORD kWaitMs = 8000;

    bool ReadPeMachine(const std::wstring& path, WORD& machine)
    {
        machine = 0;
        const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        IMAGE_DOS_HEADER dos{};
        DWORD read = 0;
        bool ok = false;
        if (ReadFile(file, &dos, sizeof(dos), &read, nullptr) && read == sizeof(dos) &&
            dos.e_magic == IMAGE_DOS_SIGNATURE)
        {
            IMAGE_NT_HEADERS32 nt{};
            if (SetFilePointer(file, dos.e_lfanew, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER &&
                ReadFile(file, &nt, sizeof(nt), &read, nullptr) &&
                read >= sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) && nt.Signature == IMAGE_NT_SIGNATURE)
            {
                machine = nt.FileHeader.Machine;
                ok = true;
            }
        }
        CloseHandle(file);
        return ok;
    }

    // 目标进程里 32 位 kernel32 的基址。系统 DLL 在同一启动会话内基址一致，
    // 但仍然按目标实际加载地址换算，避免个别场景（强制重定位）算错。
    uintptr_t QueryRemoteKernel32(const DWORD pid)
    {
        const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return 0;
        }
        uintptr_t base = 0;
        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        for (BOOL ok = Module32FirstW(snapshot, &entry); ok; ok = Module32NextW(snapshot, &entry))
        {
            if (_wcsicmp(entry.szModule, L"kernel32.dll") == 0)
            {
                base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
                break;
            }
        }
        CloseHandle(snapshot);
        return base;
    }

    // x86 stub：栈按 16 字节对齐后调用 LoadLibraryW，并回写返回值与错误码。
    std::vector<BYTE> BuildStub(const uintptr_t pathAddress, const uintptr_t loadLibraryAddress,
        const uintptr_t getLastErrorAddress, const uintptr_t resultAddress)
    {
        const auto appendDword = [](std::vector<BYTE>& code, const uintptr_t value)
        {
            for (int index = 0; index < 4; ++index)
            {
                code.push_back(static_cast<BYTE>((value >> (index * 8)) & 0xFF));
            }
        };

        std::vector<BYTE> code;
        code.reserve(56);
        code.push_back(0x9C);                            // pushfd
        code.push_back(0x55);                            // push ebp
        code.insert(code.end(), { 0x8B, 0xEC });         // mov ebp, esp
        code.insert(code.end(), { 0x83, 0xE4, 0xF0 });   // and esp, 0FFFFFFF0h
        // LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH)：让被注入 DLL 的
        // 依赖从它自己所在目录解析（默认搜索顺序只看目标 exe 目录，必然 ERROR_MOD_NOT_FOUND）。
        code.insert(code.end(), { 0x83, 0xEC, 0x14 });   // sub esp, 14h（三次 push 后 16 对齐）
        code.push_back(0x68);                            // push LOAD_WITH_ALTERED_SEARCH_PATH
        appendDword(code, 0x8);
        code.insert(code.end(), { 0x6A, 0x00 });         // push 0（hFile 为空）
        code.push_back(0x68);                            // push <path>
        appendDword(code, pathAddress);
        code.push_back(0xB8);                            // mov eax, LoadLibraryExW
        appendDword(code, loadLibraryAddress);
        code.insert(code.end(), { 0xFF, 0xD0 });         // call eax
        code.push_back(0xA3);                            // mov [result], eax
        appendDword(code, resultAddress);
        code.push_back(0xB8);                            // mov eax, GetLastError
        appendDword(code, getLastErrorAddress);
        code.insert(code.end(), { 0xFF, 0xD0 });         // call eax
        code.push_back(0xA3);                            // mov [result+4], eax
        appendDword(code, resultAddress + 4);
        code.insert(code.end(), { 0x8B, 0xE5 });         // mov esp, ebp
        code.push_back(0x5D);                            // pop ebp
        code.push_back(0x9D);                            // popfd
        // 用户态 APC 例程是 stdcall 单参数，由被调方清理 4 字节参数。
        code.insert(code.end(), { 0xC2, 0x04, 0x00 });    // ret 4
        return code;
    }

    bool WaitForModule(const DWORD pid, const std::wstring& moduleName)
    {
        const ULONGLONG deadline = GetTickCount64() + kWaitMs;
        while (GetTickCount64() <= deadline)
        {
            const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (snapshot != INVALID_HANDLE_VALUE)
            {
                MODULEENTRY32W entry{};
                entry.dwSize = sizeof(entry);
                bool found = false;
                for (BOOL ok = Module32FirstW(snapshot, &entry); ok; ok = Module32NextW(snapshot, &entry))
                {
                    if (_wcsicmp(entry.szModule, moduleName.c_str()) == 0)
                    {
                        found = true;
                        break;
                    }
                }
                CloseHandle(snapshot);
                if (found)
                {
                    return true;
                }
            }
            Sleep(100);
        }
        return false;
    }
}

int wmain(const int argc, wchar_t** argv)
{
    if (argc < 3)
    {
        return 1;
    }

    const DWORD pid = static_cast<DWORD>(wcstoul(argv[1], nullptr, 10));
    const std::wstring dllPath = argv[2];
    if (pid == 0 || dllPath.empty())
    {
        return 1;
    }

    const HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (process == nullptr)
    {
        return 2;
    }

    BOOL wow64 = FALSE;
    if (!IsWow64Process(process, &wow64) || wow64 == FALSE)
    {
        CloseHandle(process);
        return 3;
    }

    WORD machine = 0;
    if (!ReadPeMachine(dllPath, machine) || machine != IMAGE_FILE_MACHINE_I386)
    {
        CloseHandle(process);
        return 4;
    }

    const std::wstring moduleName = dllPath.substr(dllPath.find_last_of(L"\\/") + 1);
    const size_t pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);

    // 目标 kernel32 的 LoadLibraryExW / GetLastError：同位数，直接按基址差换算
    const HMODULE localKernel32 = GetModuleHandleW(L"kernel32.dll");
    const uintptr_t localLoadLibrary = reinterpret_cast<uintptr_t>(GetProcAddress(localKernel32, "LoadLibraryExW"));
    const uintptr_t localGetLastError = reinterpret_cast<uintptr_t>(GetProcAddress(localKernel32, "GetLastError"));
    if (localKernel32 == nullptr || localLoadLibrary == 0 || localGetLastError == 0)
    {
        CloseHandle(process);
        return 5;
    }

    uintptr_t remoteKernel32 = QueryRemoteKernel32(pid);
    if (remoteKernel32 == 0)
    {
        remoteKernel32 = reinterpret_cast<uintptr_t>(localKernel32);
    }
    const uintptr_t delta = remoteKernel32 - reinterpret_cast<uintptr_t>(localKernel32);
    const uintptr_t remoteLoadLibrary = localLoadLibrary + delta;
    const uintptr_t remoteGetLastError = localGetLastError + delta;

    auto* page = static_cast<BYTE*>(VirtualAllocEx(process, nullptr, kPageSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (page == nullptr)
    {
        CloseHandle(process);
        return 5;
    }

    const uintptr_t pageBase = reinterpret_cast<uintptr_t>(page);
    const auto pathAddress = pageBase + kPathOffset;
    const auto stubAddress = pageBase + kStubOffset;
    const auto resultAddress = pageBase + kResultOffset;

    SIZE_T written = 0;
    bool ok = WriteProcessMemory(process, reinterpret_cast<LPVOID>(pathAddress), dllPath.c_str(),
        pathBytes, &written) && written == pathBytes;

    const std::vector<BYTE> stub = BuildStub(pathAddress, remoteLoadLibrary, remoteGetLastError, resultAddress);
    if (ok)
    {
        written = 0;
        ok = WriteProcessMemory(process, reinterpret_cast<LPVOID>(stubAddress), stub.data(),
            stub.size(), &written) && written == stub.size();
    }
    if (!ok)
    {
        VirtualFreeEx(process, page, 0, MEM_RELEASE);
        CloseHandle(process);
        return 6;
    }

    // 向所有线程排队：只要有一个线程处于可警示等待就会执行
    int queued = 0;
    const HANDLE threads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (threads != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        for (BOOL more = Thread32First(threads, &entry); more; more = Thread32Next(threads, &entry))
        {
            if (entry.th32OwnerProcessID != pid)
            {
                continue;
            }
            const HANDLE thread = OpenThread(THREAD_SET_CONTEXT, FALSE, entry.th32ThreadID);
            if (thread == nullptr)
            {
                continue;
            }
            if (QueueUserAPC(reinterpret_cast<PAPCFUNC>(stubAddress), thread, 0) != 0)
            {
                ++queued;
            }
            CloseHandle(thread);
        }
        CloseHandle(threads);
    }

    if (queued == 0)
    {
        VirtualFreeEx(process, page, 0, MEM_RELEASE);
        CloseHandle(process);
        return 7;
    }

    const bool loaded = WaitForModule(pid, moduleName);
    if (!loaded)
    {
        VirtualFreeEx(process, page, 0, MEM_RELEASE);
        CloseHandle(process);
        return 8;
    }

    // 成功：远程页留 5 秒后再回收，避免 stub 尚未从栈上返回就被释放
    Sleep(5000);
    VirtualFreeEx(process, page, 0, MEM_RELEASE);
    CloseHandle(process);
    return 0;
}
