#include "../dllmain.h"
#include "../Channels/DispatchData.h"
#include "../Init/InitNTDevice.h"
#include "ApcDllInject.h"

#include <TlHelp32.h>

// APC 注入远程 DLL 的实现说明
// ---------------------------------------------------------------------------
// 目标进程里最终执行的是我们写进目标内存的一小段 stub，内容等价于：
//     LoadLibraryW(L"<dll 路径>");
// 这段 stub 通过下面三条通道之一进入目标进程：
//   1. 驱动通道：IOCTL_CREATE_REMOTE_THREAD -> KeInsertQueueApc（内核排队 APC）；
//   2. 用户态通道：OpenThread + QueueUserAPC（排队 APC，线程需处于可警示等待）；
//   3. 线程劫持：SuspendThread + SetThreadContext 把 Rip 指向 stub，stub 执行完
//      恢复全部易失寄存器与原 Rip 后跳回，目标线程继续原流程。
//
// 三条通道都不创建新线程，因此不会留下 CreateRemoteThread 这类痕迹。
namespace
{
    constexpr size_t kRemotePageSize = 0x2000;
    constexpr size_t kPathOffset = 0x000;        // UNICODE 路径
    constexpr size_t kPathLimitBytes = 0x800;    // 路径最多 1024 个字符
    constexpr size_t kApcStubOffset = 0x800;     // APC 用 stub（正常返回）
    constexpr size_t kResultOffset = 0x1000;     // stub 回写 LoadLibraryW 返回值的位置
    constexpr DWORD kStageWaitMs = 2000;         // 每条通道等待模块出现的时间
    constexpr DWORD kReclaimDelayMs = 10000;     // 远程页延迟回收，避免 stub 未返回就被释放
    constexpr size_t kTebWin32ThreadInfoOffset = 0x78;

    struct PendingFree
    {
        DWORD pid{};
        ULONGLONG tick{};
        ULONGLONG remoteAddress{};
    };

    std::mutex g_pendingFreeMutex;
    std::vector<PendingFree> g_pendingFree;

    // 注入需要能操作目标进程的调试权限；没有它 OpenProcess 会直接失败。
    bool EnableDebugPrivilege()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        {
            logger.LogError("启用调试权限：OpenProcessToken", GetLastError());
            return false;
        }

        LUID luid{};
        if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
        {
            const DWORD error = GetLastError();
            CloseHandle(token);
            logger.LogError("启用调试权限：LookupPrivilegeValue(SeDebugPrivilege)", error);
            return false;
        }

        TOKEN_PRIVILEGES privileges{};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        const BOOL result = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
        const DWORD error = GetLastError();
        CloseHandle(token);

        // ERROR_NOT_ALL_ASSIGNED 表示令牌里没有该权限（非管理员），继续尝试即可。
        if (!result || error == ERROR_NOT_ALL_ASSIGNED)
        {
            logger.Log("[DEBUG] 调试权限未完全启用：result=%d error=%lu（继续尝试注入）",
                result, static_cast<unsigned long>(error));
            return false;
        }
        return true;
    }

    // 读取待注入 DLL 的 PE 机器类型，用于在注入前拦掉位数不匹配的请求。
    bool ReadPeMachine(const std::wstring& path, WORD& machine)
    {
        machine = 0;
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            logger.LogError("读取 DLL 文件头：CreateFileW", GetLastError());
            return false;
        }

        IMAGE_DOS_HEADER dos{};
        DWORD read = 0;
        bool ok = false;
        if (ReadFile(file, &dos, sizeof(dos), &read, nullptr) && read == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE)
        {
            IMAGE_NT_HEADERS32 nt{};   // 只需要 FileHeader + Signature，32/64 位布局前缀一致
            if (SetFilePointer(file, dos.e_lfanew, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER &&
                ReadFile(file, &nt, sizeof(nt), &read, nullptr) && read >= sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) &&
                nt.Signature == IMAGE_NT_SIGNATURE)
            {
                machine = nt.FileHeader.Machine;
                ok = true;
            }
        }
        if (!ok)
        {
            logger.LogError("读取 DLL 文件头：ReadFile/PE 校验", GetLastError());
        }
        CloseHandle(file);
        return ok;
    }

    // 目标是否为 WOW64（32 位）进程。优先 IsWow64Process2，老系统回退 IsWow64Process。
    bool QueryTargetIsWow64(HANDLE hProcess, bool& isWow64)
    {
        isWow64 = false;
        using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
        const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32 != nullptr)
        {
            const auto isWow64Process2 = reinterpret_cast<IsWow64Process2Fn>(
                GetProcAddress(kernel32, "IsWow64Process2"));
            if (isWow64Process2 != nullptr)
            {
                USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
                USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
                if (!isWow64Process2(hProcess, &processMachine, &nativeMachine))
                {
                    logger.LogError("检测目标进程架构：IsWow64Process2", GetLastError());
                    return false;
                }
                isWow64 = processMachine != IMAGE_FILE_MACHINE_UNKNOWN;
                return true;
            }
        }

        BOOL wow64 = FALSE;
        if (!IsWow64Process(hProcess, &wow64))
        {
            logger.LogError("检测目标进程架构：IsWow64Process", GetLastError());
            return false;
        }
        isWow64 = wow64 != FALSE;
        return true;
    }

    // 通过 Toolhelp 取目标进程里某个模块的基址。
    uintptr_t QueryRemoteModuleBase(const DWORD pid, const wchar_t* moduleName, bool* found = nullptr)
    {
        if (found != nullptr)
        {
            *found = false;
        }
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
            if (_wcsicmp(entry.szModule, moduleName) == 0)
            {
                base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
                if (found != nullptr)
                {
                    *found = true;
                }
                break;
            }
        }
        CloseHandle(snapshot);
        return base;
    }

    void AppendQword(std::vector<BYTE>& code, const uintptr_t value)
    {
        for (int index = 0; index < 8; ++index)
        {
            code.push_back(static_cast<BYTE>((value >> (index * 8)) & 0xFF));
        }
    }

    void AppendDword(std::vector<BYTE>& code, const uintptr_t value)
    {
        for (int index = 0; index < 4; ++index)
        {
            code.push_back(static_cast<BYTE>((value >> (index * 8)) & 0xFF));
        }
    }

    bool ReadRemote(const HANDLE hProcess, const uintptr_t address, void* buffer, const size_t size)
    {
        SIZE_T read = 0;
        return ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address), buffer, size, &read) &&
            read == size;
    }

    // 取 WOW64 目标进程的 32 位 PEB 地址（NtQueryInformationProcess 的 ProcessWow64Information）。
    uintptr_t QueryWow64Peb(const HANDLE hProcess)
    {
        using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
        {
            return 0;
        }
        const auto queryInformation = reinterpret_cast<NtQueryInformationProcessFn>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (queryInformation == nullptr)
        {
            return 0;
        }

        ULONG_PTR peb32 = 0;
        const LONG status = queryInformation(hProcess, 26 /*ProcessWow64Information*/, &peb32, sizeof(peb32), nullptr);
        if (status < 0)
        {
            logger.Log("[DEBUG] 查询 32 位 PEB 失败：NTSTATUS=0x%08lX", static_cast<unsigned long>(status));
            return 0;
        }
        return static_cast<uintptr_t>(peb32);
    }

    // 在 WOW64 目标里按 32 位模块名找基址：走 PEB32 -> Ldr -> InLoadOrderModuleList。
    // Toolhelp 在 64 位进程中枚举 WOW64 目标的模块列表并不可靠，这里直接读 PEB。
    uintptr_t QueryWow64ModuleBase(const HANDLE hProcess, const wchar_t* moduleName)
    {
        const uintptr_t peb32 = QueryWow64Peb(hProcess);
        if (peb32 == 0)
        {
            return 0;
        }

        uint32_t ldr = 0;
        if (!ReadRemote(hProcess, peb32 + 0x0C, &ldr, sizeof(ldr)) || ldr == 0)
        {
            logger.Log("[DEBUG] 读取 32 位 PEB.Ldr 失败");
            return 0;
        }

        uint32_t head = 0;   // InLoadOrderModuleList.Flink
        if (!ReadRemote(hProcess, static_cast<uintptr_t>(ldr) + 0x0C, &head, sizeof(head)) || head == 0)
        {
            logger.Log("[DEBUG] 读取 32 位 PEB_LDR_DATA 失败");
            return 0;
        }

        const uint32_t listHead = static_cast<uint32_t>(ldr) + 0x0C;
        uint32_t entry = head;
        for (int guard = 0; guard < 512 && entry != 0 && entry != listHead; ++guard)
        {
            uint32_t dllBase = 0;
            uint32_t nameBuffer = 0;
            uint16_t nameLength = 0;
            if (!ReadRemote(hProcess, static_cast<uintptr_t>(entry) + 0x18, &dllBase, sizeof(dllBase)) ||
                !ReadRemote(hProcess, static_cast<uintptr_t>(entry) + 0x2C, &nameLength, sizeof(nameLength)) ||
                !ReadRemote(hProcess, static_cast<uintptr_t>(entry) + 0x30, &nameBuffer, sizeof(nameBuffer)))
            {
                break;
            }

            if (dllBase != 0 && nameLength >= sizeof(wchar_t) && nameLength <= 260 * sizeof(wchar_t) && nameBuffer != 0)
            {
                wchar_t name[261]{};
                const size_t bytes = (std::min)(static_cast<size_t>(nameLength), sizeof(name) - sizeof(wchar_t));
                if (ReadRemote(hProcess, static_cast<uintptr_t>(nameBuffer), name, bytes) &&
                    _wcsicmp(name, moduleName) == 0)
                {
                    return static_cast<uintptr_t>(dllBase);
                }
            }

            uint32_t next = 0;
            if (!ReadRemote(hProcess, static_cast<uintptr_t>(entry), &next, sizeof(next)))
            {
                break;
            }
            entry = next;
        }
        return 0;
    }

    // 在目标进程的 32 位模块里解析导出函数地址（只读，不修改目标）。
    uintptr_t ResolveRemoteExport32(const HANDLE hProcess, const uintptr_t moduleBase, const char* functionName)
    {
        IMAGE_DOS_HEADER dos{};
        if (moduleBase == 0 || !ReadRemote(hProcess, moduleBase, &dos, sizeof(dos)) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE)
        {
            return 0;
        }

        IMAGE_NT_HEADERS32 nt{};
        if (!ReadRemote(hProcess, moduleBase + static_cast<uintptr_t>(dos.e_lfanew), &nt, sizeof(nt)) ||
            nt.Signature != IMAGE_NT_SIGNATURE)
        {
            return 0;
        }

        const IMAGE_DATA_DIRECTORY& directory =
            nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (directory.VirtualAddress == 0 || directory.Size == 0)
        {
            return 0;
        }

        IMAGE_EXPORT_DIRECTORY exports{};
        if (!ReadRemote(hProcess, moduleBase + directory.VirtualAddress, &exports, sizeof(exports)))
        {
            return 0;
        }

        for (DWORD index = 0; index < exports.NumberOfNames; ++index)
        {
            DWORD nameRva = 0;
            if (!ReadRemote(hProcess, moduleBase + exports.AddressOfNames + index * sizeof(DWORD),
                &nameRva, sizeof(nameRva)))
            {
                break;
            }

            char name[128]{};
            if (!ReadRemote(hProcess, moduleBase + nameRva, name, sizeof(name) - 1))
            {
                continue;
            }
            if (strcmp(name, functionName) != 0)
            {
                continue;
            }

            WORD ordinal = 0;
            if (!ReadRemote(hProcess, moduleBase + exports.AddressOfNameOrdinals + index * sizeof(WORD),
                &ordinal, sizeof(ordinal)))
            {
                return 0;
            }

            DWORD functionRva = 0;
            if (!ReadRemote(hProcess, moduleBase + exports.AddressOfFunctions + ordinal * sizeof(DWORD),
                &functionRva, sizeof(functionRva)))
            {
                return 0;
            }
            return moduleBase + functionRva;
        }
        return 0;
    }

    // 在 stub 里生成 “mov [rip+disp32], rax”，把 rax 写回远程页的诊断槽。
    // 用 rip 相对寻址，不占用任何寄存器，也不依赖栈。
    void EmitStoreRax(std::vector<BYTE>& code, const uintptr_t stubAddress, const uintptr_t targetAddress)
    {
        code.insert(code.end(), { 0x48, 0x89, 0x05 });
        const uintptr_t nextRip = stubAddress + code.size() + sizeof(int32_t);
        const auto displacement = static_cast<int32_t>(static_cast<intptr_t>(targetAddress) -
            static_cast<intptr_t>(nextRip));
        code.insert(code.end(), reinterpret_cast<const BYTE*>(&displacement),
            reinterpret_cast<const BYTE*>(&displacement) + sizeof(displacement));
    }

    // x64 的 APC stub：sub rsp,28h -> LoadLibraryExW -> 回写返回值与 GetLastError
    // -> add rsp,28h -> ret。APC 分发器会正常接收返回，不需要保存/恢复上下文。
    std::vector<BYTE> BuildApcStub64(const uintptr_t stubAddress, const uintptr_t pathAddress,
        const uintptr_t loadLibraryAddress, const uintptr_t getLastErrorAddress, const uintptr_t resultAddress)
    {
        std::vector<BYTE> code;
        code.reserve(64);
        code.insert(code.end(), { 0x48, 0x83, 0xEC, 0x28 });   // sub rsp, 28h
        code.insert(code.end(), { 0x48, 0xB9 });               // mov rcx, 路径
        AppendQword(code, pathAddress);
        code.insert(code.end(), { 0x31, 0xD2 });               // xor edx, edx（hFile 为空）
        code.insert(code.end(), { 0x41, 0xB8, 0x08, 0x00, 0x00, 0x00 });  // mov r8d, LOAD_WITH_ALTERED_SEARCH_PATH
        code.insert(code.end(), { 0x48, 0xB8 });               // mov rax, LoadLibraryExW
        AppendQword(code, loadLibraryAddress);
        code.insert(code.end(), { 0xFF, 0xD0 });               // call rax
        EmitStoreRax(code, stubAddress, resultAddress);        // 回写 HMODULE
        code.insert(code.end(), { 0x48, 0xB8 });               // mov rax, GetLastError
        AppendQword(code, getLastErrorAddress);
        code.insert(code.end(), { 0xFF, 0xD0 });               // call rax
        EmitStoreRax(code, stubAddress, resultAddress + 8);    // 回写错误码
        code.insert(code.end(), { 0x48, 0x83, 0xC4, 0x28 });   // add rsp, 28h
        code.push_back(0xC3);                                  // ret
        return code;
    }

    // x86 的 APC stub。
    //
    // 关键点：APC 入口的 ESP 对齐是随机的，而 MSVC 编译的 kernelbase/kernel32
    // 会假设“调用点 ESP 是 16 字节对齐”，内部直接使用 movaps 之类的 SSE 指令。
    // 这里先把栈按 16 字节对齐，再压参数，保证 call 那一刻 ESP % 16 == 0；
    // 调用结束后恢复 ESP/EBP/EFLAGS 再 ret，让 APC 分发器继续走原流程。
    std::vector<BYTE> BuildApcStub32(const uintptr_t pathAddress, const uintptr_t loadLibraryAddress,
        const uintptr_t getLastErrorAddress, const uintptr_t resultAddress)
    {
        std::vector<BYTE> code;
        code.reserve(56);
        code.push_back(0x9C);                        // pushfd
        code.push_back(0x55);                        // push ebp
        code.insert(code.end(), { 0x8B, 0xEC });     // mov ebp, esp
        code.insert(code.end(), { 0x83, 0xE4, 0xF0 });  // and esp, 0FFFFFFF0h
        // LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH)：三次 push 共 12 字节，
        // 预留 0x14 后 call 点仍保持 16 字节对齐。
        code.insert(code.end(), { 0x83, 0xEC, 0x14 });  // sub esp, 14h
        code.push_back(0x68);                        // push LOAD_WITH_ALTERED_SEARCH_PATH
        AppendDword(code, 0x8);
        code.insert(code.end(), { 0x6A, 0x00 });     // push 0（hFile 为空）
        code.push_back(0x68);                        // push imm32（路径）
        AppendDword(code, pathAddress);
        code.push_back(0xB8);                        // mov eax, LoadLibraryExW
        AppendDword(code, loadLibraryAddress);
        code.insert(code.end(), { 0xFF, 0xD0 });     // call eax
        code.push_back(0xA3);                        // mov [imm32], eax
        AppendDword(code, resultAddress);
        code.push_back(0xB8);                        // mov eax, GetLastError
        AppendDword(code, getLastErrorAddress);
        code.insert(code.end(), { 0xFF, 0xD0 });     // call eax
        code.push_back(0xA3);                        // mov [imm32], eax
        AppendDword(code, resultAddress + 4);
        code.insert(code.end(), { 0x8B, 0xE5 });     // mov esp, ebp
        code.push_back(0x5D);                        // pop ebp
        code.push_back(0x9D);                        // popfd
        // 用户态 APC 例程是 stdcall 单参数（VOID CALLBACK (ULONG_PTR)），
        // 由被调方清理 4 字节参数，因此用 ret 4 而不是裸 ret。
        code.insert(code.end(), { 0xC2, 0x04, 0x00 });  // ret 4
        return code;
    }

    // 判断目标线程是否是 GUI 线程（TEB.Win32ThreadInfo 非空）。
    // GUI 线程通常不会进入可警示等待，QueueUserAPC 排进去也不会执行。
    // WOW64 目标读 TEB32（= TEB64 + 0x2000），Win32ThreadInfo 在 0x78；
    // 读不到时按“非 GUI”处理，宁可多排一次 APC。
    bool IsGuiThread(const HANDLE hProcess, const DWORD threadId, const bool isWow64)
    {
        using NtQueryInformationThreadFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        struct ThreadBasicInformation
        {
            LONG ExitStatus;
            PVOID TebBaseAddress;
            ULONG_PTR UniqueProcessId;
            ULONG_PTR UniqueThreadId;
            ULONG_PTR AffinityMask;
            LONG Priority;
            LONG BasePriority;
        };

        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
        {
            return false;
        }
        const auto queryInformation = reinterpret_cast<NtQueryInformationThreadFn>(
            GetProcAddress(ntdll, "NtQueryInformationThread"));
        if (queryInformation == nullptr)
        {
            return false;
        }

        const HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadId);
        if (thread == nullptr)
        {
            return false;
        }
        ThreadBasicInformation info{};
        const LONG status = queryInformation(thread, 0 /*ThreadBasicInformation*/, &info, sizeof(info), nullptr);
        CloseHandle(thread);
        if (status < 0 || info.TebBaseAddress == nullptr)
        {
            return false;
        }

        ULONG_PTR win32ThreadInfo = 0;
        SIZE_T read = 0;
        const uintptr_t tebOffset = isWow64 ? 0x2000 : 0;
        const size_t infoSize = isWow64 ? sizeof(uint32_t) : sizeof(ULONG_PTR);
        if (!ReadProcessMemory(hProcess,
            static_cast<const BYTE*>(info.TebBaseAddress) + tebOffset + kTebWin32ThreadInfoOffset,
            &win32ThreadInfo, infoSize, &read))
        {
            return false;
        }
        return win32ThreadInfo != 0;
    }

    // 走驱动通道排队 APC。驱动侧会自己挑一个非 GUI、带激活上下文的工作线程。
    bool QueueApcViaDriver(const HANDLE hProcess, const DWORD pid, const PVOID stub)
    {
        if (g_hGeneralDriverDevice == nullptr || g_hGeneralDriverDevice == INVALID_HANDLE_VALUE)
        {
            logger.Log("[DEBUG] 驱动设备不可用，跳过内核 APC 通道");
            return false;
        }

        RING3_REMOTE_THREAD info{};
        info.pid = static_cast<ULONG64>(pid);
        info.hProcess = static_cast<ULONG64>(reinterpret_cast<ULONG_PTR>(hProcess));
        info.pUserFunc = static_cast<ULONG64>(reinterpret_cast<ULONG_PTR>(stub));

        DWORD returned = 0;
        const BOOL result = SendUserDataToDriver(IOCTL_CREATE_REMOTE_THREAD, &info,
            sizeof(RING3_REMOTE_THREAD), nullptr, 0, &returned);
        if (!result)
        {
            logger.LogError("APC 注入：IOCTL_CREATE_REMOTE_THREAD", GetLastError());
            return false;
        }
        logger.Log("[INFO] APC 注入：已向驱动提交远程 stub pid=%lu stub=%p", pid, stub);
        return true;
    }

    // 用户态 APC：向所有非 GUI 线程排队（GUI 线程不会进入可警示等待）。
    // 多线程同时排队可大幅提高“至少有一个线程正处于可警示等待”的概率。
    bool QueueApcUserMode(const HANDLE hProcess, const DWORD pid, const PVOID stub, const bool isWow64)
    {
        // 64 位进程用 QueueUserAPC 排给 WOW64 线程时，APC 会在该线程的 64 位上下文里
        // 执行（WOW64 的 32 位分发器不参与），32 位 stub 会被按 x64 解码而崩溃。
        // 因此 32 位目标只能走驱动通道（KeInsertQueueApc 由内核按目标上下文投递）。
        if (isWow64)
        {
            logger.Log("[DEBUG] APC 注入：32 位目标跳过用户态 QueueUserAPC（会被按 64 位上下文执行）");
            return false;
        }

        const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            logger.LogError("APC 注入：CreateToolhelp32Snapshot(线程)", GetLastError());
            return false;
        }

        bool queued = false;
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        for (BOOL ok = Thread32First(snapshot, &entry); ok; ok = Thread32Next(snapshot, &entry))
        {
            if (entry.th32OwnerProcessID != pid)
            {
                continue;
            }
            if (IsGuiThread(hProcess, entry.th32ThreadID, isWow64))
            {
                logger.Log("[DEBUG] APC 注入：跳过 GUI 线程 tid=%lu", static_cast<unsigned long>(entry.th32ThreadID));
                continue;
            }

            const HANDLE thread = OpenThread(
                THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
            if (thread == nullptr)
            {
                continue;
            }
            if (QueueUserAPC(reinterpret_cast<PAPCFUNC>(stub), thread, 0) != 0)
            {
                logger.Log("[DEBUG] APC 注入：已在用户态排队 tid=%lu stub=%p",
                    static_cast<unsigned long>(entry.th32ThreadID), stub);
                queued = true;
            }
            else
            {
                logger.Log("[DEBUG] APC 注入：QueueUserAPC 失败 tid=%lu 错误=%lu",
                    static_cast<unsigned long>(entry.th32ThreadID),
                    static_cast<unsigned long>(GetLastError()));
            }
            CloseHandle(thread);
        }
        CloseHandle(snapshot);

        if (queued)
        {
            logger.Log("[INFO] APC 注入：已向目标进程的非 GUI 线程排队 pid=%lu", pid);
        }
        else
        {
            logger.Log("[DEBUG] APC 注入：没有找到可排队的线程 pid=%lu", pid);
        }
        return queued;
    }

    // 等待目标进程模块列表里出现指定 DLL（按文件名比对）。
    // WOW64 目标走 PEB32 模块链，64 位目标走 Toolhelp。
    bool WaitForRemoteModule(const HANDLE hProcess, const DWORD pid, const std::wstring& dllPath,
        const DWORD timeoutMs, const bool isWow64, uintptr_t& moduleBase)
    {
        moduleBase = 0;
        const size_t separator = dllPath.find_last_of(L"\\/");
        const std::wstring moduleName = separator == std::wstring::npos ? dllPath : dllPath.substr(separator + 1);
        if (moduleName.empty())
        {
            return false;
        }

        const ULONGLONG deadline = GetTickCount64() + timeoutMs;
        while (GetTickCount64() <= deadline)
        {
            if (isWow64)
            {
                const uintptr_t base = QueryWow64ModuleBase(hProcess, moduleName.c_str());
                if (base != 0)
                {
                    moduleBase = base;
                    return true;
                }
            }
            else
            {
                bool found = false;
                const uintptr_t base = QueryRemoteModuleBase(pid, moduleName.c_str(), &found);
                if (found)
                {
                    moduleBase = base;
                    return true;
                }
            }
            Sleep(100);
        }
        return false;
    }

    // 取本 DLL 所在目录（发布目录的 bin），辅助进程与它同目录。
    std::wstring QueryModuleDirectory()
    {
        HMODULE module = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&QueryModuleDirectory), &module))
        {
            return std::wstring();
        }
        return FileSystem::GetModuleDirectory(module);
    }

    // 32 位目标必须由同位数进程投递 APC，这里拉起 ApcInject32.exe 代劳。
    // 退出码语义见 ApcInject32/main.cpp。
    bool InjectViaWow64Helper(const DWORD pid, const std::wstring& dllPath, DWORD& exitCode)
    {
        exitCode = 0;
        std::wstring directory = QueryModuleDirectory();
        if (directory.empty())
        {
            SetLastError(ERROR_PATH_NOT_FOUND);
            logger.LogError("APC 注入：无法定位本模块目录，找不到 32 位辅助进程", ERROR_PATH_NOT_FOUND);
            return false;
        }
        if (!directory.empty() && directory.back() != L'\\' && directory.back() != L'/')
        {
            directory.push_back(L'\\');
        }
        const std::wstring helperPath = directory + L"ApcInject32.exe";
        if (GetFileAttributesW(helperPath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            const DWORD error = GetLastError();
            SetLastError(error);
            logger.LogError("APC 注入：缺少 32 位辅助进程 ApcInject32.exe", error);
            logger.LogW(L"[DEBUG] 期望路径=%ls", helperPath.c_str());
            return false;
        }

        std::wstring commandLine = L"\"" + helperPath + L"\" " + std::to_wstring(pid) + L" \"" + dllPath + L"\"";
        std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
        mutableCommandLine.push_back(L'\0');

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        logger.LogW(L"[INFO] APC 注入：拉起 32 位辅助进程 pid=%lu helper=%ls", pid, helperPath.c_str());
        if (!CreateProcessW(helperPath.c_str(), mutableCommandLine.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, directory.c_str(), &startup, &process))
        {
            const DWORD error = GetLastError();
            SetLastError(error);
            logger.LogError("APC 注入：启动 32 位辅助进程 CreateProcessW", error);
            return false;
        }

        const DWORD wait = WaitForSingleObject(process.hProcess, 30000);
        if (wait != WAIT_OBJECT_0)
        {
            const DWORD error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
            TerminateProcess(process.hProcess, 1);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            SetLastError(error);
            logger.LogError("APC 注入：等待 32 位辅助进程超时", error);
            return false;
        }

        DWORD code = 0;
        GetExitCodeProcess(process.hProcess, &code);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        exitCode = code;
        if (code != 0)
        {
            const DWORD error = code == 3 ? ERROR_NOT_SUPPORTED
                : (code == 4 ? ERROR_BAD_EXE_FORMAT : ERROR_GEN_FAILURE);
            SetLastError(error);
            logger.Log("[DEBUG] APC 注入：32 位辅助进程退出码=%lu", static_cast<unsigned long>(code));
            return false;
        }
        return true;
    }

    // 延迟回收远程页：stub 还在目标线程栈上执行时不能释放。
    void ReclaimExpiredPages()
    {
        std::vector<PendingFree> pending;
        {
            std::lock_guard<std::mutex> guard(g_pendingFreeMutex);
            const ULONGLONG now = GetTickCount64();
            for (auto it = g_pendingFree.begin(); it != g_pendingFree.end();)
            {
                if (now - it->tick >= kReclaimDelayMs)
                {
                    pending.push_back(*it);
                    it = g_pendingFree.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        for (const PendingFree& item : pending)
        {
            const HANDLE process = OpenProcess(PROCESS_VM_OPERATION, FALSE, item.pid);
            if (process == nullptr)
            {
                logger.Log("[DEBUG] APC 注入：远程页回收失败（进程已退出？）pid=%lu 地址=0x%llX",
                    item.pid, item.remoteAddress);
                continue;
            }
            VirtualFreeEx(process, reinterpret_cast<LPVOID>(static_cast<uintptr_t>(item.remoteAddress)), 0, MEM_RELEASE);
            CloseHandle(process);
            logger.Log("[DEBUG] APC 注入：远程页已回收 pid=%lu 地址=0x%llX", item.pid, item.remoteAddress);
        }
    }

    void RememberPageForReclaim(const DWORD pid, const PVOID remotePage)
    {
        std::lock_guard<std::mutex> guard(g_pendingFreeMutex);
        g_pendingFree.push_back(PendingFree{ pid, GetTickCount64(),
            static_cast<ULONGLONG>(reinterpret_cast<uintptr_t>(remotePage)) });
    }
}

BOOL InjectDllByApc(DWORD dwProcessId, const wchar_t* dllPath)
{
    if (dwProcessId == 0 || dllPath == nullptr || dllPath[0] == 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        logger.LogError("APC 注入请求被拒绝：PID 或 DLL 路径无效", ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    const std::wstring requestedPath(dllPath);
    ReclaimExpiredPages();

    // 1. 规范化路径并确认文件存在
    wchar_t fullPath[32768]{};
    const DWORD fullLength = GetFullPathNameW(requestedPath.c_str(), ARRAYSIZE(fullPath), fullPath, nullptr);
    if (fullLength == 0 || fullLength >= ARRAYSIZE(fullPath))
    {
        const DWORD error = fullLength == 0 ? GetLastError() : ERROR_FILENAME_EXCED_RANGE;
        SetLastError(error);
        logger.LogError("APC 注入：解析 DLL 路径失败", error);
        return FALSE;
    }
    const std::wstring targetDllPath(fullPath);
    if (GetFileAttributesW(targetDllPath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        const DWORD error = GetLastError();
        SetLastError(error);
        logger.LogError("APC 注入：DLL 文件不存在", error);
        logger.LogW(L"[DEBUG] 目标路径=%ls", targetDllPath.c_str());
        return FALSE;
    }

    logger.LogW(L"[INFO] APC 注入开始：pid=%lu dll=%ls", dwProcessId, targetDllPath.c_str());

    // 2. 打开目标进程（驱动通道要求句柄带 PROCESS_ALL_ACCESS）
    EnableDebugPrivilege();
    const HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (hProcess == nullptr)
    {
        const DWORD error = GetLastError();
        SetLastError(error);
        logger.LogError("APC 注入：打开目标进程 OpenProcess(PROCESS_ALL_ACCESS)", error);
        return FALSE;
    }

    bool isWow64 = false;
    WORD dllMachine = 0;
    PVOID remotePage = nullptr;
    bool success = false;
    do
    {
        // 3. 架构校验：DLL 位数必须与目标进程一致
        //    x64 目标 -> 64 位 stub + 64 位 LoadLibraryW；
        //    WOW64 目标 -> 32 位 stub + 32 位 LoadLibraryW。
        if (!QueryTargetIsWow64(hProcess, isWow64))
        {
            break;
        }
        const WORD expectedMachine = isWow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
        if (!ReadPeMachine(targetDllPath, dllMachine))
        {
            break;
        }
        if (dllMachine != expectedMachine)
        {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            logger.Log("[DEBUG] APC 注入：DLL 机器类型=0x%04X 目标=0x%04X",
                static_cast<unsigned int>(dllMachine), static_cast<unsigned int>(expectedMachine));
            logger.LogError(isWow64
                ? "APC 注入：目标是 32 位进程，必须注入 32 位（x86）DLL"
                : "APC 注入：目标是 64 位进程，必须注入 64 位（x64）DLL", ERROR_BAD_EXE_FORMAT);
            break;
        }
        logger.Log("[DEBUG] APC 注入：目标位数=%s", isWow64 ? "32 位（WOW64）" : "64 位");

        // 4. 解析目标进程内的 LoadLibraryExW / GetLastError
        //    用 LoadLibraryExW + LOAD_WITH_ALTERED_SEARCH_PATH，让被注入 DLL 的依赖
        //    从它自己所在目录解析（LoadLibraryW 只按目标 exe 目录解析，会返回 126）。
        //    64 位目标：kernel32 在各进程里基址一致，用本进程地址差推导；
        //    32 位目标：读目标 PEB32 里的 kernel32 基址，再解析它的导出表。
        uintptr_t remoteLoadLibrary = 0;
        uintptr_t remoteGetLastError = 0;
        if (isWow64)
        {
            const uintptr_t remoteKernel32Wow64 = QueryWow64ModuleBase(hProcess, L"kernel32.dll");
            if (remoteKernel32Wow64 == 0)
            {
                SetLastError(ERROR_MOD_NOT_FOUND);
                logger.LogError("APC 注入：在 32 位 PEB 模块链里找不到 kernel32.dll", ERROR_MOD_NOT_FOUND);
                break;
            }
            // kernel32 里的 LoadLibraryW 只是一条 jmp [IAT] 转发存根，真正的实现在
            // kernelbase。WOW64 下这个存根有时会因为 IAT 尚未完成重定位而在 APC 里
            // 崩溃，因此优先直接解析 kernelbase 的真实实现，解析不到再退回 kernel32。
            const uintptr_t remoteKernelBaseWow64 = QueryWow64ModuleBase(hProcess, L"kernelbase.dll");
            if (remoteKernelBaseWow64 != 0)
            {
                remoteLoadLibrary = ResolveRemoteExport32(hProcess, remoteKernelBaseWow64, "LoadLibraryExW");
                remoteGetLastError = ResolveRemoteExport32(hProcess, remoteKernelBaseWow64, "GetLastError");
                logger.Log("[DEBUG] APC 注入：32 位 kernelbase=0x%llX LoadLibraryW=0x%llX GetLastError=0x%llX",
                    static_cast<unsigned long long>(remoteKernelBaseWow64),
                    static_cast<unsigned long long>(remoteLoadLibrary),
                    static_cast<unsigned long long>(remoteGetLastError));
            }
            if (remoteLoadLibrary == 0 || remoteGetLastError == 0)
            {
                remoteLoadLibrary = ResolveRemoteExport32(hProcess, remoteKernel32Wow64, "LoadLibraryExW");
                remoteGetLastError = ResolveRemoteExport32(hProcess, remoteKernel32Wow64, "GetLastError");
                logger.Log("[DEBUG] APC 注入：回退 32 位 kernel32=0x%llX LoadLibraryW=0x%llX GetLastError=0x%llX",
                    static_cast<unsigned long long>(remoteKernel32Wow64),
                    static_cast<unsigned long long>(remoteLoadLibrary),
                    static_cast<unsigned long long>(remoteGetLastError));
            }
            if (remoteLoadLibrary != 0)
            {
                BYTE head[16]{};
                if (ReadRemote(hProcess, remoteLoadLibrary, head, sizeof(head)))
                {
                    logger.Log("[DEBUG] APC 注入：LoadLibraryW 机器码=%02X %02X %02X %02X %02X %02X %02X %02X",
                        head[0], head[1], head[2], head[3], head[4], head[5], head[6], head[7]);
                }
            }
            if (remoteLoadLibrary == 0 || remoteGetLastError == 0)
            {
                SetLastError(ERROR_PROC_NOT_FOUND);
                logger.LogError("APC 注入：解析 32 位 kernel32 导出失败", ERROR_PROC_NOT_FOUND);
                break;
            }
        }
        else
        {
            const HMODULE localKernel32 = GetModuleHandleW(L"kernel32.dll");
            const uintptr_t localLoadLibrary = localKernel32 == nullptr
                ? 0
                : reinterpret_cast<uintptr_t>(GetProcAddress(localKernel32, "LoadLibraryExW"));
            const uintptr_t localGetLastError = localKernel32 == nullptr
                ? 0
                : reinterpret_cast<uintptr_t>(GetProcAddress(localKernel32, "GetLastError"));
            if (localKernel32 == nullptr || localLoadLibrary == 0 || localGetLastError == 0)
            {
                const DWORD error = GetLastError();
                SetLastError(error);
                logger.LogError("APC 注入：解析本进程 LoadLibraryExW/GetLastError", error);
                break;
            }

            const uintptr_t remoteKernel32 = QueryRemoteModuleBase(dwProcessId, L"kernel32.dll");
            remoteLoadLibrary = remoteKernel32 == 0
                ? 0
                : remoteKernel32 + (localLoadLibrary - reinterpret_cast<uintptr_t>(localKernel32));
            remoteGetLastError = remoteKernel32 == 0
                ? 0
                : remoteKernel32 + (localGetLastError - reinterpret_cast<uintptr_t>(localKernel32));
            if (remoteLoadLibrary != 0)
            {
                BYTE probe[4]{};
                SIZE_T read = 0;
                if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(remoteLoadLibrary),
                    probe, sizeof(probe), &read))
                {
                    logger.Log("[DEBUG] APC 注入：目标 LoadLibraryW 探测失败，改用本进程地址 0x%llX",
                        static_cast<unsigned long long>(localLoadLibrary));
                    remoteLoadLibrary = 0;
                    remoteGetLastError = 0;
                }
            }
            if (remoteLoadLibrary == 0)
            {
                remoteLoadLibrary = localLoadLibrary;
                remoteGetLastError = localGetLastError;
            }
            logger.Log("[DEBUG] APC 注入：LoadLibraryW 目标地址=0x%llX（本进程=0x%llX kernel32=0x%llX）",
                static_cast<unsigned long long>(remoteLoadLibrary),
                static_cast<unsigned long long>(localLoadLibrary),
                static_cast<unsigned long long>(remoteKernel32));
        }

        // 4.5 32 位目标：64 位进程排的 APC 会按 x64 上下文执行，改由同位数的
        //     ApcInject32.exe 投递（不需要 VT 驱动）。
        if (isWow64)
        {
            DWORD helperExitCode = 0;
            if (!InjectViaWow64Helper(dwProcessId, targetDllPath, helperExitCode))
            {
                break;
            }
            uintptr_t helperModuleBase = 0;
            if (!WaitForRemoteModule(hProcess, dwProcessId, targetDllPath, kStageWaitMs, isWow64, helperModuleBase))
            {
                SetLastError(ERROR_MOD_NOT_FOUND);
                logger.LogError("APC 注入：辅助进程报告成功，但目标模块列表里仍未出现该 DLL",
                    ERROR_MOD_NOT_FOUND);
                break;
            }
            logger.LogW(L"[INFO] APC 注入成功（32 位辅助进程）：pid=%lu dll=%ls 模块基址=0x%llX",
                dwProcessId, targetDllPath.c_str(),
                static_cast<unsigned long long>(helperModuleBase));
            success = true;
            break;
        }

        // 5. 在目标进程里申请一页：路径 + APC stub
        const size_t pathBytes = (targetDllPath.size() + 1) * sizeof(wchar_t);
        if (pathBytes > kPathLimitBytes)
        {
            SetLastError(ERROR_FILENAME_EXCED_RANGE);
            logger.LogError("APC 注入：DLL 路径过长，无法放入远程页", ERROR_FILENAME_EXCED_RANGE);
            break;
        }

        remotePage = VirtualAllocEx(hProcess, nullptr, kRemotePageSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (remotePage == nullptr)
        {
            const DWORD error = GetLastError();
            SetLastError(error);
            logger.LogError("APC 注入：在目标进程申请内存 VirtualAllocEx", error);
            break;
        }
        logger.Log("[DEBUG] APC 注入：远程页=0x%llX pid=%lu",
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(remotePage)), dwProcessId);

        const auto remotePathAddress = reinterpret_cast<PVOID>(
            reinterpret_cast<uintptr_t>(remotePage) + kPathOffset);
        const auto remoteApcStub = reinterpret_cast<PVOID>(
            reinterpret_cast<uintptr_t>(remotePage) + kApcStubOffset);
        const auto remoteResult = reinterpret_cast<PVOID>(
            reinterpret_cast<uintptr_t>(remotePage) + kResultOffset);

        // 结果槽预填 0xFFFF...：保持该值说明 stub 根本没执行，写成 0 才是
        // “stub 执行了但 LoadLibraryW 返回空”，两者含义完全不同。
        // 32 位目标的结果槽是 4 字节宽，按目标位数决定写入长度。
        const ULONG_PTR resultSentinel = static_cast<ULONG_PTR>(~static_cast<ULONG_PTR>(0));
        const size_t resultSlotSize = isWow64 ? sizeof(uint32_t) : sizeof(ULONG_PTR);
        SIZE_T written = 0;
        WriteProcessMemory(hProcess, remoteResult, &resultSentinel, resultSlotSize, &written);
        WriteProcessMemory(hProcess, static_cast<BYTE*>(remoteResult) + resultSlotSize,
            &resultSentinel, resultSlotSize, &written);

        written = 0;
        if (!WriteProcessMemory(hProcess, remotePathAddress, targetDllPath.c_str(), pathBytes, &written) ||
            written != pathBytes)
        {
            const DWORD error = GetLastError();
            SetLastError(error);
            logger.LogError("APC 注入：写入 DLL 路径 WriteProcessMemory", error);
            break;
        }

        const std::vector<BYTE> apcStub = isWow64
            ? BuildApcStub32(reinterpret_cast<uintptr_t>(remotePathAddress), remoteLoadLibrary,
                remoteGetLastError, reinterpret_cast<uintptr_t>(remoteResult))
            : BuildApcStub64(reinterpret_cast<uintptr_t>(remoteApcStub),
                reinterpret_cast<uintptr_t>(remotePathAddress), remoteLoadLibrary, remoteGetLastError,
                reinterpret_cast<uintptr_t>(remoteResult));
        written = 0;
        if (!WriteProcessMemory(hProcess, remoteApcStub, apcStub.data(), apcStub.size(), &written) ||
            written != apcStub.size())
        {
            const DWORD error = GetLastError();
            SetLastError(error);
            logger.LogError("APC 注入：写入 APC stub WriteProcessMemory", error);
            break;
        }

        logger.Log("[DEBUG] APC 注入：stub 已写入 0x%llX 长度=%zu",
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(remoteApcStub)), apcStub.size());

        // 6. 两条通道依次尝试：内核 APC -> 用户态 APC
        uintptr_t moduleBase = 0;
        bool injected = false;
        if (QueueApcViaDriver(hProcess, dwProcessId, remoteApcStub))
        {
            injected = WaitForRemoteModule(hProcess, dwProcessId, targetDllPath, kStageWaitMs, isWow64, moduleBase);
            if (!injected)
            {
                logger.Log("[INFO] APC 注入：内核 APC 通道未在 %lu 毫秒内完成加载",
                    static_cast<unsigned long>(kStageWaitMs));
            }
        }
        if (!injected && QueueApcUserMode(hProcess, dwProcessId, remoteApcStub, isWow64))
        {
            injected = WaitForRemoteModule(hProcess, dwProcessId, targetDllPath, kStageWaitMs, isWow64, moduleBase);
            if (!injected)
            {
                logger.Log("[INFO] APC 注入：用户态 APC 通道未在 %lu 毫秒内完成加载",
                    static_cast<unsigned long>(kStageWaitMs));
            }
        }

        if (!injected)
        {
            // 回读 stub 写回的 LoadLibraryW 返回值：0 表示 stub 已执行但加载失败，
            // 保持 0xFFFFFFFFFFFFFFFF（未写入）说明 stub 根本没跑。
            ULONG_PTR remoteResultValue[2]{ 0, 0 };
            SIZE_T read = 0;
            if (ReadProcessMemory(hProcess, remoteResult, remoteResultValue, resultSlotSize * 2, &read) &&
                read == resultSlotSize * 2)
            {
                logger.Log("[DEBUG] APC 注入：stub 返回值=0x%llX GetLastError=0x%llX（返回值全 F 表示 stub 未执行）",
                    static_cast<unsigned long long>(remoteResultValue[0]),
                    static_cast<unsigned long long>(remoteResultValue[1]));
            }
            else
            {
                logger.Log("[DEBUG] APC 注入：读取 stub 返回值失败，错误=%lu",
                    static_cast<unsigned long>(GetLastError()));
            }

            SetLastError(ERROR_MOD_NOT_FOUND);
            logger.LogError("APC 注入：等待模块加载超时，目标进程未出现该 DLL（APC 需要目标存在处于可警示等待的非 GUI 线程）",
                ERROR_MOD_NOT_FOUND);
            break;
        }

        logger.LogW(L"[INFO] APC 注入成功：pid=%lu dll=%ls 模块基址=0x%llX",
            dwProcessId, targetDllPath.c_str(),
            static_cast<unsigned long long>(moduleBase));
        RememberPageForReclaim(dwProcessId, remotePage);
        remotePage = nullptr;   // 交给延迟回收
        success = true;
    } while (false);

    if (remotePage != nullptr)
    {
        VirtualFreeEx(hProcess, remotePage, 0, MEM_RELEASE);
    }
    CloseHandle(hProcess);

    if (!success)
    {
        const DWORD error = GetLastError() == ERROR_SUCCESS ? ERROR_GEN_FAILURE : GetLastError();
        logger.LogError("APC 注入失败", error);
        SetLastError(error);
        return FALSE;
    }
    return TRUE;
}
