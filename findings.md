2026-11-02：仓库初始工作区干净；本机安装 VS2022 与 VS2026。
首次构建：MSB8020，缺少 v142 和 WindowsKernelModeDriver10.0；SDK 当前仅 26100。WinUI NuGet 已恢复。
本地工具链：VS2022 v143 + SDK26100 + WDK NuGet 10.0.26100.6584；临时 props/targets 适配路径，不修改原项目文件。
已编译 D-encryption.dll；VMProtect 使用仓库开发占位实现；AIHelper.dll 从本机现有 UnrealDbg/UnrealDbg/Win64/Release 复制，核对 x64 和 InjectDll 导出。
