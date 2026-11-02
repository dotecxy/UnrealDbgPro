2026-11-02：开始读取项目构建说明。
VS Installer 系统组件安装被自动审批拒绝（blocked by policy），未执行。改查项目本地工具包构建。
DLL、Loader、三个驱动已编译链接；使用 SignMode=Off 构建未签名驱动，WinUI 编译进行中。
2026-11-02：构建成功；self-test=0；补齐 AIHelper 后 UI smoke=0，后端日志确认 InjectDll 导出已解析。未加载驱动。完整记录见 _artifacts/BUILD-RESULT.md。
2026-11-02：三个发布 SYS 已免费自签名，SignTool 均成功；证书未加入受信任根，Authenticode 因根未信任显示 UnknownError。未更改测试模式、未加载驱动。
2026-11-02：用户要求继续后，导入本机 Root/TrustedPublisher 测试证书；三个 SYS 验签均 Valid；BCD testsigning Yes，等待用户手动重启，未加载驱动。
补签三个项目 x64/Release 下的 SYS；连同发布 bin 下的三个 SYS，共六个文件 SignTool verify /pa 均成功，Authenticode 均为 Valid；未加载驱动。
2026-11-02：新增 APC 注入 DLL 功能。后端 UnrealDbgProDll/Inject/ApcDllInject.cpp 实现 InjectDllByApc（内核 KeInsertQueueApc 通道 + 用户态 QueueUserAPC 通道，远程 stub 调用 LoadLibraryW 并回写返回值/错误码）；前端调试器页新增「DLL 注入」卡片与窗口拾取 PID。实测：带工作线程的测试进程注入成功（模块加载 + DllMain 落文件）；纯 GUI 进程按预期超时失败且目标进程不受影响；--ui-smoke-test 退出码 0（含新增第 13 项检查）。
2026-11-02：重新编译（含 APC 注入功能）并对三个驱动做测试签名，六个副本验签均 Valid；self-test=0、ui-smoke-test=0、注入实测成功；未加载驱动。
2026-11-02：WOW64 支持调研完成。32 位路径（PEB32/导出解析/x86 stub/位数校验）已实现；实测发现 64 位进程 QueueUserAPC 到 WOW64 线程会按 64 位上下文执行导致目标崩溃，故 32 位目标改为仅走内核 APC 通道，驱动未就绪时干净失败（ERROR_NOT_SUPPORTED，目标不受影响）。x64 注入回归通过；self-test=0、ui-smoke-test=0；驱动已重新测试签名。
2026-11-02：32 位目标注入打通（ApcInject32 辅助进程 + x86 stub `ret 4` 修正）；64 位目标路径回归通过（WoW 客户端为 64 位，走该路径）；self-test/ui-smoke-test 均 0。
2026-11-02：实机注入 WoW（64 位）成功。修正 LoadLibraryW→LoadLibraryExW(LOAD_WITH_ALTERED_SEARCH_PATH)，解决被注入 DLL 依赖解析失败（126）。
