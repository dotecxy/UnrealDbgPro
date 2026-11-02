#pragma once

#ifndef _APC_DLL_INJECT_H
#define _APC_DLL_INJECT_H

#include <Windows.h>

// 使用 APC 方式把 DLL 注入到指定进程。
//
// 实现分两级：
//   1. 优先把远程 stub 交给驱动（IOCTL_CREATE_REMOTE_THREAD），由内核在目标
//      进程里挂 KeInsertQueueApc，注入点不受用户态 API Hook 影响；
//   2. 驱动不可用或目标没有合适线程时，退回到用户态 QueueUserApc。
//
// 返回 TRUE 表示目标进程的模块列表里已经出现该 DLL。
BOOL InjectDllByApc(DWORD dwProcessId, const wchar_t* dllPath);

#endif // !_APC_DLL_INJECT_H
