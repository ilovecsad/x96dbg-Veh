// VehDebug.cpp : 定义 DLL 的导出函数。
//

#include "VehDebug.h"
HANDLE fm; 
char ConfigName[256];

CriticalSectionLock handler_cs;
VEHDebugSharedMem* vehmem;
BOOL veh_debug_active = FALSE;
PVOID exception_handler_handle = NULL;
void InitializeVEH()
{
	handler_cs.Init();
	if (!fm && !(fm = OpenFileMappingA(FILE_MAP_ALL_ACCESS, false, ConfigName)))
		return;

	vehmem = (VEHDebugSharedMem*)MapViewOfFile(fm, FILE_READ_ACCESS | FILE_WRITE_ACCESS, 0, 0, 0);
	if (!vehmem) {
		CloseHandle(fm);
		return;
	}
	if (!vehmem->HasDebugEvent) {
		vehmem->HasDebugEvent = OpenEventA(EVENT_MODIFY_STATE, FALSE, vehmem->ConfigName[0]);
	}
	if (!vehmem->HasHandledDebugEvent) {
		vehmem->HasHandledDebugEvent = OpenEventA(EVENT_MODIFY_STATE, FALSE, vehmem->ConfigName[1]);
	}
	if (vehmem && vehmem->HasDebugEvent && vehmem->HasHandledDebugEvent)
	{
		handler_cs.Enter();

		exception_handler_handle = AddVectoredExceptionHandler(TRUE, (PVECTORED_EXCEPTION_HANDLER)Handler);
		if (exception_handler_handle)
		{
			veh_debug_active = TRUE;
		}
		handler_cs.Leave();

	}
	CloseHandle(fm);
	fm = 0;

}

LONG Handler(LPEXCEPTION_POINTERS ep)
{
	LONG nRet = EXCEPTION_CONTINUE_SEARCH;

	nRet = InternalHandler(ep,GetCurrentThreadId());

	return nRet;
}

LONG InternalHandler(LPEXCEPTION_POINTERS ep, DWORD tid)
{
	LONG result = EXCEPTION_CONTINUE_SEARCH;
	if (!veh_debug_active)
		return result;

	DWORD nPid = GetCurrentProcessId();

	//确保只有一个 线程进入
	handler_cs.Enter();

	vehmem->DebugEvent.dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
	vehmem->DebugEvent.dwProcessId = nPid;
	vehmem->DebugEvent.dwThreadId = tid;
	vehmem->dwProcessId = nPid;
	vehmem->dwThreadId = tid;
	vehmem->DebugEvent.u.Exception.ExceptionRecord.ExceptionCode = ep->ExceptionRecord->ExceptionCode;
	vehmem->DebugEvent.u.Exception.ExceptionRecord.ExceptionFlags = ep->ExceptionRecord->ExceptionFlags;
	vehmem->DebugEvent.u.Exception.ExceptionRecord.ExceptionRecord = ep->ExceptionRecord->ExceptionRecord;
	vehmem->DebugEvent.u.Exception.ExceptionRecord.NumberParameters = ep->ExceptionRecord->NumberParameters;
	vehmem->DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress = ep->ExceptionRecord->ExceptionAddress;
	vehmem->DebugEvent.u.Exception.dwFirstChance = 1;
	for (size_t i = 0; i < ep->ExceptionRecord->NumberParameters; i++) {
		vehmem->DebugEvent.u.Exception.ExceptionRecord.ExceptionInformation[i] = ep->ExceptionRecord->ExceptionInformation[i];
	}

	if (ep->ContextRecord)
	{
		
		RtlCopyMemory(&vehmem->CurrentContext, ep->ContextRecord, sizeof(CONTEXT));

		if (ep->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
		{
			//为什么需要在 STATUS_BREAKPOINT 异常下 RIP++ ,看一下 x96dbg引擎就知道了
#ifdef _WIN64
			vehmem->CurrentContext.Rip++;
#else
			vehmem->CurrentContext.Eip++;
#endif
		}
	}
	else
	{
		RtlSecureZeroMemory(&vehmem->CurrentContext, sizeof(CONTEXT));
	}

	if (SetEvent(vehmem->HasDebugEvent))
	{
		DWORD wr;
		
		do
		{
			wr = WaitForSingleObject(vehmem->HasHandledDebugEvent, 5000);
		} while (wr == WAIT_TIMEOUT);
		

		if (wr == WAIT_OBJECT_0) 
		{
			if (ep->ContextRecord)
			{
				RtlCopyMemory(ep->ContextRecord, &vehmem->CurrentContext, sizeof(CONTEXT));

			}


		}
		else 
		{
			result = EXCEPTION_CONTINUE_EXECUTION;
		}
		if (vehmem->dwContinueStatus == DBG_CONTINUE)
		{
			result = EXCEPTION_CONTINUE_EXECUTION;
		}
	}


	handler_cs.Leave();

	return result;
}
