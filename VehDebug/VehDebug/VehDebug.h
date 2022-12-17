#pragma once
#include <Windows.h>


#define PADDING(type, name, size) union { type name; char name##_padding[size]; }

struct VEHDebugSharedMem
{
	PADDING(CONTEXT, CurrentContext, sizeof(CONTEXT) * 2);
	HANDLE HasDebugEvent; //被调试进程，有异常事件
	HANDLE HasHandledDebugEvent;
	ULONG dwProcessId;
	ULONG dwThreadId;
	ULONG dwContinueStatus;
	DEBUG_EVENT DebugEvent;
	char ConfigName[2][256];
};

void InitializeVEH();


struct CriticalSectionLock
{
	CRITICAL_SECTION cs;

	void Init()
	{
		InitializeCriticalSection(&cs);
	}

	void Enter()
	{
		EnterCriticalSection(&cs);
	}

	void Leave()
	{
		LeaveCriticalSection(&cs);
	}
};


LONG  Handler(LPEXCEPTION_POINTERS ep);

LONG InternalHandler(LPEXCEPTION_POINTERS ep, DWORD tid);