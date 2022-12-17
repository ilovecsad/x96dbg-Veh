#pragma once
#include <Windows.h>
#include <objbase.h>
#include <string>



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

#pragma pack(push, 1)
struct RemoteInjectShellCode
{
#ifdef _WIN64
    DWORD   sub_rsp_0x28;
    WORD    mov_rcx;
    DWORD64 Arg_1;
    WORD    call_FF15;
    DWORD   call_offset;
    WORD    jmp_8;
    DWORD64 pLoadLibraryA;
    DWORD   add_rsp_0x28;
    char    testRax[3];
    WORD    jmp_6;
    BYTE    Register_eax1;
    DWORD   nResust1;
    BYTE    Ret1;
    WORD    mov_rcx1;
    DWORD64 pDllBase;
    char    movRcxRax[3];
    BYTE    Register_eax2;
    DWORD   nResust2;
    BYTE    Ret2;
    DWORD64 n[4];
#else
    BYTE    push;
    DWORD   arg;
    BYTE    call;
    DWORD   call_offset;
    WORD    test_eax;
    WORD    jne_6;
    BYTE    Register_eax1;
    DWORD   nResust1;
    BYTE    Ret1;

    BYTE    mov_rcx;
    DWORD   pDllBase;
    WORD   movEcxEax;

    BYTE    Register_eax2;
    DWORD   nResust2;
    BYTE    Ret2;
    DWORD   n[4];
#endif


};
#pragma pack(pop)

struct CriticalSectionLockEx
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
    void UnLoad()
    {
        DeleteCriticalSection(&cs);
    }
};

BOOL ListProcessModules(HANDLE hProcess);
BOOL ListProcessThreads(HANDLE hProcess);
DWORD HandleToPid(HANDLE hProcess);

PVOID GetThreadStartAddress(HANDLE hThread);
typedef BOOL(APIENTRY* t_WaitForDebugEvent)(
    _Out_ LPDEBUG_EVENT lpDebugEvent,
    _In_ DWORD dwMilliseconds
    );

typedef BOOL(APIENTRY* t_ContinueDebugEvent)(
    _In_ DWORD dwProcessId,
    _In_ DWORD dwThreadId,
    _In_ DWORD dwContinueStatus
    );

typedef NTSTATUS  (*t_NtDebugActiveProcess)(
    HANDLE ProcessHandle,
    HANDLE DebugObjectHandle);

typedef BOOL(WINAPI* t_GetThreadContext)(
    _In_ HANDLE hThread,
    _Inout_ LPCONTEXT lpContext
    );
typedef BOOL(WINAPI* t_SetThreadContext)(
    _In_ HANDLE hThread,
    _Inout_ LPCONTEXT lpContext
    );


BOOL VehSetThreadContext(_In_ HANDLE hThread,
    _In_ CONST CONTEXT* lpContext);

BOOL VehGetThreadContext(_In_ HANDLE hThread,
    _In_ CONST CONTEXT* lpContext);

PVOID GetModuleBase(WCHAR* szModule);

BOOL InitFileMapping();


BOOL IsTargetException();

std::string GuidToString(const GUID& guid);

BOOL WINAPI HookedGetThreadContext(
    _In_ HANDLE hThread,
    _Inout_ LPCONTEXT lpContext
);

BOOL WINAPI HookedSetThreadContext(
    _In_ HANDLE hThread,
    _Inout_ LPCONTEXT lpContext
);

BOOL  HookedWaitForDebugEvent(
    _Out_ LPDEBUG_EVENT lpDebugEvent,
    _In_ DWORD dwMilliseconds
);
BOOL HookedContinueDebugEvent(
    _In_ DWORD dwProcessId,
    _In_ DWORD dwThreadId,
    _In_ DWORD dwContinueStatus
);
NTSTATUS HookedNtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle);


BOOL InjectDll(HANDLE ProcessHandle,const char* szDllPath, PVOID* pDllBase);


PVOID CreateInjectCode(HANDLE ProcessHandle,const char* szDllPath, PVOID* pDllBase);


DWORD InitWork(PVOID p);