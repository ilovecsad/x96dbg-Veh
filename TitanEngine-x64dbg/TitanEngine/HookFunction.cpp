#include "HookFunction.h"
#include  "minhook/MinHook.h"
#include <list>
#include <TlHelp32.h>
#include <winternl.h>


PVOID orgWaitForDebugEvent = NULL;
PVOID orgContinueDebugEvent = NULL;
PVOID orgNtDebugActiveProcess = NULL;
PVOID orgGetThreadContext = NULL;
PVOID orgSetThreadContext = NULL;

VEHDebugSharedMem* pShareMem = NULL;
HANDLE HasDebugEvent = NULL;
HANDLE HasHandledDebugEvent = NULL;
CriticalSectionLockEx handler_cs;

std::list<DEBUG_EVENT> m_event;
std::list<MODULEENTRY32W> m_moduleInfo;
HANDLE hDebuggedProcess = 0;
ULONG hNoExceptionEvent = 0;

BOOL bEnableVeh = FALSE;
char ConfigName[3][256];





BOOL ListProcessModules(HANDLE hProcess)
{
    m_moduleInfo.clear();
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32W me32;

    // Take a snapshot of all modules in the specified process.
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, HandleToPid(hProcess));
    if (hModuleSnap == INVALID_HANDLE_VALUE)
    {
        return(FALSE);
    }

    // Set the size of the structure before using it.
    me32.dwSize = sizeof(MODULEENTRY32);

    // Retrieve information about the first module,
    // and exit if unsuccessful
    if (!Module32First(hModuleSnap, &me32))
    {
        CloseHandle(hModuleSnap);           // clean the snapshot object
        return(FALSE);
    }

    // Now walk the module list of the process,
    // and display information about each module


    do
    {

        m_moduleInfo.push_back(me32);

    } while (Module32Next(hModuleSnap, &me32));

    CloseHandle(hModuleSnap);
    return(TRUE);
}

BOOL ListProcessThreads(HANDLE hProcess)
{
    m_event.clear();
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;
    DWORD hMainThreadId = 0;
    // Take a snapshot of all running threads  
    DWORD dwOwnerPID = 0;
    dwOwnerPID = HandleToPid(hProcess);
    if (!dwOwnerPID)return FALSE;

    HANDLE hFile = 0;
    for (auto it = m_moduleInfo.begin(); it != m_moduleInfo.end(); ++it)
    {
        if (wcsstr(it->szModule, L".exe"))
        {
            hFile = CreateFileW(it->szExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
            break;
        }
    }
    if (!hFile) return FALSE;

    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return(FALSE);

    // Fill in the size of the structure before using it. 
    te32.dwSize = sizeof(THREADENTRY32);

    // Retrieve information about the first thread,
    // and exit if unsuccessful
    if (!Thread32First(hThreadSnap, &te32))
    {

        CloseHandle(hThreadSnap);          // clean the snapshot object
        return(FALSE);
    }

    // Now walk the thread list of the system,
    // and display information about each thread
    // associated with the specified process
    DEBUG_EVENT event = { 0 };
    static BOOL bFirst = TRUE;
    do
    {
        if (te32.th32OwnerProcessID == dwOwnerPID)
        {
            RtlZeroMemory(&event, sizeof(DEBUG_EVENT));
            if (bFirst)
            {
                bFirst = FALSE;
                event.dwDebugEventCode = CREATE_PROCESS_DEBUG_EVENT;
                event.dwProcessId = dwOwnerPID;
                event.dwThreadId = te32.th32ThreadID;
                hMainThreadId = event.dwThreadId;
                event.u.CreateProcessInfo.hFile = hFile;
                event.u.CreateProcessInfo.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwOwnerPID);
                hDebuggedProcess = event.u.CreateProcessInfo.hProcess;
                event.u.CreateProcessInfo.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, event.dwThreadId);
                event.u.CreateProcessInfo.lpBaseOfImage = GetModuleBase(NULL);
                event.u.CreateProcessInfo.fUnicode = 1;
                m_event.push_back(event);


            }
            else
            {
                event.dwDebugEventCode = CREATE_THREAD_DEBUG_EVENT;
                event.dwProcessId = dwOwnerPID;
                event.dwThreadId = te32.th32ThreadID;
                event.u.CreateThread.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, event.dwThreadId);
                event.u.CreateThread.lpStartAddress = (LPTHREAD_START_ROUTINE)GetThreadStartAddress(event.u.CreateThread.hThread);
                event.u.CreateProcessInfo.fUnicode = 1;
                m_event.push_back(event);
            }
        }
    } while (Thread32Next(hThreadSnap, &te32));
    CloseHandle(hThreadSnap);

    for (auto it = m_moduleInfo.begin(); it != m_moduleInfo.end(); ++it)
    {
        if (!wcsstr(it->szModule, L".exe"))
        {
            RtlZeroMemory(&event, sizeof(DEBUG_EVENT));
            event.dwDebugEventCode = LOAD_DLL_DEBUG_EVENT;
            event.dwProcessId = dwOwnerPID;
            event.dwThreadId = hMainThreadId;
            event.u.CreateProcessInfo.fUnicode = 1;
            event.u.LoadDll.hFile = CreateFileW(it->szExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
            event.u.LoadDll.lpBaseOfDll = it->modBaseAddr;
            m_event.push_back(event);
        }
    }



    bFirst = TRUE;
    return(TRUE);
}



BOOL APIENTRY VehWaitForDebugEvent(
    _Out_ LPDEBUG_EVENT lpDebugEvent,
    _In_ DWORD dwMilliseconds
)

{
    BOOL bRet = FALSE;

    handler_cs.Enter();
    if (!m_event.empty())
    {
        RtlCopyMemory(lpDebugEvent, &m_event.front(), sizeof(DEBUG_EVENT));
        m_event.pop_front();
        bRet = TRUE;
        InterlockedExchange(&hNoExceptionEvent, 1);

        handler_cs.Leave();
        return bRet;
    }
    handler_cs.Leave();


    DWORD nResult = WaitForSingleObject(HasDebugEvent, dwMilliseconds);
    if (nResult == WAIT_OBJECT_0)
    {
        RtlCopyMemory(lpDebugEvent, &pShareMem->DebugEvent, sizeof(DEBUG_EVENT));

        return TRUE;
    }


    return bRet;
}

BOOL
APIENTRY
VehContinueDebugEvent(
    _In_ DWORD dwProcessId,
    _In_ DWORD dwThreadId,
    _In_ DWORD dwContinueStatus
)

{
    BOOL bRet = FALSE;

    if (InterlockedCompareExchange(&hNoExceptionEvent, 0, 1) == 1) {
        return TRUE;
    }
    pShareMem->dwContinueStatus = dwContinueStatus;
    pShareMem->dwProcessId = dwProcessId;
    pShareMem->dwThreadId = dwThreadId;
    pShareMem->DebugEvent.dwDebugEventCode = 0;
    bRet = SetEvent(HasHandledDebugEvent);

    return bRet;
}
NTSTATUS VehDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
{
    NTSTATUS ntStaus = STATUS_ACCESS_VIOLATION;
    HasDebugEvent = 0;
    HasHandledDebugEvent = 0;
    static BOOL bInit = FALSE;
    if (!bInit)
    {
        bInit = TRUE;
        handler_cs.Init();
    }

    GUID guid[3] = {0,0,0};
 
    for (int i = 0; i < 3; i++) {
        HRESULT h = CoCreateGuid(&guid[i]);
        if (h == S_OK) {
            strcpy_s(ConfigName[i], GuidToString(guid[i]).c_str());
        }
        else {
            return ntStaus;
        }
    }



    if (InitFileMapping())
    {
        HasDebugEvent = CreateEventA(NULL, FALSE, FALSE, ConfigName[1]);
        HasHandledDebugEvent = CreateEventA(NULL, FALSE, FALSE, ConfigName[2]);

        ListProcessModules(ProcessHandle);
        ListProcessThreads(ProcessHandle);

        strcpy_s(pShareMem->ConfigName[0], ConfigName[1]);
        strcpy_s(pShareMem->ConfigName[1], ConfigName[2]);
        DuplicateHandle(GetCurrentProcess(), HasDebugEvent, hDebuggedProcess, &pShareMem->HasDebugEvent, 0, false, DUPLICATE_SAME_ACCESS);
        DuplicateHandle(GetCurrentProcess(), HasHandledDebugEvent, hDebuggedProcess, &pShareMem->HasHandledDebugEvent, 0, false, DUPLICATE_SAME_ACCESS);
        //注入 就可以了

        PVOID pDllBase = NULL;

#ifdef _WIN64
#define DLL_PATH "E:\\vs2019\\VehDebug\\x64\\Debug\\VehDebug.dll"
#else
#define DLL_PATH "E:\\vs2019\\VehDebug\\Debug\\VehDebug.dll"
#endif
        if ((InjectDll(hDebuggedProcess,DLL_PATH,&pDllBase)) && HasDebugEvent && HasHandledDebugEvent) {
            ntStaus = 0;
        }
    }

   

    return ntStaus;
}




DWORD HandleToPid(HANDLE hProcess)
{
    PROCESS_BASIC_INFORMATION pi = { 0 };
    if (NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pi, sizeof(PROCESS_BASIC_INFORMATION), 0)))
    {
        return (DWORD)pi.UniqueProcessId;
    }
    return 0;
}

PVOID GetThreadStartAddress(HANDLE hThread)
{
    PVOID b = NULL;
    if (NT_SUCCESS(NtQueryInformationThread(hThread, (THREADINFOCLASS)9, &b, sizeof(PVOID), 0))) {
        return b;
    }

    return NULL;
}

BOOL VehSetThreadContext(HANDLE hThread, const CONTEXT* lpContext)
{
    BOOL bRet = FALSE;

    __try
    {
        RtlCopyMemory(&pShareMem->CurrentContext, lpContext, sizeof(CONTEXT));
        bRet = TRUE;
    }
    __except (1)
    {

    }

    return bRet;
}

BOOL VehGetThreadContext(HANDLE hThread, const CONTEXT* lpContext)
{
    BOOL bRet = FALSE;
    __try
    {

        RtlCopyMemory((void*)lpContext, &pShareMem->CurrentContext, sizeof(CONTEXT));
        bRet = TRUE;
    }
    __except (1)
    {

    }

    return bRet;
}

PVOID GetModuleBase(WCHAR* szModule)
{

    for (auto it = m_moduleInfo.begin(); it != m_moduleInfo.end(); ++it)
    {
        if (!szModule)
        {
            if (wcsstr(it->szModule, L".exe"))
            {
                return it->modBaseAddr;
            }
        }
        else {
            if (wcsstr(it->szModule, szModule))
            {
                return it->modBaseAddr;
            }
        }
    }

    return NULL;
}


BOOL InitFileMapping()
{
    SECURITY_ATTRIBUTES sa = { 0 };
    SECURITY_DESCRIPTOR sd = { 0 };
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = &sd;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    HANDLE hFileMapping = CreateFileMappingA(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, sizeof(VEHDebugSharedMem), ConfigName[0]);
    if (hFileMapping == NULL)
    {
        return false;
    }
    pShareMem = (VEHDebugSharedMem*)MapViewOfFile(hFileMapping, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
    if (pShareMem)
    {
        RtlSecureZeroMemory(pShareMem, sizeof(VEHDebugSharedMem));


        return true;
    }

    return false;
}





BOOL IsTargetException()
{
    BOOL bRet = FALSE;

    __try
    {
        if (pShareMem->DebugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            bRet = TRUE;
        }
    }
    __except (1)
    {

    }
    return bRet;
}

std::string GuidToString(const GUID& guid)
{
    char buf[64] = { 0 };
    sprintf_s(buf, sizeof(buf),
        "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return std::string(buf);
}

BOOL __stdcall HookedGetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
{
    BOOL bRet = FALSE;
    if (bEnableVeh && IsTargetException())
    {

        bRet = VehGetThreadContext(hThread, lpContext);
    }
    else {
        bRet = ((t_GetThreadContext)orgGetThreadContext)(hThread, lpContext);
    }


    return bRet;
}

BOOL __stdcall HookedSetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
{
    BOOL bRet = FALSE;
    if (bEnableVeh && IsTargetException())
    {
        bRet = VehSetThreadContext(hThread, lpContext);
    }
    else {

        bRet = ((t_GetThreadContext)orgSetThreadContext)(hThread, lpContext);
    }

    return bRet;
}

BOOL HookedWaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
{
    BOOL bRet = FALSE;
    if (bEnableVeh)
    {
        bRet = VehWaitForDebugEvent(lpDebugEvent, dwMilliseconds);
    }
    else {
        bRet = ((t_WaitForDebugEvent)orgWaitForDebugEvent)(lpDebugEvent, dwMilliseconds);
    }

    return bRet;
}

BOOL HookedContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus)
{
    BOOL bRet = FALSE;
    if (bEnableVeh)
    {
        bRet = VehContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus);
    }
    else {
        bRet = ((t_ContinueDebugEvent)orgContinueDebugEvent)(dwProcessId, dwThreadId, dwContinueStatus);
    }

    return bRet;
}

NTSTATUS HookedNtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
{
    MessageBoxW(NULL, L"启用Veh调试模式", L"提示", MB_OKCANCEL | MB_ICONEXCLAMATION) == IDOK ? bEnableVeh = TRUE : bEnableVeh = FALSE;
    NTSTATUS ntStaus = STATUS_ACCESS_VIOLATION;
    if (bEnableVeh)
    {
        ntStaus = VehDebugActiveProcess(ProcessHandle, DebugObjectHandle);
    }
    else {
        ntStaus = ((t_NtDebugActiveProcess)orgNtDebugActiveProcess)(ProcessHandle, DebugObjectHandle);
    }

    return ntStaus;
}



BOOL InjectDll(HANDLE ProcessHandle, const char* szDllPath, PVOID* pDllBase)
{
    BOOL bRet = FALSE;
    HMODULE h = LoadLibraryA(szDllPath);
    if (!h)return FALSE;

    PVOID InitializeVEH = NULL;
    PVOID  ConfigNameOffset = NULL;

    PVOID pTemp = NULL;
    PVOID pAllcoate = CreateInjectCode(ProcessHandle, szDllPath, pDllBase);
    if (pAllcoate)
    {
        HANDLE hRemote = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)pAllcoate, NULL, 0, 0);
        if (hRemote)
        {
            DWORD ExitCode = 0;
            WaitForSingleObject(hRemote, 5000);
            if (GetExitCodeThread(hRemote, &ExitCode)) {

                switch (ExitCode)
                {
                    case 1: 
                    {
                        if (ReadProcessMemory(ProcessHandle, *pDllBase, &pTemp, sizeof(ULONG_PTR), NULL)) {
                            *pDllBase = pTemp;

                            InitializeVEH = GetProcAddress(h, "InitializeVEH");
                            ConfigNameOffset = GetProcAddress(h, "ConfigName");
                            if (InitializeVEH && ConfigNameOffset) {

                                if (WriteProcessMemory(ProcessHandle, (PVOID)((ULONG_PTR)ConfigNameOffset - (ULONG_PTR)h+ (ULONG_PTR)pTemp), ConfigName[0],
                                    256, NULL))
                                {

                                    HANDLE hRemote = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)((ULONG_PTR)InitializeVEH - (ULONG_PTR)h + (ULONG_PTR)pTemp),
                                        NULL, 0, 0);
                                    if (hRemote) {
                                        bRet = TRUE;
                                        CloseHandle(hRemote);
                                    }
                                }
                            }
                        }
                        break;
                    }
                    case 2:
                    {
                        break;
                    }
                default:
                    break;
                }
            }


            CloseHandle(hRemote);
        }

        VirtualFreeEx(ProcessHandle, pAllcoate, 0, MEM_FREE);
    }

    FreeLibrary(h);




    return bRet;
}

PVOID CreateInjectCode(HANDLE ProcessHandle,const char* szDllPath,PVOID* pDllBase)
{
    ULONG_PTR nOffset = 0;
    PVOID pAllocate = VirtualAllocEx(ProcessHandle,NULL, 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pAllocate)return NULL;

    nOffset = (ULONG_PTR)pAllocate + sizeof(RemoteInjectShellCode);
    char szCode[0x1000] = { 0 };
    strcpy((char*)((ULONG_PTR)szCode + sizeof(RemoteInjectShellCode)), szDllPath);

    RemoteInjectShellCode code;
#ifdef _WIN64
    code.sub_rsp_0x28 = '\x48\x83\xec\x28';
    code.mov_rcx = '\x48\xb9';
    code.Arg_1 = (DWORD64)nOffset;
    code.call_FF15 = '\xff\x15';
    code.call_offset = 2;
    code.jmp_8 = '\xeb\x08';
    code.pLoadLibraryA = (DWORD64)LoadLibraryA;
    code.add_rsp_0x28 = '\x48\x83\xc4\x28';
    code.testRax[0] = '\x48';
    code.testRax[1] = '\x85';
    code.testRax[2] = '\xc0';
    code.jmp_6 = '\x75\x06';
    code.Register_eax1 = '\xb8';
    code.nResust1 = 2;
    code.Ret1 = '\xc3';
    code.mov_rcx1 = '\x48\xb9';
    code.pDllBase = ((DWORD64)&code.n - (DWORD64)&code + (DWORD64)pAllocate);
    code.movRcxRax[0] = '\x48';
    code.movRcxRax[1] = '\x89';
    code.movRcxRax[2] = '\x01';
    code.Register_eax2 = '\xb8';
    code.nResust2 = 1;
    code.Ret2 = '\xc3';
#else
    code.push = '\x68';
    code.arg = (DWORD)nOffset;
    code.call = '\xe8';
    code.call_offset = (DWORD)LoadLibraryA - ((DWORD)&code.test_eax - (DWORD)&code + (DWORD)pAllocate);
    code.test_eax = '\x85\xc0';
    code.jne_6 = '\x75\x06';
    code.Register_eax1 = '\xb8';
    code.nResust1 = 2;
    code.Ret1 = '\xc3';

    code.mov_rcx = '\xb9';
    code.pDllBase = ((DWORD)&code.n - (DWORD)&code + (DWORD)pAllocate);
    code.movEcxEax = '\x89\x01';

    code.Register_eax2 = '\xb8';
    code.nResust2 = 1;
    code.Ret2 = '\xc3';
#endif
    RtlCopyMemory((void*)szCode, &code, sizeof(code));

    if (WriteProcessMemory(ProcessHandle, pAllocate, szCode, 0x1000, NULL)) {

        *pDllBase = (PVOID)code.pDllBase;
    }

    return pAllocate;
}


// 你可以把 这个功能写成 插件 或者dll注入到 x96dbg调试器(我就不写了，我对 x96dbg调试器插件接口不了解)

DWORD InitWork(PVOID p)
{
    /*
    *                 x64dbg veh的实现逻辑 就是 重写下面 五个函数的逻辑
    * 1.其中 GetThreadContext SetThreadContext 函数 是x96dbg 的引擎的函数函数，主要负责 调试器与被调试器进程的交流
    * 如果出现某些 崩溃 bug ，重点检测这个两个函数。
    * 
    * 2.潜在的问题：由于在应用层 无法获取最新的 线程创建/销毁信息 模块的加载/卸载信息  会导致异常不到的情况（可以尝试把它移进 内核模式 通过 注册 回调历程来解决
     未来 我也会尝试把移进内核里）
    * 
    * 3.调试器最重要的就是 获取 异常信息 去具体参考dll(如果dll,有bug一定要修改,那是最重要的!最重要的!)
    * 
    * 4.如果有 Bug,欢迎交流!!!
    */

    MH_Initialize();
    MH_CreateHook((PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtDebugActiveProcess"), HookedNtDebugActiveProcess, &orgNtDebugActiveProcess);
    MH_CreateHook((PVOID)WaitForDebugEvent, HookedWaitForDebugEvent, &orgWaitForDebugEvent);
    MH_CreateHook((PVOID)ContinueDebugEvent, HookedContinueDebugEvent, &orgContinueDebugEvent);
    MH_CreateHook((PVOID)GetThreadContext, HookedGetThreadContext, &orgGetThreadContext);
    MH_CreateHook((PVOID)SetThreadContext, HookedSetThreadContext, &orgSetThreadContext);

    MH_EnableHook(MH_ALL_HOOKS);
    return 0;
}