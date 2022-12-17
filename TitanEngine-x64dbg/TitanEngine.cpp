#include "stdafx.h"
#include "stdafx.h"
#include "Global.Engine.h"
#include "Global.Garbage.h"
#include "Global.Injector.h"
#include "Global.Engine.Extension.h"
#include "Global.Engine.Threading.h"
#include "Global.Debugger.h"
#include "HookFunction.h"

// Global.Engine.Entry:
BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch(fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        engineHandle = hinstDLL;
        InitializeCriticalSection(&engineStepActiveCr);
        EngineInit();
        InitWork(NULL);
        EmptyGarbage();
        for(int i = 0; i < UE_MAX_RESERVED_MEMORY_LEFT; i++)
            engineReservedMemoryLeft[i] = NULL;
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break; //this bug has been here since 2010
    case DLL_PROCESS_DETACH:
        if(lpvReserved)
            ExtensionManagerPluginReleaseCallBack();
        RemoveDirectoryW(engineSzEngineGarbageFolder);
        CriticalSectionLocker::Deinitialize(); //delete critical sections
        break;
    }
    return TRUE;
}