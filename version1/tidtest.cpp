#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <locale.h>
#include <iostream>
#pragma	comment(lib,"psapi.lib")


typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    MaxThreadInfoClass
} THREADINFOCLASS;
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID* PCLIENT_ID;
typedef struct _THREAD_BASIC_INFORMATION { // Information Class 0
    LONG ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    LONG AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;
extern "C" LONG(__stdcall * ZwQueryInformationThread) (
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    ) = NULL;

int getPIDFromTid(DWORD dwThreadId) {
    setlocale(LC_ALL, ".ACP");
    HINSTANCE hNTDLL = ::GetModuleHandle(TEXT("ntdll"));
    (FARPROC&)ZwQueryInformationThread = ::GetProcAddress(hNTDLL, "ZwQueryInformationThread");
    THREAD_BASIC_INFORMATION    tbi;
    PVOID                       startaddr;
    LONG                        status;
    HANDLE                      thread, process;
    // DWORD dwThreadId = 3840;
    //thread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
    thread = ::OpenThread(THREAD_QUERY_INFORMATION, FALSE, dwThreadId);

    DWORD error;
    if (NULL == thread) {
        thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, TRUE, dwThreadId);
        if (thread == NULL) {
            error = ::GetLastError();
            SetLastError(error);
            std::cout << "\t打开线程失败，ERROR:" << error << std::endl;
            return FALSE;
        }
    }
    //error = GetLastError();
    //if (thread == NULL)
    //{
    //    printf("\tcannot open thread handle\n");
    //    std::cout << "\tError: " << error << std::endl;
    //    return FALSE;
    //}
    status = ZwQueryInformationThread(thread, ThreadQuerySetWin32StartAddress, &startaddr, sizeof(startaddr), NULL);
    error = ::GetLastError();
    
    if (status < 0)
    {
        CloseHandle(thread);
        SetLastError(error);
        std::cout << "\tZwQueryInformationThread失败,ERROR:" << error <<  std::endl;
        //printf("\tcannot get status1\n");
        return FALSE;
    };
    //printf("线程 %08x 的起始地址为 %p\n", dwThreadId, startaddr);
    status = ZwQueryInformationThread(thread,
        ThreadBasicInformation,
        &tbi,
        sizeof(tbi),
        NULL);
    if (status < 0)
    {
        CloseHandle(thread);
        printf("cannot get status2\n");
        return FALSE;
    };
   // printf("线程 %08d 所在进程ID为 %08d\n", dwThreadId, (DWORD)tbi.ClientId.UniqueProcess);
    process = ::OpenProcess(PROCESS_ALL_ACCESS,
        FALSE,
        (DWORD)tbi.ClientId.UniqueProcess);
    if (process == NULL)
    {
        DWORD error = ::GetLastError();
        CloseHandle(thread);
        SetLastError(error);
        return FALSE;
    };
    TCHAR modname[0x100];
    ::GetModuleFileNameEx(process, NULL, modname, 0x100);
    //printf("线程 %08x 所在进程映象为 %S\n", dwThreadId, modname);
    GetMappedFileName(process,
        startaddr,
        modname,
        0x100);
    /*std::string stName(pName);
    std::string stModName(modname);
    if (stModName.find(stName) != std::string::npos)
    {
        printf("线程 %08x 可执行代码所在模块为 %s\n", dwThreadId, modname);
        ret = TRUE;
    }*/
    CloseHandle(process);
    CloseHandle(thread);

    return (DWORD)tbi.ClientId.UniqueProcess;

}