#pragma once
#include <windows.h>
#include <assert.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib,"user32.lib") 
#include <tchar.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <iostream>
#include "psapi.h"
#include <string>
#include <NTSecAPI.h>
#include <string>
#define BUF_SIZE 4096
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#pragma comment(lib,"Secur32.lib")
#include "getopt.h"
#include "logonSession.h"


VOID GetSessionData(PLUID);
DWORD GetThreadListFromPid(DWORD dwOwnerPID, DWORD** pThreadList);
BOOL GetInfoFromTid(DWORD tid);