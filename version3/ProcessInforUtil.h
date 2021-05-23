#pragma once
#include <tchar.h>
#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include "settings.h"

class ProcessInforUtil
{
public:
	static BOOL GetProcessNameFromPid(DWORD pid, TCHAR* tProcName);
};

