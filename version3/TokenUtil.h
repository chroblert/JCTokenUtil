#pragma once
#include "getopt.h"
#include "Helper.h"
#include <tchar.h>
#include <Windows.h>
#include "TokenInforUtil.h"
#include "Execute.h"
#include "settings.h"

extern BOOL bVerbose = FALSE;
extern BOOL bPrivileges = FALSE;
extern BOOL bCurInfo = FALSE;
extern BOOL bDisLogonSession = FALSE;
extern BOOL bConsoleMode = FALSE;

// ����module: Token,LogonSession,Execute
const TCHAR* ModuleList[] = { L"ListTokens",L"Execute",L"ListLogonSession" };

