#pragma once
#include <tchar.h>
#include <windows.h>
#include "TokenInforUtil.h"
#include "settings.h"
#include <stdio.h>

static HANDLE hChildStdinRd, hChildStdinWr, hChildStdoutRd, hChildStdoutWr, hStdout;

class Execute
{
public:
	static BOOL ExecuteWithToken(HANDLE hToken,TCHAR* tCommand,BOOL bConsoleMode);
	static BOOL ExecuteMain(TCHAR* tUsername, DWORD dwPid,TCHAR* tCommand, BOOL bConsoleMode);
	static void CreateProcessWithPipeComm(HANDLE token, TCHAR* command);
	static void CreateChildProcess(HANDLE token, TCHAR* command, PROCESS_INFORMATION* piProcInfo);
	static DWORD WINAPI ReadFromPipe(LPVOID p);
	static DWORD WINAPI WriteToPipe(LPVOID p);
	static BOOL output_counted_string(char* string, DWORD dwRead);
	static BOOL read_counted_input(char* string, int string_size, DWORD* dwRead);
	static void create_process(HANDLE token, TCHAR* command, BOOL console_mode, SECURITY_IMPERSONATION_LEVEL impersonation_level);
};
