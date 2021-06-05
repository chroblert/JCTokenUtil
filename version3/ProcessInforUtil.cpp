#include "ProcessInforUtil.h"
//#define PROCNAME_CHAR_COUNT 260

BOOL ProcessInforUtil::GetProcessNameFromPid(DWORD pid, TCHAR* tProcName) {
	//HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	HANDLE hProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
	if (hProc == NULL) {
		hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (hProc == NULL) {
			//std::cout << "\t获取进程句柄失败,ERROR: " << GetLastError() << std::endl;
			printf("JCT:获取进程句柄失败，%d\n", GetLastError());
			return FALSE;
		}
	}
	TCHAR* Buffer = (TCHAR*)calloc(PROCNAME_CHAR_COUNT,sizeof(TCHAR));
	if (!Buffer) {
		printf("\tmalloc失败，ERROR: %d\n", GetLastError());
		return FALSE;
	}
	//ZeroMemory(Buffer, MAX_PATH);
	if (!GetModuleFileNameEx(hProc, NULL, Buffer, PROCNAME_CHAR_COUNT))
	{
		// You better call GetLastError() here
		//std::cout << "\t" << "ProcessName   : error" << GetLastError() << std::endl;
		//printf("JCT:GetModuleFileNameEx获取进程文件名失败,error: %d\n", GetLastError());
		// [·] bug fix: 获取进程文件名失败：返回Unknown
		_tcscpy(tProcName,_T("UnKnown"));
		free(Buffer);
		Buffer = NULL;
		return TRUE;
	}
	else
	{
		_tcscpy(tProcName, Buffer);
		free(Buffer);
		Buffer = NULL;
		return TRUE;
	}
}