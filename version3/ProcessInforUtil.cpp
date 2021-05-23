#include "ProcessInforUtil.h"
//#define PROCNAME_CHAR_COUNT 260

BOOL ProcessInforUtil::GetProcessNameFromPid(DWORD pid, TCHAR* tProcName) {
	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (hProc == NULL) {
		hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
		if (hProc == NULL) {
			//std::cout << "\t获取进程句柄失败,ERROR: " << GetLastError() << std::endl;
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
		free(Buffer);
		Buffer = NULL;
		return FALSE;
	}
	else
	{
		_tcscpy(tProcName, Buffer);
		free(Buffer);
		Buffer = NULL;
		return TRUE;
	}
}