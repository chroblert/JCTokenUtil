
//#include <tchar.h>
//#include <windows.h>
//
//#include <NTSecAPI.h>
//#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#include "logonSession.h"
#include "TokenUtils.h"

int EnumLogonSessions() {
	//LARGE_INTEGER示例,参加CPlusplus工程

	//当前用户名称
	DWORD buflen = 256;
	TCHAR buffer[256];
	BOOL bRet = GetUserName(buffer, &buflen);
	if (bRet)
	{
		wprintf(L"Current User : %s\n", buffer);
	}
	else
	{
		wprintf(L"Call GetUserName FALSE.\n");
	}

	PLUID sessions;
	ULONG count;
	NTSTATUS retval;
	int i;

	retval = LsaEnumerateLogonSessions(&count, &sessions);

	if (retval != STATUS_SUCCESS) {
		wprintf(L"LsaEnumerate failed %lu\n",
			LsaNtStatusToWinError(retval));
		return 1;
	}
	wprintf(L"Enumerate sessions received %lu sessions.\n", count);

	// Process the array of session LUIDs...
	for (i = 0; i < (int)count; i++)
	{
		GetSessionData(&sessions[i]);
	}

	// Free the array of session LUIDs allocated by the LSA.
	LsaFreeReturnBuffer(sessions);

	return 0;

}