
//#include <tchar.h>
//#include <windows.h>
//
//#include <NTSecAPI.h>
//#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#include "logonSession.h"
#include "TokenUtils.h"


VOID GetSessionData(PLUID session)
{
	PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
	NTSTATUS retval;
	WCHAR buffer[256];
	WCHAR* usBuffer;
	int usLength;

	// Check for a valid session.
	if (!session) {
		wprintf(L"Error - Invalid logon session identifier.\n");
		return;
	}
	// Get the session information.
	//调用者必须是拥有该session或者是本地的系统管理员,否则window错误码为5
	retval = LsaGetLogonSessionData(session, &sessionData);
	if (retval != STATUS_SUCCESS) {
		// An error occurred. Tell the world.
		wprintf(L"LsaGetLogonSessionData failed %lu \n",
			LsaNtStatusToWinError(retval));
		// If session information was returned, free it.
		if (sessionData) {
			LsaFreeReturnBuffer(sessionData);
		}
		return;
	}
	// Determine whether there is session data to parse. 
	if (!sessionData) { // no data for session
		wprintf(L"Invalid logon session data. \n");
		return;
	}
	// 输出登录会话中的LogonId
	wprintf(L"LogonId: %08x-%08x\n", sessionData->LogonId.HighPart, sessionData->LogonId.LowPart);

	// 输出登录会话中的用户名
	if (sessionData->UserName.Buffer != NULL) {
		// Get the user name.
		usBuffer = (sessionData->UserName).Buffer;
		usLength = (sessionData->UserName).Length;
		if (usLength < 256)
		{
			wcsncpy_s(buffer, 256, usBuffer, usLength);
			wcscat_s(buffer, 256, L"");
		}
		else
		{
			wprintf(L"\tUser name too long for buffer. Exiting program.\n");
			return;
		}

		wprintf(L"\tuser : %s \n ", buffer);
	}
	else {
		wprintf(L"\tMissing user name.\n");
		LsaFreeReturnBuffer(sessionData);
		return;
	}
	// 输出登录会话中的用来进行身份验证的服务器
	if (sessionData->LogonServer.Buffer != NULL) {
		// Get the user name.
		usBuffer = (sessionData->LogonServer).Buffer;
		usLength = (sessionData->LogonServer).Length;
		if (usLength < 256)
		{
			wcsncpy_s(buffer, 256, usBuffer, usLength);
			wcscat_s(buffer, 256, L"");
		}
		else
		{
			wprintf(L"\tLogonServer name too long for buffer. Exiting program.\n");
			return;
		}

		wprintf(L"\tLogonServer : %s \n ", buffer);
	}
	else {
		wprintf(L"\tMissing LogonServer name.\n");
		LsaFreeReturnBuffer(sessionData);
		return;
	}
	// 输出登录会话中的登录类型
	if ((SECURITY_LOGON_TYPE)sessionData->LogonType == Interactive) {
		wprintf(L"\tLogonType: interactively\n");
	}
	// 输出登录会话中的身份验证程序包
	if (sessionData->AuthenticationPackage.Buffer != NULL) {
		// Get the authentication package name.
		usBuffer = (sessionData->AuthenticationPackage).Buffer;
		usLength = (sessionData->AuthenticationPackage).Length;
		if (usLength < 256)
		{
			wcsncpy_s(buffer, 256, usBuffer, usLength);
			wcscat_s(buffer, 256, L"");
		}
		else
		{
			wprintf(L"\tAuthentication package too long for buffer."
				L" Exiting program.");
			return;
		}
		wprintf(L"\tAuthenticationPackage: %s \n", buffer);
	}
	else {
		wprintf(L"\tMissing authentication package.\n");
		LsaFreeReturnBuffer(sessionData);
		return;
	}
	// 输出登录会话中的登录域
	if (sessionData->LogonDomain.Buffer != NULL) {
		// Get the domain name.
		usBuffer = (sessionData->LogonDomain).Buffer;
		usLength = (sessionData->LogonDomain).Length;
		if (usLength < 256)
		{
			wcsncpy_s(buffer, 256, usBuffer, usLength);
			wcscat_s(buffer, 256, L"");
		}
		else
		{
			wprintf(L"\tLogon domain too long for buffer."
				L" Exiting program.");
			return;
		}
		wprintf(L"\tLogonDomain: %s \n", buffer);
	}
	else {
		wprintf(L"\tMissing authenticating domain information. ");
		LsaFreeReturnBuffer(sessionData);
		return;
	}
	// Free the memory returned by the LSA.
	LsaFreeReturnBuffer(sessionData);
	return;
}

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
		printf("\n");
	}

	// Free the array of session LUIDs allocated by the LSA.
	LsaFreeReturnBuffer(sessions);

	return 0;
}