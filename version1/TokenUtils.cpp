/*
Author: JC0o0l,Jerrybird
GitHub: https://github.com/chroblert/CodeLab/AccessToken
Desp: 访问令牌实验代码
*/

#include "TokenUtils.h"
#include "tidtest.h"

using namespace std;

const char* ILStr[4] = { "SecurityAnonymous","SecurityIdentification","SecurityImpersonation","SecurityDelegation" };


int IsTokenSystem(HANDLE tok)
{
	DWORD Size, UserSize, DomainSize;
	SID* sid;
	SID_NAME_USE SidType;
	TCHAR UserName[64], DomainName[64];
	TOKEN_USER* User;
	Size = 0;
	GetTokenInformation(tok, TokenUser, NULL, 0, &Size);
	if (!Size)
		return 0;
	User = (TOKEN_USER*)malloc(Size);
	//assert(0);// 如果参数值为0，则弹窗报错
	assert(User);
	GetTokenInformation(tok, TokenUser, User, Size, &Size);
	assert(Size);
	printf("%d\n", User->User.Sid);
	Size = GetLengthSid(User->User.Sid);
	assert(Size);
	sid = (SID*)malloc(Size);
	assert(sid);

	CopySid(Size, sid, User->User.Sid);
	UserSize = (sizeof UserName / sizeof * UserName) - 1;
	DomainSize = (sizeof DomainName / sizeof * DomainName) - 1;
	LookupAccountSid(NULL, sid, UserName, &UserSize, DomainName, &DomainSize, &SidType);
	free(sid);

	printf("whoami:\n%S\\%S\n", DomainName, UserName);
	// 比较该进程的用户是否为SYSTEM
	if (!_wcsicmp(UserName, L"SYSTEM")) {
		printf("SYSTEM 用户\n");
		return 0;
	}
	printf("%S 用户\n", &UserName);
	return 1;
}

VOID RetPrivDwordAttributesToStr(DWORD attributes, LPTSTR szAttrbutes)
{
	UINT len = 0;
	if (attributes & SE_PRIVILEGE_ENABLED)
		len += wsprintf(szAttrbutes, TEXT("Enabled"));
	if (attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
		len += wsprintf(szAttrbutes, TEXT("Enabled by default"));
	if (attributes & SE_PRIVILEGE_REMOVED)
		len += wsprintf(szAttrbutes, TEXT("Removed"));
	if (attributes & SE_PRIVILEGE_USED_FOR_ACCESS)
		len += wsprintf(szAttrbutes, TEXT("Used for access"));
	if (szAttrbutes[0] == 0)
		wsprintf(szAttrbutes, TEXT("Disabled"));
	return;
}
BOOL get_domain_username_from_token(HANDLE token, char* full_name_to_return)
{
	LPVOID TokenUserInfo[BUF_SIZE];
	char username[BUF_SIZE], domainname[BUF_SIZE];
	DWORD user_length = sizeof(username), domain_length = sizeof(domainname), sid_type = 0, returned_tokinfo_length;

	if (!GetTokenInformation(token, TokenUser, TokenUserInfo, BUF_SIZE, &returned_tokinfo_length))
		return FALSE;
	LookupAccountSidA(NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username, &user_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type);

	// Make full name in DOMAIN\USERNAME format
	sprintf(full_name_to_return, "%s\\%s", domainname, username);
	// 获取token中的账号
	//char* username;
	//get_domain_username_from_token(tok, username);
	//printf("username: %s\n", username);
	//PTOKEN_USER pTokenUser;
	//dwRet = 0;
	//GetTokenInformation(tok, TokenUser, pTokenUser, dwRet, &dwRet);
	//if (GetTokenInformation(tok, TokenUser, pTokenUser, dwRet, &dwRet)) {
	//	cout << "dwRet: " << dwRet << endl;
	//	printf("SID: %s,%d\n", (char*)pTokenUser->User.Sid, pTokenUser->User.Sid);
	//}

	return TRUE;
}
int GetTokenPrivilege(HANDLE tok)
{
	DWORD error;
	//char* tmpStr;
	char tmpStr[BUF_SIZE] = { 0 };
	get_domain_username_from_token(tok, tmpStr);
	printf(" \tUser: %s\n", tmpStr);
	
	PTOKEN_PRIVILEGES ppriv = NULL;
	DWORD dwRet = 0;
	//BOOL tmp = GetTokenInformation(tok, TokenGroups, ppriv, dwRet, &dwRet);
	GetTokenInformation(tok, TokenPrivileges, ppriv, dwRet, &dwRet);
	if (!dwRet)
		return 0;
	ppriv = (PTOKEN_PRIVILEGES)calloc(dwRet, 1);
	if (!GetTokenInformation(tok, TokenPrivileges, ppriv, dwRet, &dwRet)) {
		cout << " \t获取token信息失败，Error: " << GetLastError() << endl;
		return FALSE;

	}
	printf("\n \tprivileges:\n");
	if (ppriv->PrivilegeCount == 0) {
		cout << " \t\tno privileges" << endl;
	}
	else {
		for (int i = 0; i < ppriv->PrivilegeCount; i++)
		{
			TCHAR lpszPriv[MAX_PATH] = { 0 };
			DWORD dwRet = MAX_PATH;
			BOOL n = LookupPrivilegeName(NULL, &(ppriv->Privileges[i].Luid), lpszPriv, &dwRet);
			printf(" \t\t%-50ws", lpszPriv);
			TCHAR lpszAttrbutes[1024] = { 0 };
			RetPrivDwordAttributesToStr(ppriv->Privileges[i].Attributes, lpszAttrbutes);
			printf("%ws\n", lpszAttrbutes);
		}
	}

	
	LPVOID TokenImpersonationInfo[BUF_SIZE];

	DWORD returned_tokinfo_length;
	PSECURITY_IMPERSONATION_LEVEL pImpersonationLevel=NULL;
	dwRet = 0;
	GetTokenInformation(tok, TokenImpersonationLevel, TokenImpersonationInfo, dwRet, &dwRet);
	if (!GetTokenInformation(tok, TokenImpersonationLevel, TokenImpersonationInfo, dwRet, &dwRet)) {
		error = GetLastError();
		printf("\n \t获取IL失败: %d\n", error);
		
	}
	else {
		int idx = (int)*TokenImpersonationInfo;
		printf("\n \tImpersonationLevel: %s\n", ILStr[idx]);
	}

	//if (GetTokenInformation(tok, TokenImpersonationLevel, TokenImpersonationInfo, BUF_SIZE, &returned_tokinfo_length)) {
	//	int idx =(int)*TokenImpersonationInfo;
	//	printf("\n \tImpersonationLevel: %s\n", ILStr[idx]);
	//}
	//else {
	//	error = GetLastError();
	//	printf("\n \t获取IL失败: %d\n", error);
	//}
	LPVOID TokenType1[BUF_SIZE];
	returned_tokinfo_length = 0;
	if (GetTokenInformation(tok, TokenType, TokenType1, BUF_SIZE, &returned_tokinfo_length)) {
		error = GetLastError();
		printf(" \tTokenType: %d\n", *TokenType1);
		switch ((int)*TokenType1) {
		case 1:
			printf(" \tTokenType: Primary Token\n\n");
			break;
		case 2:
			printf(" \tTokenType: Impersonation Token\n\n");
			break;
		default:
			printf(" \tTokenType: Error: %d\n\n",error);
		}
	}

	return 1;
}

BOOL EnablePriv(HANDLE hToken, LPCTSTR priv)
{

	TOKEN_PRIVILEGES tp;
	LUID luid;
	// 用来获取priv对应的luid
	if (!LookupPrivilegeValue(NULL, priv, &luid))
	{
		printf("[!]LookupPrivilegeValue error\n");
		return 0;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	// 开启令牌中的Debug权限
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		printf("[!]AdjustTokenPrivileges error\n");
		return 0;
	}
	if (1300 == GetLastError()) {
		printf("JC| 2 |GetLastError: %d,没有成功调整权限\n", GetLastError());
	}
	return TRUE;
}
void EnumThreads() {
	THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (INVALID_HANDLE_VALUE == hThreadSnap) {
		cout << "error" << endl;
	}

	if (Thread32First(hThreadSnap, &te32)) {
		do {
			HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, TRUE, te32.th32ThreadID);
			HANDLE htoken;
			if (OpenThreadToken(hThread, TOKEN_QUERY, TRUE, &htoken)) {
				cout << "ThreadId : " << te32.th32ThreadID << endl;
				//printf("SUC\n");
				cout << '\t' << "OwnerProcessID: " << te32.th32OwnerProcessID << endl;
				cout << '\t' << "usage         : " << te32.cntUsage << endl;
				cout << '\t' << "Delta Priority: " << te32.tpDeltaPri << endl;
				cout << '\t' << "Base Prigority: " << te32.tpBasePri << endl;
				HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, te32.th32OwnerProcessID);
				TCHAR Buffer[MAX_PATH];
				if (GetModuleFileNameEx(hProc, NULL, Buffer, MAX_PATH))
				{
					printf("\tProcessName    : %S\n", Buffer);
				}
				else
				{
					// You better call GetLastError() here
					cout << "\t" << "ProcessName   : error" << GetLastError() << endl;
				}
				GetTokenPrivilege(htoken);
				//break;
			}
			else {
				//printf("Fail: %d\n",GetLastError());
				continue;
			}

		} while (Thread32Next(hThreadSnap, &te32));
	}
	CloseHandle(hThreadSnap);
}
BOOL GetProcessNameFromPid(DWORD pid, TCHAR** tProcName) {
	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (hProc == NULL) {
		hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
		if (hProc == NULL) {
			cout << "\t获取进程句柄失败,ERROR: " << GetLastError() << endl;
			return FALSE;
		}
	}
	TCHAR Buffer[MAX_PATH];
	if (GetModuleFileNameEx(hProc, NULL, Buffer, MAX_PATH))
	{
		//printf("\tProcessName    : %S\n", Buffer);
	}
	else
	{
		// You better call GetLastError() here
		cout << "\t" << "ProcessName   : error" << GetLastError() << endl;
		return FALSE;
	}
	*tProcName = (TCHAR*)malloc(sizeof(Buffer));
	_tcscpy(*tProcName, Buffer);
	//printf("%S\n", *tProcName);
	return TRUE;
}
void GetInfoFromPid(int pid) {


	// 根据pid获取进程句柄
	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (hProc == NULL) {
		hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
		if (hProc == NULL) {
			cout << "\t获取进程句柄失败,ERROR: " << GetLastError() << endl;
		}
	}
	TCHAR* tProcName;
	if(GetProcessNameFromPid(pid, &tProcName)){
		printf("\tProcessName: %S\n", tProcName);
	}
	HANDLE hToken;
	if (!OpenProcessToken(hProc, MAXIMUM_ALLOWED, &hToken)) {
		printf(" \t%d : 获取进程token失败: %d\n", pid, GetLastError());
	}
	else {
		GetTokenPrivilege(hToken);
	}
	CloseHandle(hToken);
	CloseHandle(hProc);

	// 枚举进程下的所有线程
	DWORD* pThreadList;
	DWORD dwThreadListLength;
	//cout << "pThreadList addr: " << pThreadList << endl;
	cout << "枚举[" << pid << "]进程下所有的线程:" << endl;
	if (!(dwThreadListLength=GetThreadListFromPid(pid, &pThreadList))) {
		printf("ERROR: %d\n", GetLastError());
	}
	for (int i = 0; i < dwThreadListLength; i++) {
		DWORD tid = pThreadList[i];
		GetInfoFromTid(tid);
	}
}

DWORD GetThreadListFromPid(DWORD dwOwnerPID,DWORD** pThreadList) {
	HANDLE        hThreadSnap = NULL;
	BOOL          bRet = FALSE;
	THREADENTRY32 te32 = { 0 };
	//cout << "GetThreadListFromPid - pThreadList addr: " << *pThreadList << endl;

	*pThreadList = (DWORD*)malloc(BUF_SIZE * sizeof(dwOwnerPID));
	// Take a snapshot of all threads currently in the system. 
	//cout << "GetThreadListFromPid - pThreadList addr: " << *pThreadList << endl;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return (FALSE);

	// Fill in the size of the structure before using it. 

	te32.dwSize = sizeof(THREADENTRY32);

	// Walk the thread snapshot to find all threads of the process. 
	// If the thread belongs to the process, add its information 
	// to the display list.
	int i = 0;
	if (Thread32First(hThreadSnap, &te32))
	{
		do
		{
			if (te32.th32OwnerProcessID == dwOwnerPID)
			{
				//printf("%d   %x\n", te32.th32ThreadID, te32.th32ThreadID);
				//printf("Owner PID/t%d/n", te32.th32OwnerProcessID);
				//printf("Delta Priority/t%d/n", te32.tpDeltaPri);
				//printf("Base Priority/t%d/n", te32.tpBasePri);
				(*pThreadList)[i] = te32.th32ThreadID;
				//printf("xxx %d\n", (*pThreadList)[i]);
				i++;
			}
		} while (Thread32Next(hThreadSnap, &te32));
		bRet = TRUE;
		CloseHandle(hThreadSnap);
		return i;
	}
	else
		bRet = FALSE;          // could not walk the list of threads 

	// Do not forget to clean up the snapshot object. 

	CloseHandle(hThreadSnap);

	return (bRet);
}
BOOL GetInfoFromTid(DWORD tid) {
	DWORD error;
	cout << "ThreadId : " << tid << endl;
	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, TRUE, tid);

	if (NULL == hThread) {
		hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, TRUE, tid);
		if (hThread == NULL) {
			error = ::GetLastError();
			SetLastError(error);
			cout << "\t获取线程句柄失败，ERROR:" << error << "\n" << endl;
			return FALSE;
		}
	}
	HANDLE htoken;
	HANDLE hProc;
	DWORD dwPid = getPIDFromTid(tid);
	if (dwPid == FALSE) {
		cout << "\t根据线程TID获取进程PID失败" << endl;
		//return FALSE;
	}
	else {
		cout << '\t' << "OwnerProcessID: " << dwPid << endl;
		hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		//HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
		if (hProc == NULL)
		{
			hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid);
			if (NULL == hProc) {
				error = ::GetLastError();
				SetLastError(error);
				cout << "\t获取进程句柄失败，ERROR:" << error << endl;
				return FALSE;
			}

		};
		TCHAR Buffer[MAX_PATH];
		if (GetModuleFileNameEx(hProc, NULL, Buffer, MAX_PATH))
		{
			printf("\tProcessName    : %S\n", Buffer);
		}
		else
		{
			cout << "\tProcessName   : error" << GetLastError() << endl;
		}
	}
	

	if (OpenThreadToken(hThread, TOKEN_QUERY, TRUE, &htoken)) {
		
		GetTokenPrivilege(htoken);
	}
	else {
		//printf("Fail: %d\n",GetLastError());
		DWORD error = ::GetLastError();
		SetLastError(error);
		if (1008 == error) {
			cout << "\t该线程不存在模拟令牌,";
		}
		cout << " ERROR:" << error << endl;

		
	}
	CloseHandle(hThread);
	CloseHandle(hProc);
	return TRUE;
}


DWORD TryEnableDebugPriv(HANDLE token)
{
	HANDLE hToken = token;
	DWORD dwError = 0;
	TOKEN_PRIVILEGES privileges;

	if (hToken == NULL && !OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken))
	{
		dwError = GetLastError();
		goto exit;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &privileges.Privileges[0].Luid))
	{
		dwError = GetLastError();
		goto exit;
	}

	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	privileges.PrivilegeCount = 1;

	if (AdjustTokenPrivileges(hToken, FALSE, &privileges, 0, NULL, NULL) == 0)
	{
		dwError = GetLastError();
		goto exit;
	}

exit:
	if (token == NULL && hToken)
		CloseHandle(hToken);

	return dwError;
}

DWORD TryEnableAssignPrimaryPriv(HANDLE token)
{
	HANDLE hToken = token;
	DWORD dwError = 0;
	TOKEN_PRIVILEGES privileges;

	if (hToken == NULL && !OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken))
	{
		dwError = GetLastError();
		goto exit;
	}

	if (!LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &privileges.Privileges[0].Luid))
	{
		dwError = GetLastError();
		goto exit;
	}

	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	privileges.PrivilegeCount = 1;

	if (AdjustTokenPrivileges(hToken, FALSE, &privileges, 0, NULL, NULL) == 0)
	{
		dwError = GetLastError();
		goto exit;
	}

exit:
	if (token == NULL && hToken)
		CloseHandle(hToken);

	return dwError;
}


/*
desp: 用来枚举当前系统中所有进程及其线程的主令牌或模拟令牌
params: none
*/
void EnumProcess() {
	//创建一个进程快照
	HANDLE snapHandele = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (INVALID_HANDLE_VALUE == snapHandele)
	{
		cout << "CreateToolhelp32Snapshot error" <<endl;
		return;
	}
	PROCESSENTRY32 entry = { 0 };
	entry.dwSize = sizeof(entry);// 长度必须赋值
	// 第一个进程
	BOOL ret = Process32First(snapHandele, &entry);
	int i = 0;
	printf("序号\tPID\tPPID\tProg\n");
	while (ret) {
		HANDLE hProc;
		WCHAR *exeFile = entry.szExeFile;
		printf("%d\t%d\t%d\t%S\n",i, entry.th32ProcessID,entry.th32ParentProcessID, exeFile );
		// 跳过System及PID为0的进程
		if (0 == entry.th32ProcessID || !wcscmp(TEXT("System"),exeFile) ){
			goto loop;
		}
		TCHAR* tProcName;
		if (GetProcessNameFromPid(entry.th32ProcessID, &tProcName)) {
			printf("\tProcessName: %S\n", tProcName);
		}
		// 根据pid获取进程句柄
		// 这里对于一些进程会报错,会显示Access Dined
		 hProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, entry.th32ProcessID);
		//cout << "364 ERROR: " << GetLastError() << endl;
		if (hProc == NULL) {
			hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, entry.th32ProcessID);
			if (hProc == NULL) {
				cout << "\t获取进程句柄失败,ERROR: " << GetLastError() << endl;
				//getchar();
				goto loop;
			}

		}
		HANDLE hToken;
		if (!OpenProcessToken(hProc, MAXIMUM_ALLOWED, &hToken)) {
			printf(" \t获取进程token失败: %d\n\n", GetLastError());
		}
		else {
			//printf(" \t%d: Success\n", entry.th32ProcessID);
			GetTokenPrivilege(hToken);
		}
		CloseHandle(hToken);
		CloseHandle(hProc);
		loop:
			i++;
			ret = Process32Next(snapHandele, &entry);
	}
	CloseHandle(snapHandele);

}


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
			wprintf(L"\nUser name too long for buffer. Exiting program.");
			return;
		}

		wprintf(L"user %s was authenticated ", buffer);
	}
	else {
		wprintf(L"\nMissing user name.\n");
		LsaFreeReturnBuffer(sessionData);
		return;
	}
	if ((SECURITY_LOGON_TYPE)sessionData->LogonType == Interactive) {
		wprintf(L"interactively ");
	}
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
			wprintf(L"\nAuthentication package too long for buffer."
				L" Exiting program.");
			return;
		}
		wprintf(L"using %s ", buffer);
	}
	else {
		wprintf(L"\nMissing authentication package.");
		LsaFreeReturnBuffer(sessionData);
		return;
	}
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
			wprintf(L"\nLogon domain too long for buffer."
				L" Exiting program.");
			return;
		}
		wprintf(L"in the %s domain.\n", buffer);
	}
	else {
		wprintf(L"\nMissing authenticating domain information. ");
		LsaFreeReturnBuffer(sessionData);
		return;
	}
	// Free the memory returned by the LSA.
	LsaFreeReturnBuffer(sessionData);
	return;
}


void printUsage() {
	string rawUsageMsg = R"(
Usage: test.exe [OPTION]

[OPTION]
-p [pid|ALL]: 列出所有进程中的令牌或列出某个进程中的令牌
-t [tid|ALL]: 列出所有线程中的模拟令牌或某个线程中的模拟令牌
-l : 列出当前所有的登录会话
-c : 列出当前的信息)";
	cout << rawUsageMsg << "\n\n";
}
void tchar2char(TCHAR* input, char* output) {
	int length = WideCharToMultiByte(CP_ACP, 0, input, -1, NULL, 0, NULL, NULL);
	WideCharToMultiByte(CP_ACP, 0, input, -1, output, length, NULL, NULL);
}

char* TCHARToChar(TCHAR* pTchar)
{
	char* pChar = nullptr;
	int nLen = wcslen(pTchar) + 1;
	pChar = new char[nLen * 2];
	WideCharToMultiByte(CP_ACP, 0, pTchar, nLen, pChar, 2 * nLen, NULL, NULL);
	return pChar;
}
TCHAR* CharToTCHAR(char* pChar)
{
	TCHAR* pTchar = nullptr;
	int nLen = strlen(pChar) + 1;
	pTchar = new wchar_t[nLen];
	MultiByteToWideChar(CP_ACP, 0, pChar, nLen, pTchar, nLen);
	return pTchar;
}
int _tmain(int argc, _TCHAR* argv[])
{
	TryEnableDebugPriv(NULL);
	TryEnableAssignPrimaryPriv(NULL);
	// 从命令行获取参数
	char opt;
	char* optStr= NULL;
	while ((opt = getopt(argc, argv, "p:t:lc")) != -1){
		
		switch (opt) {
		case 'p':
			optStr = TCHARToChar(optarg);
			cout << opt << " : " << optStr << endl;
			if ((_tcscmp(optarg, L"ALL")) == 0) {
				cout << "All Primary Token:" << endl;
				EnumProcess();
			}
			else {
				cout << "Primary Token In [" << optStr << "] Process" << endl;
				GetInfoFromPid(atoi(optStr));
			}
			break;
		case 't':
			optStr = TCHARToChar(optarg);
			cout << opt << " : " << optStr << endl;
			if ((_tcscmp(optarg, L"ALL"))==0) {
				cout << "All Impersernation Token:" << endl;
				EnumThreads();
			}
			else {
				cout << "Impersonation Token In [" << optStr << "] Thread" << endl;
				GetInfoFromTid(atoi(optStr));
			}
			break;
		case 'l':
			EnumLogonSessions();
			break;
		case 'c':
			HANDLE hToken;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
			{
				printf("[!]OpenProcessToken error\n");
				return 0;
			}
			else {
				// 判断是不是SYSTEM用户
				//IsTokenSystem(hToken);
				cout << "当前进程的令牌信息如下：" << endl;
				GetTokenPrivilege(hToken);
			}
			break;
		default:
			printUsage();
			exit(1);
		}
	}
	return 0;
}