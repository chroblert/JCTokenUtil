/*
Author: JC0o0l,Jerrybird
GitHub: https://github.com/chroblert/CodeLab/AccessToken
*/

#include "TokenUtils.h"
//#include "tidtest.h"

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
	//assert(0);// �������ֵΪ0���򵯴�����
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
	// �Ƚϸý��̵��û��Ƿ�ΪSYSTEM
	if (!_wcsicmp(UserName, L"SYSTEM")) {
		printf("SYSTEM �û�\n");
		return 0;
	}
	printf("%S �û�\n", &UserName);
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
BOOL GetDomainUsernameFromToken(HANDLE token, char* full_name_to_return)
{
	LPVOID TokenUserInfo[BUF_SIZE];
	char username[BUF_SIZE], domainname[BUF_SIZE];
	DWORD user_length = sizeof(username), domain_length = sizeof(domainname), sid_type = 0, dwRet;

	if (!GetTokenInformation(token, TokenUser, TokenUserInfo, BUF_SIZE, &dwRet))
		return FALSE;
	LookupAccountSidA(NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username, &user_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type);

	// Make full name in DOMAIN\USERNAME format
	sprintf(full_name_to_return, "%s\\%s", domainname, username);
	return TRUE;
}
BOOL GetTokenInfo(HANDLE hToken) {
	DWORD error;
	DWORD dwRet=0;
	PTOKEN_GROUPS_AND_PRIVILEGES pTokenGroupsAndPrivileges=NULL;
	GetTokenInformation(hToken, TokenGroupsAndPrivileges, NULL, NULL, &dwRet);
	printf("\tGetTokenInfo: %d\n", dwRet);
	if (dwRet == 0) {
		return FALSE;
	}
	else {
		pTokenGroupsAndPrivileges = (PTOKEN_GROUPS_AND_PRIVILEGES)calloc(dwRet, 1);
		NTSTATUS status = GetTokenInformation(hToken, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet);
		//cout << "\tstatus: " << status << endl;
		if (!NT_SUCCESS(status)) {
			printf("\t��ȡ������Ϣʧ�ܣ�ERROR: %d\n", GetLastError());
			return FALSE;
		}
		else {
			printf("\tAuthId: %08x-%08x\n", pTokenGroupsAndPrivileges->AuthenticationId.HighPart, pTokenGroupsAndPrivileges->AuthenticationId.LowPart);
		}
	}
	return TRUE;
}


BOOL GetTokenILFromToken(HANDLE hToken, DWORD* dwIL) {
	//LPVOID TokenImpersonationInfo[BUF_SIZE];
	PSECURITY_IMPERSONATION_LEVEL pTokenIL = NULL;
	DWORD dwRet = 0;
	// ��ȡ����ģ��ȼ���Ϣ������ȡ�������ж�ģ��ȼ��ǲ��Ǵ��ڵ���ģ��
	GetTokenInformation(hToken, TokenImpersonationLevel, pTokenIL, NULL, &dwRet);
	pTokenIL = (PSECURITY_IMPERSONATION_LEVEL)malloc(dwRet);
	if (GetTokenInformation(hToken, TokenImpersonationLevel, pTokenIL, dwRet, &dwRet)) {
		*dwIL = *pTokenIL;
		//printf("\t��ȡ�����е�ģ��ȼ��ɹ���%d\n", *dwIL);
	}
	else {
		//printf("\t��ȡ�����е�ģ��ȼ�ʧ�ܣ�ERROR: %d\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}



BOOL GetTokenTypeFromToken(HANDLE hToken) {
	DWORD* pTokenTypeInfo;
	DWORD dwRet = 0;
	DWORD error;
	GetTokenInformation(hToken, TokenType, NULL, NULL, &dwRet);
	if (0 == dwRet) {
		error = GetLastError();
		printf(" \tTokenType\t: Error: %d\n\n", error);
		return FALSE;
	}

	pTokenTypeInfo = (DWORD*)malloc(dwRet);
	if (GetTokenInformation(hToken, TokenType, pTokenTypeInfo, dwRet, &dwRet)) {
		error = GetLastError();
		//printf(" \tTokenType: %d\n", (DWORD)*pTokenTypeInfo);
		switch ((DWORD)*pTokenTypeInfo) {
		case 1:
			printf(" \tTokenType\t: Primary Token\n");
			break;
		case 2:
			printf(" \tTokenType\t: Impersonation Token\n");
			break;
		default:
			printf(" \tTokenType\t: Error: %d\n", error);
			return FALSE;
		}
		return TRUE;
	}
	else {
		error = GetLastError();
		printf(" \t��ȡtoken�е���������ʧ�ܣ� Error: %d\n", error);
		return FALSE;

	}
}

int GetTokenPrivilege(HANDLE tok)
{
	GetTokenInfo(tok);
	DWORD error;
	char tmpStr[BUF_SIZE] = { 0 };
	GetDomainUsernameFromToken(tok, tmpStr);
	printf(" \tTokenUser\t: %s\n", tmpStr);
	
	PTOKEN_PRIVILEGES ppriv = NULL;
	DWORD dwRet = 0;
	GetTokenInformation(tok, TokenPrivileges, NULL, NULL, &dwRet);
	if (!dwRet)
		return 0;
	ppriv = (PTOKEN_PRIVILEGES)calloc(dwRet, 1);
	if (!GetTokenInformation(tok, TokenPrivileges, ppriv, dwRet, &dwRet)) {
		cout << " \t��ȡtoken��Ϣʧ�ܣ�Error: " << GetLastError() << endl;
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

	DWORD idx;
	GetTokenILFromToken(tok,&idx);
	printf("\tImpersonationLevel: %s\n",ILStr[idx]);
	GetTokenTypeFromToken(tok);

	return 1;
}


BOOL EnablePriv(HANDLE hToken, LPCTSTR priv)
{

	TOKEN_PRIVILEGES tp;
	LUID luid;
	// ������ȡpriv��Ӧ��luid
	if (!LookupPrivilegeValue(NULL, priv, &luid))
	{
		printf("[!]LookupPrivilegeValue error\n");
		return 0;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	// ���������е�DebugȨ��
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		printf("[!]AdjustTokenPrivileges error\n");
		return 0;
	}
	if (1300 == GetLastError()) {
		printf("JC| 2 |GetLastError: %d,û�гɹ�����Ȩ��\n", GetLastError());
	}
	return TRUE;
}
BOOL EnumThreads() {
	THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (INVALID_HANDLE_VALUE == hThreadSnap) {
		cout << "error" << endl;
		return FALSE;
	}

	if (Thread32First(hThreadSnap, &te32)) {
		do {
			HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
			HANDLE htoken;
			if (OpenThreadToken(hThread, TOKEN_QUERY, FALSE, &htoken)) {
				cout << "ThreadId : " << te32.th32ThreadID << endl;
				//printf("SUC\n");
				cout << '\t' << "OwnerProcessID: " << te32.th32OwnerProcessID << endl;
				HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, te32.th32OwnerProcessID);
				TCHAR Buffer[MAX_PATH];
				if (GetModuleFileNameEx(hProc, NULL, Buffer, MAX_PATH))
				{
					printf("\tProcessName    : %S\n", Buffer);
				}
				else
				{
					cout << "\t" << "ProcessName   : error" << GetLastError() << endl;
				}
				GetTokenPrivilege(htoken);
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
			cout << "\t��ȡ���̾��ʧ��,ERROR: " << GetLastError() << endl;
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

/*
Desp: ����pid������ѯ������Ϣ
Params: int pid
Return: 
*/
void GetInfoFromPid(int pid) {
	// ����pid��ȡ���̾��
	HANDLE hProc = OpenProcess(MAXIMUM_ALLOWED, TRUE, pid);
	if (hProc == NULL) {
		hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
		if (hProc == NULL) {
			cout << "\t��ȡ���̾��ʧ��,ERROR: " << GetLastError() << endl;
		}
	}
	TCHAR* tProcName;
	if(GetProcessNameFromPid(pid, &tProcName)){
		printf("\tProcessName: %S\n", tProcName);
	}
	HANDLE hToken;
	if (!OpenProcessToken(hProc, MAXIMUM_ALLOWED, &hToken)) {
		printf(" \t%d : ��ȡ����tokenʧ��: %d\n", pid, GetLastError());
	}
	else {
		GetTokenPrivilege(hToken);
	}
	CloseHandle(hToken);
	CloseHandle(hProc);

	// ö�ٽ����µ������߳�
	DWORD* pThreadList;
	DWORD dwThreadListLength;
	//cout << "pThreadList addr: " << pThreadList << endl;
	cout << "ö��[" << pid << "]���������е��߳�:" << endl;
	if (!(dwThreadListLength=GetThreadListFromPid(pid, &pThreadList))) {
		printf("ERROR: %d\n", GetLastError());
	}
	for (int i = 0; i < dwThreadListLength; i++) {
		DWORD tid = pThreadList[i];
		GetInfoFromTid(tid);
	}
}


/*
Desp: ����pid������ѯ������Ϣ������΢��δ��������Ntxxxʵ�֣�
Params: int pid
Return:
*/
void GetInfoFromPidB(int pid) {
	HANDLE hProc;
	// ����pid��ȡ���̾��
	hProc = OpenProcess(MAXIMUM_ALLOWED, TRUE, pid);
	// ��ȡNtOpenProcess�ĺ���ָ��
	NTOPENPROCESS NtOpenProcess = (NTOPENPROCESS)GetProcAddress(GetModuleHandle(_T("NTDLL.DLL")), "NtOpenProcess");
	NTQUERYINFORMATIONPROCESS NtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS)GetProcAddress(GetModuleHandle(_T("NTDLL.DLL")), "NtQueryInformationProcess");
	CLIENT_ID clientId;
	clientId.UniqueProcess = UlongToHandle(pid);
	clientId.UniqueThread = 0;

	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, NULL, NULL, NULL, NULL, NULL);
	// ��ȡ���̾��
	NTSTATUS status = NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &objectAttributes,&clientId);
	if (!NT_SUCCESS(status)) {
		hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
		if (hProc == NULL) {
			cout << "\t��ȡ���̾��ʧ��,ERROR: " << GetLastError() << endl;
			return;
		}
	}
	// ��ȡ������Ϣ
	PROCESS_BASIC_INFORMATIONA pbi;
	ULONG ulRet = 0;
	status=NtQueryInformationProcess(hProc, ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATIONA), &ulRet);

	if (!NT_SUCCESS(status)) {
		printf("\t��ȡ������Ϣʧ�ܣ�ERROR: %d\n", GetLastError());
		return ;
	}
	printf("\tUniqueProcessId: %d\n",pbi.UniqueProcessId);
	// ����pid��ȡ������
	TCHAR* tProcName;
	if (GetProcessNameFromPid(pid, &tProcName)) {
		printf("\tProcessName: %S\n", tProcName);
	}
	// ��ȡ�����еķ�������
	HANDLE hToken;
	if (!OpenProcessToken(hProc, MAXIMUM_ALLOWED, &hToken)) {
		printf(" \t%d : ��ȡ����tokenʧ��: %d\n", pid, GetLastError());
	}
	else {
		GetTokenInfo(hToken);
	}
	CloseHandle(hToken);
	CloseHandle(hProc);

	// ö�ٽ����µ������߳�
	DWORD* pThreadList;
	DWORD dwThreadListLength;
	//cout << "pThreadList addr: " << pThreadList << endl;
	cout << "ö��[" << pid << "]���������е��߳�:" << endl;
	if (!(dwThreadListLength = GetThreadListFromPid(pid, &pThreadList))) {
		printf("ERROR: %d\n", GetLastError());
	}
	cout << "\tThreadCount: " << dwThreadListLength << endl;
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
DWORD GetPIDFromTID(DWORD tid) {
	DWORD error;
//	cout << "ThreadId : " << tid << endl;
	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, TRUE, tid);

	if (NULL == hThread) {
		hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, TRUE, tid);
		if (hThread == NULL) {
			error = ::GetLastError();
			cout << "\t��ȡ�߳̾��ʧ�ܣ�ERROR:" << error << "\n" << endl;
			return -1;
		}
	}
	// ��ȡ�̵߳������Ϣ
	THREAD_BASIC_INFORMATION ThreadBasicInfoBuffer;
	NTQUERYINFORMATIONTHREAD NtQueryInformationThread = (NTQUERYINFORMATIONTHREAD)GetProcAddress(GetModuleHandle(_T("NTDLL.DLL")), "NtQueryInformationThread");
	NTSTATUS status = NtQueryInformationThread(hThread,ThreadBasicInformation,&ThreadBasicInfoBuffer,sizeof(THREAD_BASIC_INFORMATION),NULL);
	//printf("\tstatus: %X\n", status);
	if (!NT_SUCCESS(status)) {
		return -1;
	}
	//printf("ThreadBasicInfoBuffer.UniqueProcessId     = %d\n", ThreadBasicInfoBuffer.ClientId.UniqueProcess);
	DWORD pid = (DWORD)ThreadBasicInfoBuffer.ClientId.UniqueProcess;
	return pid;
}
BOOL GetInfoFromTid(DWORD tid) {
	DWORD error;
	cout << "ThreadId : " << tid << endl;
	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, TRUE, tid);

	if (NULL == hThread) {
		hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, TRUE, tid);
		if (hThread == NULL) {
			error = ::GetLastError();
			cout << "\t��ȡ�߳̾��ʧ�ܣ�ERROR:" << error << "\n" << endl;
			return FALSE;
		}
	}
	HANDLE hToken;
	HANDLE hProc;
	
	//DWORD dwPid = getPIDFromTid(tid);
	DWORD dwPid = GetPIDFromTID(tid);

	if (dwPid == FALSE) {
		cout << "\t�����߳�TID��ȡ����PIDʧ��" << endl;
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
				cout << "\t��ȡ���̾��ʧ�ܣ�ERROR:" << error << endl;
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
	
	// ��ȡ�߳��е�ģ������
	NTOPENTHREADTOKEN NtOpenThreadToken = (NTOPENTHREADTOKEN)GetProcAddress(GetModuleHandle(_T("NTDLL.DLL")), "NtOpenThreadToken");
	NTSTATUS status = NtOpenThreadToken(hThread, TOKEN_QUERY, FALSE, &hToken);
	if (!NT_SUCCESS(status))
	{
		if (status == STATUS_NO_TOKEN) {
			printf("\tRetrieving token handle failed,ERROR: NTSTATUS: 0x%X ,STATUS_NO_TOKEN\n", status);
		}
		else {
			printf("\tRetrieving token handle failed,ERROR: NTSTATUS: 0x%X\n", status);
		}
		return status;
	}
	// ��ȡ�̵߳������Ϣ
	//THREAD_BASIC_INFORMATION ThreadBasicInfoBuffer;
	//NTQUERYINFORMATIONTHREAD NtQueryInformationThread = (NTQUERYINFORMATIONTHREAD)GetProcAddress(GetModuleHandle(_T("NTDLL.DLL")), "NtQueryInformationThread");
	//NTSTATUS status = NtQueryInformationThread(hThread,ThreadImpersonationToken,&hToken,0x04,NULL);
	//printf("\tstatus: %X\n", status);
//	printf("ThreadBasicInfoBuffer.UniqueProcessId     = %d\n", ThreadBasicInfoBuffer.ClientId.UniqueThread);
	GetTokenInfo(hToken);
	//if (OpenThreadToken(hThread, TOKEN_QUERY, FALSE, &hToken)) {
	//	
	//	//GetTokenPrivilege(hToken);
	//	GetTokenInfo(hToken);
	//}
	//else {
	//	OpenThreadToken(hThread, TOKEN_QUERY, FALSE, &hToken);
	//	//printf("Fail: %d\n",GetLastError());
	//	DWORD error = ::GetLastError();
	//	if (1008 == error) {
	//		cout << "\t���̲߳�����ģ������,ERROR: " << error << endl;
	//	}
	//	else {
	//		cout << "other Error, ERROR:" << error << endl;
	//	}
	//}
	CloseHandle(hThread);
	CloseHandle(hProc);
	CloseHandle(hToken);
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

	//if (AdjustTokenPrivileges(hToken, FALSE, &privileges, 0, NULL, NULL) == 0)
	if (AdjustTokenPrivileges(hToken, FALSE, &privileges, sizeof(privileges), NULL, NULL) == 0)
	{
		dwError = GetLastError();
		goto exit;
	}

exit:
	if (token == NULL && hToken)
		CloseHandle(hToken);

	return dwError == ERROR_SUCCESS;
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


LPWSTR GetObjectInfo(HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass)
{
	LPWSTR data = NULL;
	DWORD dwSize = sizeof(OBJECT_NAME_INFORMATION);
	POBJECT_NAME_INFORMATION pObjectInfo = (POBJECT_NAME_INFORMATION)malloc(dwSize);
	NTQUERYOBJECT NtQueryObject = (NTQUERYOBJECT)GetProcAddress(GetModuleHandle(_T("NTDLL.DLL")), "NtQueryObject");

	NTSTATUS ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
	if ((ntReturn == STATUS_BUFFER_OVERFLOW) || (ntReturn == STATUS_INFO_LENGTH_MISMATCH)) {
		pObjectInfo = (POBJECT_NAME_INFORMATION)realloc(pObjectInfo, dwSize);
		ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
	}
	if ((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->Buffer != NULL))
	{
		data = (LPWSTR)calloc(pObjectInfo->Length, sizeof(WCHAR));
		CopyMemory(data, pObjectInfo->Buffer, pObjectInfo->Length);
	}
	free(pObjectInfo);
	return data;
}


// �жϴ�������token�ܷ�ģ��
BOOL IsImpersonationToken(HANDLE token)
{
	HANDLE temp_token;
	LPVOID TokenImpersonationInfo[BUF_SIZE];
	// ��ȡ����ģ��ȼ���Ϣ������ȡ�������ж�ģ��ȼ��ǲ��Ǵ��ڵ���ģ��
	DWORD dwTokenIL;
	if (GetTokenILFromToken(token, &dwTokenIL)) {
		if (dwTokenIL >= SecurityImpersonation)
			return TRUE;
		else
			return FALSE;
	}
	// ��δ��ȡ�����Ƶȼ���Ϣ�������Ƿ��ܹ�ʹ�ø����ƴ���һ������ģ��ȼ���ģ�����ơ����ݴ����Ľ���ж��ܹ�ģ�������
	BOOL ret = DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &temp_token);
	CloseHandle(temp_token);
	return ret;
}

BOOL EnumProcessB() {
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION_EX pshi=(PSYSTEM_HANDLE_INFORMATION_EX)malloc(sizeof(SYSTEM_HANDLE_INFORMATION_EX));
	NTQUERYSYSTEMINFORMATION NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(_T("NTDLL.DLL")), "NtQuerySystemInformation");
	char tmpStr[BUF_SIZE] = { 0 };
	DWORD dwRet=0;
	PTOKEN_GROUPS_AND_PRIVILEGES pTokenGroupsAndPrivileges = NULL;
	HANDLE hObject=NULL;
	HANDLE hObject2 = NULL;
	HANDLE hProc = NULL;


	if (pshi) {
		status = NtQuerySystemInformation(SystemHandleInformation, pshi, sizeof(SYSTEM_HANDLE_INFORMATION_EX), NULL);
		for (ULONG r = 0; r < pshi->NumberOfHandles; r++)
		{
			// Token���͵�ֵ��5
			if (pshi->Information[r].ObjectTypeNumber == 5)
			{
				// ���������ڵĽ���ID
				printf("ProcessId: %d\n", pshi->Information[r].ProcessId);
				// ����������
				printf("\tHandleType\t: Token\n");
				printf("\tHandleOffset\t: 0x%x\n", pshi->Information[r].Handle);
				// �����Ӧ���ں˶���
				printf("\t�ں˶���\t\t: 0x%p\n", pshi->Information[r].Object);
				// �򿪽��̾��
				hProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, (DWORD)pshi->Information[r].ProcessId);
				if (hProc == NULL) {
					hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pshi->Information[r].ProcessId);
					if (hProc == NULL) {
						printf("\t��ȡ���̾��ʧ�ܣ�Error: %d\n", GetLastError());
						// �¸����
						goto loopCon;
					}
				}
				// ��ȡpid��Ӧ�Ľ�����
				TCHAR* tProcName;
				if (GetProcessNameFromPid((DWORD)pshi->Information[r].ProcessId, &tProcName)) {
					printf("\tProcessName\t: %S\n", tProcName);
				}
				// ����token�������ǰ���̵ľ������
				if (DuplicateHandle(hProc, (HANDLE)(pshi->Information[r].Handle),GetCurrentProcess(), &hObject, MAXIMUM_ALLOWED, FALSE, 0x02) != FALSE)
				{
					// ��token�л�ȡ��¼�ỰID
					dwRet = 0;
					PTOKEN_GROUPS_AND_PRIVILEGES pTokenGroupsAndPrivileges = NULL;
					GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet);
					if (dwRet == 0) {
						printf("\tdwreterror,ERROR: %d\n", GetLastError());
						//getchar();
					}
					else {
						pTokenGroupsAndPrivileges = (PTOKEN_GROUPS_AND_PRIVILEGES)calloc(dwRet, 1);
						if (!GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet)) {
							printf("\t��ȡ������Ϣʧ�ܣ�ERROR: %d\n", GetLastError());
						}
						else {
							printf("\tLogonId\t\t: %08x-%08x\n", pTokenGroupsAndPrivileges->AuthenticationId.HighPart, pTokenGroupsAndPrivileges->AuthenticationId.LowPart);
						}
					}
					// ��token�л�ȡ�û���
					GetDomainUsernameFromToken(hObject, tmpStr);
					printf(" \tTokenUser\t: %s\n", tmpStr);
					// ��token�л�ȡ��������
					GetTokenTypeFromToken(hObject);
					// ʹ�ñ����̵��߳���ģ������
					if (ImpersonateLoggedOnUser(hObject) == 0) {
						printf("\t���߳�ģ������ʧ��,ERROR: %d\n", GetLastError());
						printf("\t\t�����Ʋ��ܹ���ģ��\n");
						goto loopCon;
					}
					else {
						printf("\t���߳�ģ�����Ƴɹ���\n");
						// �򿪲���ȡ����
						OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, TRUE, &hObject2);
						// ���ص��Լ��İ�ȫ������
						RevertToSelf();
						// �жϻ�ȡ���������ǲ���ģ������
						if (IsImpersonationToken(hObject)) {
							printf("\t\t�������ܹ���ģ��\n");
							//getchar();
						}
						else {
							printf("\t\t�����Ʋ��ܹ���ģ��\n");
							//getchar();
						}
					}
				//}
				}
				else {
					printf("\t����Token���ʧ��,ERROR: %d\n",GetLastError());
					goto loopCon;
				}
				loopCon:
					printf("\n");
					if (hObject2 != NULL) {
						CloseHandle(hObject2);
					}
					if (hObject != NULL) {
						CloseHandle(hObject);
					}
					if (hProc != NULL) {
						CloseHandle(hProc);
					}
			}
		}
		free(pshi);
	}
	return TRUE;
}
/*
DESP: ����NtQuerySystemInformation��ö�����еĽ���
PARAMS: none
RETURN: BOOL
*/
BOOL EnumProcessA() {
	NTSTATUS status;
	PSYSTEM_PROCESS_INFO pspi;
	ULONG ReturnLength=0;
	NTQUERYSYSTEMINFORMATION NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(_T("NTDLL.DLL")), "NtQuerySystemInformation");
	//status = NtQuerySystemInformation(SystemHandleInformation, NULL, NULL, &ReturnLength);
	status = NtQuerySystemInformation(SystemHandleInformation, NULL, NULL, &ReturnLength);

	if (!NT_SUCCESS(status)) {
		pspi = (PSYSTEM_PROCESS_INFO)malloc(ReturnLength);
		//pspi = (PSYSTEM_PROCESS_INFO)VirtualAlloc(NULL, ReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!NT_SUCCESS(status = NtQuerySystemInformation(SystemHandleInformation, pspi, ReturnLength, NULL))) {
			return FALSE;
		}
		//=======ö�پ������
		DWORD dwCount;
		//=======
		wprintf(L"ProcName\tProcId\n");
		HANDLE hObject;
		HANDLE hObject2 = NULL;
		TCHAR* tmpProcName = NULL;
		while (pspi->NextEntryOffset) {
			wprintf(L"%ws\t%d\n", pspi->ImageName.Buffer, pspi->ProcessId);
			wprintf(L"\tHandleCount: %d\n", pspi->NumberOfHandle);
			if (pspi->ProcessId != 0) {
				tmpProcName = (TCHAR*)calloc(pspi->ImageName.Length, 1);
				wcscat(tmpProcName, pspi->ImageName.Buffer);
			}
			// �򿪽��̾��
			HANDLE hProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, (DWORD)pspi->ProcessId);
			//HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pspi->ProcessId);
			if (hProc == NULL) {
				printf("\tOpenProcessError: %d\n", GetLastError());
				hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pspi->ProcessId);
				if (hProc == NULL) {
					printf("\tOpenProcessError: %d\n", GetLastError());
					// �¸�����
					pspi = (PSYSTEM_PROCESS_INFO)((LPBYTE)pspi + pspi->NextEntryOffset);
					continue;
				}
			}
			// �鿴�����еľ������
			if (GetProcessHandleCount(hProc, &dwCount)) {
				printf("\tRealHandleCount: %d\n", dwCount);
			}

			//���������µ�ÿ�����
			for (int i = 0; i < pspi->NumberOfHandle; i++) {
				if (hProc != INVALID_HANDLE_VALUE) {
					hObject = NULL;

					if (DuplicateHandle(hProc, (HANDLE)((i + 1) * 4),
						GetCurrentProcess(), &hObject, MAXIMUM_ALLOWED, FALSE, 0x02) != FALSE) {
						LPWSTR lpwsType = NULL;
						lpwsType = GetObjectInfo(hObject, ObjectTypeInformation);
						printf("\t\ttype: %S\n", lpwsType);
						//wprintf(L"\t%s\n", lpwsType);
						//wprintf(L"lpwstype: %ws\n", lpwsType);
						//if ((lpwsType != NULL) && !wcscmp(lpwsType, L"Token") && ImpersonateLoggedOnUser(hObject) != 0)
						if ((lpwsType != NULL) && !wcscmp(lpwsType, L"Token"))
						{
							printf("\t�þ����token:\n");
							if (ImpersonateLoggedOnUser(hObject) != 0) {
								printf("\tGG\n");
							}
							// �򿪲���ȡ����
							OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, TRUE, &hObject2);
							// ���ص��Լ��İ�ȫ������
							RevertToSelf();
							// �жϻ�ȡ���������ǲ���ģ������
							//if (IsImpersonationToken(hObject2)) {
								DWORD dwRet = 0;
								PTOKEN_GROUPS_AND_PRIVILEGES pTokenGroupsAndPrivileges = NULL;
								GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet);
								if (dwRet == 0) {
									return FALSE;
								}
								//cout << "dwRet: " << dwRet << endl;
								pTokenGroupsAndPrivileges = (PTOKEN_GROUPS_AND_PRIVILEGES)calloc(dwRet, 1);
								if (!GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet)) {
									printf("ERROR: %d\n", GetLastError());
									return FALSE;
								}
								printf("\t1AuthId: %08x-%08x\n", pTokenGroupsAndPrivileges->AuthenticationId.HighPart, pTokenGroupsAndPrivileges->AuthenticationId.LowPart);
								//getchar();
							//}
							CloseHandle(hObject2);
							CloseHandle(hObject);
						}
					}
				}
			}

			hProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, (DWORD)pspi->ProcessId);
			DWORD dwError = OpenProcessToken(hProc, MAXIMUM_ALLOWED, &hObject);
			//if (dwError != 0 && ImpersonateLoggedOnUser(hObject) != 0)
			if (dwError != 0)
			{
					printf("\t�򿪽��̣���ȡ����������:\n");
			//	OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, TRUE, &hObject2);
			//	RevertToSelf();
			//	if (IsImpersonationToken(hObject2)) {
					DWORD dwRet = 0;
					PTOKEN_GROUPS_AND_PRIVILEGES pTokenGroupsAndPrivileges = NULL;
					GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet);
					if (dwRet == 0) {
						return FALSE;
					}
					//cout << "dwRet: " << dwRet << endl;
					pTokenGroupsAndPrivileges = (PTOKEN_GROUPS_AND_PRIVILEGES)calloc(dwRet, 1);
					if (!GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet)) {
						printf("ERROR: %d\n", GetLastError());
						return FALSE;
					}
					printf("\tAuthId: %08x-%08x\n", pTokenGroupsAndPrivileges->AuthenticationId.HighPart, pTokenGroupsAndPrivileges->AuthenticationId.LowPart);
					//getchar();
				//}
				CloseHandle(hObject2);
				CloseHandle(hObject);
			}
			//if (pspi->ProcessId != 0) {
			//	if (!wcscmp(pspi->ImageName.Buffer, L"lsass.exe")) {
			//		printf("pause\n");
			//		getchar();
			//	}
			//}
			// �¸�����
			pspi = (PSYSTEM_PROCESS_INFO)((LPBYTE)pspi + pspi->NextEntryOffset);
		}
	}
	return TRUE;
}
/*
desp: ����ö�ٵ�ǰϵͳ�����н��̼����̵߳������ƻ�ģ������
params: none
*/
void EnumProcess() {
	//����һ�����̿���
	HANDLE snapHandele = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (INVALID_HANDLE_VALUE == snapHandele)
	{
		cout << "CreateToolhelp32Snapshot error" <<endl;
		return;
	}
	PROCESSENTRY32 entry = { 0 };
	entry.dwSize = sizeof(entry);// ���ȱ��븳ֵ
	// ��һ������
	BOOL ret = Process32First(snapHandele, &entry);
	int i = 0;
	printf("���\tPID\tPPID\tProg\n");
	while (ret) {
		HANDLE hProc;
		WCHAR *exeFile = entry.szExeFile;
		printf("%d\t%d\t%d\t%S\n",i, entry.th32ProcessID,entry.th32ParentProcessID, exeFile );
		// ����System��PIDΪ0�Ľ���
		if (0 == entry.th32ProcessID || !wcscmp(TEXT("System"),exeFile) ){
			goto loop;
		}
		TCHAR* tProcName;
		if (GetProcessNameFromPid(entry.th32ProcessID, &tProcName)) {
			printf("\tProcessName: %S\n", tProcName);
		}
		// ����pid��ȡ���̾��
		// �������һЩ���̻ᱨ��,����ʾAccess Dined
		 hProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, entry.th32ProcessID);
		//cout << "364 ERROR: " << GetLastError() << endl;
		if (hProc == NULL) {
			hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, entry.th32ProcessID);
			if (hProc == NULL) {
				cout << "\t��ȡ���̾��ʧ��,ERROR: " << GetLastError() << endl;
				//getchar();
				goto loop;
			}

		}
		HANDLE hToken;
		if (!OpenProcessToken(hProc, MAXIMUM_ALLOWED, &hToken)) {
			printf(" \t��ȡ����tokenʧ��: %d\n\n", GetLastError());
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



void printUsage() {
	string rawUsageMsg = R"(
Usage: test.exe [OPTION]

[OPTION]
-p <pid|ALL>: �г����н����е����ƻ��г�ĳ�������е�����
-t <tid|ALL>: �г������߳��е�ģ�����ƻ�ĳ���߳��е�ģ������
-l : �г���ǰ���еĵ�¼�Ự
-c : �г���ǰ����Ϣ
-P : �Ƿ���ʾ�����е�privileges��Ϣ
-u <username>: ��ĳ���û�ִ�������-e <command>���ʹ��
-e <command> : ִ������
-v : ��ϸģʽ)";
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
BOOL ExecuteCmd(TCHAR* username,TCHAR* cmd) {

	system("whoami");
	// �������е�token
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION_EX pshi = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(sizeof(SYSTEM_HANDLE_INFORMATION_EX));
	NTQUERYSYSTEMINFORMATION NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(_T("NTDLL.DLL")), "NtQuerySystemInformation");
	char tmpStr[BUF_SIZE] = { 0 };
	DWORD dwRet = 0;
	PTOKEN_GROUPS_AND_PRIVILEGES pTokenGroupsAndPrivileges = NULL;
	HANDLE hObject = NULL;
	HANDLE hObject2 = NULL;
	HANDLE hProc = NULL;


	if (pshi) {
		status = NtQuerySystemInformation(SystemHandleInformation, pshi, sizeof(SYSTEM_HANDLE_INFORMATION_EX), NULL);
		for (ULONG r = 0; r < pshi->NumberOfHandles; r++)
		{
			// Token���͵�ֵ��5
			if (pshi->Information[r].ObjectTypeNumber == 5)
			{
				// ���������ڵĽ���ID
				//printf("ProcessId: %d\n", pshi->Information[r].ProcessId);
				// ����������
				//printf("\tHandleType\t: Token\n");
				//printf("\tHandleOffset\t: 0x%x\n", pshi->Information[r].Handle);
				// �����Ӧ���ں˶���
				//printf("\t�ں˶���\t\t: 0x%p\n", pshi->Information[r].Object);
				// �򿪽��̾��
				hProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, (DWORD)pshi->Information[r].ProcessId);
				if (hProc == NULL) {
					hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pshi->Information[r].ProcessId);
					if (hProc == NULL) {
						printf("\t��ȡ���̾��ʧ�ܣ�Error: %d\n", GetLastError());
						// �¸����
						goto loopCon;
					}
				}
				// ��ȡpid��Ӧ�Ľ�����
				TCHAR* tProcName;
				//if (GetProcessNameFromPid((DWORD)pshi->Information[r].ProcessId, &tProcName)) {
					//printf("\tProcessName\t: %S\n", tProcName);
				//}
				// ����token�������ǰ���̵ľ������
				if (DuplicateHandle(hProc, (HANDLE)(pshi->Information[r].Handle), GetCurrentProcess(), &hObject, MAXIMUM_ALLOWED, FALSE, 0x02) != FALSE)
				{
					// ��token�л�ȡ��¼�ỰID
					dwRet = 0;
					PTOKEN_GROUPS_AND_PRIVILEGES pTokenGroupsAndPrivileges = NULL;
					GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet);
					if (dwRet == 0) {
						printf("\tdwreterror,ERROR: %d\n", GetLastError());
						//getchar();
					}
					else {
						pTokenGroupsAndPrivileges = (PTOKEN_GROUPS_AND_PRIVILEGES)calloc(dwRet, 1);
						if (!GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet)) {
							//printf("\t��ȡ������Ϣʧ�ܣ�ERROR: %d\n", GetLastError());
						}
						else {
							//printf("\tLogonId\t\t: %08x-%08x\n", pTokenGroupsAndPrivileges->AuthenticationId.HighPart, pTokenGroupsAndPrivileges->AuthenticationId.LowPart);
						}
					}
					// ��token�л�ȡ�û���
					GetDomainUsernameFromToken(hObject, tmpStr);
					if (wcscmp(CharToTCHAR(tmpStr), username)) {
						printf(" \tTokenUser\t: %s\n", tmpStr);
						//system("cmd");
						//return TRUE;
					}
					// ��token�л�ȡ��������
					GetTokenTypeFromToken(hObject);
					// ʹ�ñ����̵��߳���ģ������
					if (ImpersonateLoggedOnUser(hObject) == 0) {
						printf("\t���߳�ģ������ʧ��,ERROR: %d\n", GetLastError());
						printf("\t\t�����Ʋ��ܹ���ģ��\n");
						goto loopCon;
					}
					else {
						printf("\t���߳�ģ�����Ƴɹ���\n");
						if (wcscmp(CharToTCHAR(tmpStr), username)) {
							printf(" \tTokenUser\t: %s\n", tmpStr);
							//system("cmd");
							STARTUPINFO startupInfo = { 0 };
							PROCESS_INFORMATION  processInformation = { 0 };
							/*��WordӦ�ó��� C:\\Program Files (x86)\\Microsoft Office\\Office14\\WINWORD.EXE Ϊ����·��*/
							BOOL bSuccess = CreateProcess(TEXT("C:\\Windows\\SysWOW64\\whoami.exe"),NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &startupInfo, &processInformation);

							if (bSuccess)
							{
								cout << "Process started..." << endl
									<< "ProcessID: "
									<< processInformation.dwProcessId << endl;
							}
							else
							{
								cout << "Can not start process!" << endl
									<< "Error code: " << GetLastError();
							}
							return TRUE;
						}
						// �򿪲���ȡ����
						OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, TRUE, &hObject2);
						// ���ص��Լ��İ�ȫ������
						RevertToSelf();
						// �жϻ�ȡ���������ǲ���ģ������
						if (IsImpersonationToken(hObject)) {
							printf("\t\t�������ܹ���ģ��\n");
							//getchar();
						}
						else {
							printf("\t\t�����Ʋ��ܹ���ģ��\n");
							//getchar();
						}
					}
					//}
				}
				else {
					//printf("\t����Token���ʧ��,ERROR: %d\n", GetLastError());
					goto loopCon;
				}
			loopCon:
				//printf("\n");
				if (hObject2 != NULL) {
					CloseHandle(hObject2);
				}
				if (hObject != NULL) {
					CloseHandle(hObject);
				}
				if (hProc != NULL) {
					CloseHandle(hProc);
				}
			}
		}
		free(pshi);
	}
	// ģ��token

	return TRUE;
}
int _tmain(int argc, _TCHAR* argv[])
{
	DWORD tmpRes = TryEnableDebugPriv(NULL);
	printf("enableDebug: %d\n", tmpRes);
	TryEnableAssignPrimaryPriv(NULL);
	// �������л�ȡ����
	char opt;
	char* optStr= NULL;
	TCHAR tmpstrx[10] = _T("cmd");
	while ((opt = getopt(argc, argv, "p:t:lcvpu:e:")) != -1){
		
		switch (opt) {
		case 'u':
			optStr = TCHARToChar(optarg);
			cout << opt << " : " << optStr << endl;
			ExecuteCmd(optarg,tmpstrx);
			break;
		case 'p':
			optStr = TCHARToChar(optarg);
			cout << opt << " : " << optStr << endl;
			if ((_tcscmp(optarg, L"ALL")) == 0) {
				cout << "All Primary Token:" << endl;
				//EnumProcess();
				//EnumProcessA();
				EnumProcessB();

			}
			else {
				cout << "Primary Token In [" << optStr << "] Process" << endl;
				//GetInfoFromPid(atoi(optStr));
				GetInfoFromPidB(atoi(optStr));

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
				// �ж��ǲ���SYSTEM�û�
				//IsTokenSystem(hToken);
				cout << "��ǰ���̵�������Ϣ���£�" << endl;
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