#include "Execute.h"




/*使用传进来的username执行命令*/
BOOL Execute::ExecuteMain(TCHAR* tUserName, DWORD dwPid,TCHAR* tCommandArg,BOOL bConsoleMode) {

	HANDLE hToken = NULL;
	TokenList* pTokenList = (TokenList*)calloc(1,sizeof(TokenList));
	pTokenList->pTokenListNode = (PTokenListNode)calloc(Token_List_Node_Count, sizeof(TokenListNode));
	pTokenList->dwLength = 0;
	TokenInforUtil::GetTokens(pTokenList);
	//if (!TokenInforUtil::GetTokenByUsername(*pTokenList, tUserName, &hToken)) {
	if(!TokenInforUtil::GetTokenByUserProc(*pTokenList,tUserName,dwPid,&hToken)){
		printf("获取%S用户的令牌失败\n", tUserName);
		// 释放令牌List
		if (pTokenList) {
			TokenInforUtil::ReleaseTokenList(pTokenList);
		}
		return FALSE;
	}
	// 210507: 枚举获取到的所有令牌，找到具有SeAssignPrimaryTokenPrivilege权限的令牌，因为CreateProcessAsUser()函数需要这个权限，不然之后会报错：1314
	//[-] Failed to create new process: 1314
	for (DWORD i = 0; i < pTokenList->dwLength; i++) {
		if (TokenInforUtil::TrySwitchTokenPriv(pTokenList->pTokenListNode[i].hToken,SE_ASSIGNPRIMARYTOKEN_NAME,TRUE,NULL) && TokenInforUtil::HasAssignPriv(pTokenList->pTokenListNode[i].hToken)) {
			ImpersonateLoggedOnUser(pTokenList->pTokenListNode[i].hToken);
			break;
		}
	}
	ExecuteWithToken(hToken, tCommandArg, bConsoleMode);
	if(hToken != NULL)
		CloseHandle(hToken);
	// 释放令牌List
	if (pTokenList) {
		TokenInforUtil::ReleaseTokenList(pTokenList);
	}
	return TRUE;
}


/*使用传进来的token执行命令*/
BOOL Execute::ExecuteWithToken(HANDLE hToken, TCHAR* tCommand, BOOL bConsoleMode) {
	if (!hToken) {
		return FALSE;
	}
	create_process(hToken, tCommand, bConsoleMode, SecurityImpersonation);
	return TRUE;
}


void Execute::create_process(HANDLE token, TCHAR* command, BOOL console_mode, SECURITY_IMPERSONATION_LEVEL impersonation_level)
{
	BOOL grepable_mode = FALSE;

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	TCHAR window_station[100];
	DWORD length_needed, sessionid = 1, returned_length;
	HANDLE new_token, primary_token, current_process, current_process_token;
	new_token = NULL;
	primary_token = NULL;
	// Create primary token
	if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, impersonation_level, TokenPrimary, &primary_token))
	{
		printf("[+] DuplicateTokenEx Fail,Error: %d\n",GetLastError());
		// 尝试获取线程中的模拟令牌
		if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &new_token)) {
			printf("\t[1] OpenThreadToken Fail,Error: %d\n", GetLastError());
			// 尝试获取主进程中的主令牌
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &new_token)) {
				printf("ERROR: %d\n", GetLastError());
				return;
			}
		}

		// Duplicate to make primary token 
		if (!DuplicateTokenEx(new_token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &primary_token))
		{
			printf("[-] Failed to duplicate token to primary token: %d\n", GetLastError());
			return;
		}
	}
	
	// Associate process with parent process session. This makes non-console connections pop up with GUI hopefully
	// 获取当前进程的句柄
	current_process = OpenProcess(MAXIMUM_ALLOWED, FALSE, GetCurrentProcessId());
	// 获取当前进程的主令牌
	OpenProcessToken(current_process, MAXIMUM_ALLOWED, &current_process_token);
	// 获取当前进程主令牌中的sessionid
	GetTokenInformation(current_process_token, TokenSessionId, &sessionid, sizeof(sessionid), &returned_length);
	// 设置传进来的令牌中的sessionid为刚刚获取的
	SetTokenInformation(primary_token, TokenSessionId, &sessionid, sizeof(sessionid));

	// Create window station if necessary for invisible process
	GetUserObjectInformation(
		GetProcessWindowStation(),
		UOI_NAME,
		(PVOID)window_station,
		100,
		&length_needed
	);

	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);

	if (!_tcscmp(window_station, _T("WinSta0")))
		si.lpDesktop = (LPWSTR)_T("WinSta0\\default");
	else
		si.lpDesktop = window_station;

	if (console_mode)
	{
		printf("[*] Attempting to create new child process and communicate via anonymous pipe\n\n");
		CreateProcessWithPipeComm(primary_token, command);
		if (!grepable_mode)
			printf("\n");
		printf("[*] Returning from exited process\n");
		return;
	}
	else
	{
		// 对于非控制台模式
		if (CreateProcessAsUser(
			primary_token,            // client's access token
			NULL,              // file to execute
			command,     // command line
			NULL,              // pointer to process SECURITY_ATTRIBUTES
			NULL,              // pointer to thread SECURITY_ATTRIBUTES
			FALSE,             // handles are not inheritable
			CREATE_NEW_CONSOLE,   // creation flags
			NULL,              // pointer to new environment block
			NULL,              // name of current directory
			&si,               // pointer to STARTUPINFO structure
			&pi                // receives information about new process
		))
			printf("[+] Created new process with token successfully\n");
		else
			printf("[-] Failed to create new process: %d\n", GetLastError());
	}
	if (primary_token != NULL) {
		CloseHandle(primary_token);
	}
	if (new_token != NULL) {
		CloseHandle(new_token);
	}
}



void Execute::CreateProcessWithPipeComm(HANDLE token, TCHAR* command)
{
	PROCESS_INFORMATION piProcInfo;
	SECURITY_ATTRIBUTES saAttr;
	DWORD dwThreadId[2];
	HANDLE hThread[2];

	// Set the bInheritHandle flag so pipe handles are inherited.
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// Get the handle to the current STDOUT.
	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

	// Create a pipe for the child process's STDOUT.
	if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0))
	{
		printf("[-] Stdout pipe creation failed\n");
		return;
	}

	// Ensure the read handle to the pipe for STDOUT is not inherited.
	SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);

	// Create a pipe for the child process's STDIN.
	if (!CreatePipe(&hChildStdinRd, &hChildStdinWr, &saAttr, 0))
	{
		printf("[-] Stdin pipe creation failed\n");
		return;
	}

	// Ensure the write handle to the pipe for STDIN is not inherited.
	SetHandleInformation(hChildStdinWr, HANDLE_FLAG_INHERIT, 0);

	// Now create the child process.
	CreateChildProcess(token, command, &piProcInfo);

	hThread[0] = CreateThread(
		NULL,              // default security attributes
		0,                 // use default stack size
		ReadFromPipe,        // thread function
		NULL,             // argument to thread function
		0,                 // use default creation flags
		&dwThreadId[0]);   // returns the thread identifier

	hThread[1] = CreateThread(
		NULL,              // default security attributes
		0,                 // use default stack size
		WriteToPipe,        // thread function
		NULL,             // argument to thread function
		0,                 // use default creation flags
		&dwThreadId[1]);   // returns the thread identifier

	WaitForSingleObject(piProcInfo.hProcess, INFINITE);
}


void Execute::CreateChildProcess(HANDLE token, TCHAR* command, PROCESS_INFORMATION* piProcInfo)
{
	STARTUPINFO siStartInfo;
	BOOL bFuncRetn = FALSE;
	HWINSTA new_winstation, old_winstation;

	// Set up members of the PROCESS_INFORMATION structure.
	ZeroMemory(piProcInfo, sizeof(PROCESS_INFORMATION));

	// Set up members of the STARTUPINFO structure.
	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = hChildStdoutWr;
	siStartInfo.hStdOutput = hChildStdoutWr;
	siStartInfo.hStdInput = hChildStdinRd;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
	siStartInfo.lpDesktop = (LPWSTR)_T("incognito\\default");

	// Create new window station and save handle to existing one
	old_winstation = GetProcessWindowStation();
	new_winstation = CreateWindowStation(
		_T("incognito"),
		(DWORD)NULL,
		MAXIMUM_ALLOWED,
		NULL
	);

	// Set process to new window station and create new desktop object within it
	SetProcessWindowStation(new_winstation);
	CreateDesktop(
		_T("default"),
		NULL,
		NULL,
		(DWORD)NULL,
		GENERIC_ALL,
		NULL
	);
	SetProcessWindowStation(old_winstation);

	// Create the child process.
	bFuncRetn = CreateProcessAsUser(
		token,
		NULL,
		command,     // command line
		NULL,          // process security attributes
		NULL,          // primary thread security attributes
		TRUE,          // handles are inherited
		0,             // creation flags
		NULL,          // use parent's environment
		NULL,          // use parent's current directory
		&siStartInfo,  // STARTUPINFO pointer
		piProcInfo);  // receives PROCESS_INFORMATION

	if (bFuncRetn == 0)
		printf("[-] Failed to create new process: %d\n", GetLastError());
}


DWORD WINAPI Execute::WriteToPipe(LPVOID p)
{
	DWORD dwRead, dwWritten;
	char chBuf[BUFSIZE];

	for (;;)
	{
		// 从stdin中获取输入内容
		if (!read_counted_input(chBuf, BUFSIZE, &dwRead))
			break;
		chBuf[dwRead - 1] = '\n';
		// 将获取到的输入内容通过匿名管道传输给子进程
		if (!WriteFile(hChildStdinWr, chBuf, dwRead,
			&dwWritten, NULL))
			break;
	}
	return 0;
}

DWORD WINAPI Execute::ReadFromPipe(LPVOID p)
{
	DWORD dwRead;
	char chBuf[BUFSIZE];

	for (;;)
	{
		// 通过匿名管道获取子进程的输出
		if (!ReadFile(hChildStdoutRd, chBuf, BUFSIZE, &dwRead,
			NULL) || dwRead == 0) break;
		// 将获取到的输出内容输出到stdout
		if (!output_counted_string(chBuf, dwRead))
			break;
	}
	return 0;
}


BOOL Execute::output_counted_string(char* string, DWORD dwRead)
{
	DWORD dwWritten;

	return fwrite(string, sizeof(char), dwRead, stdout);
}

BOOL Execute::read_counted_input(char* string, int string_size, DWORD* dwRead)
{
	char* ret_value;

	ret_value = gets_s(string,BUFSIZE);
	*dwRead = strlen(string) + 1;
	return (BOOL)ret_value;
}