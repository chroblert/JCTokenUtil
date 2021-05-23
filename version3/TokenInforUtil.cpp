#include "TokenInforUtil.h"
//#define DOMAIN_CHAR_COUNT 100
//#define USERNAME_CHAR_COUNT 50

//BOOL TokenInforUtil::GetDomainUsernameFromToken(HANDLE hToken, char* full_name_to_return) {
//	LPVOID TokenUserInfo[BUF_SIZE];
//	char username[USERNAME_CHAR_COUNT], domainname[DOMAIN_CHAR_COUNT];
//	DWORD user_length = sizeof(username), domain_length = sizeof(domainname), sid_type = 0, dwRet;
//	if (!GetTokenInformation(hToken, TokenUser, TokenUserInfo, BUF_SIZE, &dwRet))
//		return FALSE;
//	//执行完这一步报错，why？how？
//	LookupAccountSidA(NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username, &user_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type);
//
//	// Make full name in DOMAIN\USERNAME format
//	sprintf(full_name_to_return, "%s\\%s", domainname, username);
//	return TRUE;
//}


/*从token中获取域名\用户名*/
BOOL TokenInforUtil::GetDomainUsernameFromToken(HANDLE hToken, TCHAR* full_name_to_return) {
	DWORD dwRet = 0;
	SID_NAME_USE snu = SidTypeUnknown;

	TCHAR* AcctName = NULL;
	TCHAR* DomainName = NULL;
	TCHAR* tmpFullname = NULL;
	DWORD dwAcctName = 1, dwDomainName = 1;
	BOOL bRtnBool = FALSE;

	GetTokenInformation(hToken, TokenUser, NULL, dwRet, &dwRet);
	if (!dwRet) {
		printf("\tGetTokenInformation（）失败,ERROR: %d\n", GetLastError());
		return FALSE;
	}
	PTOKEN_USER pTokenUser = (PTOKEN_USER)calloc(dwRet,1);
	if (!pTokenUser) {
		goto FAIL;
	}
	if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwRet, &dwRet))
		goto FAIL;
	//printf("test,%d\n", pTokenUser->User.Sid);
	bRtnBool = LookupAccountSid(
		NULL,           // local computer
		pTokenUser->User.Sid,
		NULL,
		&dwAcctName,
		NULL,
		&dwDomainName,
		&snu);

	// Reallocate memory for the buffers.
	AcctName = (TCHAR*)calloc(dwAcctName+1,sizeof(TCHAR));
	if (!AcctName) {
		goto FAIL;
	}
	DomainName = (TCHAR*)calloc(dwDomainName+1, sizeof(TCHAR));
	if (!DomainName) {
		goto FAIL;
	}
	// Second call to LookupAccountSid to get the account name.
	bRtnBool = LookupAccountSid(
		NULL,                   // name of local or remote computer
		pTokenUser->User.Sid,              // security identifier
		AcctName,               // account name buffer
		&dwAcctName,   // size of account name buffer 
		DomainName,             // domain name
		&dwDomainName, // size of domain name buffer
		&snu);

	//这里会报错，为什么啊？
	tmpFullname = (TCHAR*)calloc(dwAcctName+2 + 1 + dwDomainName + 1, sizeof(TCHAR));
	if (!tmpFullname) {
		printf("\tmalloc失败,ERROR: %d\n", GetLastError());
		goto FAIL;
	}
	if (bRtnBool) {
		_tcscat(tmpFullname, DomainName);
		_tcscat(tmpFullname, L"\\");
		_tcscat(tmpFullname, AcctName);
		_tcscpy(full_name_to_return, tmpFullname);
		if (AcctName != NULL) {
			free(AcctName);
			AcctName = NULL;
		}
		if (DomainName != NULL) {
			free(DomainName);
			DomainName = NULL;
		}
		if (tmpFullname != NULL) {
			free(tmpFullname);
			tmpFullname = NULL;
		}
		// 释放pTokenUser
		if (pTokenUser != NULL) {
			free(pTokenUser);
			pTokenUser = NULL;
		}
		return TRUE;
	}
FAIL:
	// 释放pTokenUser
	if (pTokenUser != NULL) {
		free(pTokenUser);
		pTokenUser = NULL;
	}
	if (AcctName != NULL) {
		free(AcctName);
		AcctName = NULL;
	}
	if (DomainName != NULL) {
		free(DomainName);
		DomainName = NULL;
	}
	if (tmpFullname != NULL) {
		free(tmpFullname);
		tmpFullname = NULL;
	}
	return FALSE;

}

/*释放链表中的节点*/
BOOL TokenInforUtil::ReleaseTokenListNode(TokenListNode* pTokenListNode) {
	if (pTokenListNode->tProcName) {
		free(pTokenListNode->tProcName);
		pTokenListNode->tProcName = NULL;
	}
	if (pTokenListNode->tUserName) {
		free(pTokenListNode->tUserName);
		pTokenListNode->tUserName = NULL;
	}
	if (pTokenListNode->hToken) {
		CloseHandle(pTokenListNode->hToken);
	}
	ZeroMemory(pTokenListNode, sizeof(TokenListNode));
	return TRUE;
}
BOOL TokenInforUtil::ReleaseTokenList(TokenList* pTokenList) {
	for (DWORD i = 0; i < pTokenList->dwLength; i++) {
		ReleaseTokenListNode(pTokenList->pTokenListNode + pTokenList->dwLength);
	}
	ZeroMemory(pTokenList, sizeof(TokenList));
	return TRUE;
}

/*判断该token是否可以被模拟*/
BOOL TokenInforUtil::CanBeImpersonate(HANDLE hToken, BOOL* bRet) {
	HANDLE temp_token;
	//LPVOID TokenImpersonationInfo[10];
	// 获取令牌模拟等级信息，若获取到，则判断模拟等级是不是大于等于模拟
	DWORD dwTokenIL;
	if (GetTokenILFromToken(hToken, &dwTokenIL)) {
		if (dwTokenIL >= SecurityImpersonation)
			*bRet = TRUE;
		else
			*bRet = FALSE;
		return TRUE;
	}
	// 若未获取到令牌等级信息，则尝试是否能够使用该令牌创建一个具有模拟等级的模拟令牌。根据创建的结果判断能够模拟该令牌
	*bRet = DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &temp_token);
	if(*bRet && temp_token != NULL)
		CloseHandle(temp_token);
	return TRUE;
}


/*从token中获取模拟等级*/
BOOL TokenInforUtil::GetTokenILFromToken(HANDLE hToken, DWORD* dwIL) {
	//LPVOID TokenImpersonationInfo[BUF_SIZE];
	PSECURITY_IMPERSONATION_LEVEL pTokenIL = NULL;
	DWORD dwRet = 0;
	// 获取令牌模拟等级信息，若获取到，则判断模拟等级是不是大于等于模拟
	GetTokenInformation(hToken, TokenImpersonationLevel, pTokenIL, NULL, &dwRet);
	pTokenIL = (PSECURITY_IMPERSONATION_LEVEL)calloc(1,dwRet);
	if (!pTokenIL) {
		printf("\tmalloc失败，ERROR: %d\n", GetLastError());
		return FALSE;
	}
	if (GetTokenInformation(hToken, TokenImpersonationLevel, pTokenIL, dwRet, &dwRet)) {
		*dwIL = *pTokenIL;
		//printf("\t获取令牌中的模拟等级成功，%d\n", *dwIL);
	}
	else {
		//printf("\t获取令牌中的模拟等级失败，ERROR: %d\n", GetLastError());
		*dwIL = -1;
		//if (pTokenIL != NULL) {
		//	free(pTokenIL);
		//	pTokenIL = NULL;
		//}
		//return FALSE;
	}
	if (pTokenIL != NULL) {
		free(pTokenIL);
		pTokenIL = NULL;
	}
	return TRUE;
}


/*从token中获取令牌类型*/
BOOL TokenInforUtil::GetTokenTypeFromToken(HANDLE hToken,DWORD* dwTokenType) {
	DWORD* pTokenTypeInfo;
	DWORD dwRet = 0;
	DWORD error;
	GetTokenInformation(hToken, TokenType, NULL, NULL, &dwRet);
	if (0 == dwRet) {
		error = GetLastError();
		printf(" \tTokenType\t: Error: %d\n\n", error);
		*dwTokenType = -1;
		return FALSE;
	}

	pTokenTypeInfo = (DWORD*)calloc(1,dwRet);
	if (!pTokenTypeInfo) {
		printf("\tmalloc失败，ERROR: %d\n", GetLastError());
		return FALSE;
	}
	if (GetTokenInformation(hToken, TokenType, pTokenTypeInfo, dwRet, &dwRet)) {
		error = GetLastError();
		*dwTokenType = *pTokenTypeInfo;
		if (pTokenTypeInfo != NULL) {
			free(pTokenTypeInfo);
			pTokenTypeInfo = NULL;
		}
		return TRUE;
	}
	else {
		error = GetLastError();
		printf(" \t获取token中的令牌类型失败， Error: %d\n", error);
		*dwTokenType = -1;
		return FALSE;

	}
}


/*根据用户名获取令牌*/
BOOL TokenInforUtil::GetTokenByUsername(TokenList tokenList,TCHAR* tUsernameArg, HANDLE* hOutToken) {
	for (DWORD i = 0; i < tokenList.dwLength; i++) {
		if (tokenList.pTokenListNode[i].tUserName == NULL) {
			continue;
		}
		if (tokenList.pTokenListNode[i].bCanBeImpersonate != 1) {
			continue;
		}
		if (_tcscmp(tokenList.pTokenListNode[i].tUserName, tUsernameArg) == 0) {
			*hOutToken = tokenList.pTokenListNode[i].hToken;
			return TRUE;
		}
	}
	if(*hOutToken == NULL)
		return FALSE;
}

/*根据进程ID获取令牌*/
BOOL TokenInforUtil::GetTokenByProcessid(TokenList tokenList, DWORD dwPid, HANDLE* hOutToken) {
	for (DWORD i = 0; i < tokenList.dwLength; i++) {
		if (tokenList.pTokenListNode[i].tUserName == NULL) {
			continue;
		}
		if (tokenList.pTokenListNode[i].bCanBeImpersonate != 1) {
			continue;
		}
		if (dwPid != -1 && tokenList.pTokenListNode[i].dwPID == dwPid) {
			*hOutToken = tokenList.pTokenListNode[i].hToken;
			return TRUE;
		}
	}
	if (*hOutToken == NULL)
		return FALSE;
}


BOOL TokenInforUtil::GetTokenByUserProc(TokenList tokenList, TCHAR* tUsernameArg, DWORD dwPid, HANDLE* hOutToken) {
	for (DWORD i = 0; i < tokenList.dwLength; i++) {
		if (tokenList.pTokenListNode[i].tUserName == NULL) {
			continue;
		}
		if (tokenList.pTokenListNode[i].bCanBeImpersonate != 1) {
			continue;
		}
		if (tUsernameArg != NULL && _tcscmp(tokenList.pTokenListNode[i].tUserName, tUsernameArg) != 0) {
			continue;
		}
		if (dwPid != -1 && tokenList.pTokenListNode[i].dwPID != dwPid) {
			continue;
		}
		if (tokenList.pTokenListNode[i].bCanBeImpersonate == 1) {
			*hOutToken = tokenList.pTokenListNode[i].hToken;
			return TRUE;
		}
	}
	if (*hOutToken == NULL)
		return FALSE;
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

/*打印令牌中的权限信息*/
BOOL TokenInforUtil::PrintPriv(HANDLE hToken) {
	DWORD error;

	PTOKEN_PRIVILEGES ppriv = NULL;
	DWORD dwRet = 0;
	//BOOL tmp = GetTokenInformation(tok, TokenGroups, ppriv, dwRet, &dwRet);
	GetTokenInformation(hToken, TokenPrivileges, ppriv, dwRet, &dwRet);
	if (!dwRet)
		return 0;
	ppriv = (PTOKEN_PRIVILEGES)calloc(dwRet, 1);
	if (!GetTokenInformation(hToken, TokenPrivileges, ppriv, dwRet, &dwRet)) {
		std::cout << " \t获取token信息失败，Error: " << GetLastError() << std::endl;
		return FALSE;
	}
	printf("\n \tprivileges:\n");
	if (ppriv->PrivilegeCount == 0) {
		std::cout << " \t\tno privileges" << std::endl;
	}
	else {
		for (DWORD i = 0; i < ppriv->PrivilegeCount; i++)
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
	if (ppriv != NULL) {
		free(ppriv);
		ppriv = NULL;
	}
	return TRUE;
}

/*打印令牌信息*/
BOOL TokenInforUtil::PrintTokens(TokenList tokenList) {
	for (DWORD i = 0; i < tokenList.dwLength; i++) {
		printf("PID: %d\n", tokenList.pTokenListNode[i].dwPID);
		printf("HandleOffset: 0x%x\n", tokenList.pTokenListNode[i].dwHandleOffset);
		printf("LogonID: %08x-%08x\n", tokenList.pTokenListNode[i].luLogonID.HighPart,tokenList.pTokenListNode[i].luLogonID.LowPart);
		printf("IL: %d\n", tokenList.pTokenListNode[i].dwIL);
		printf("CanBeImpersonated: %d\n", tokenList.pTokenListNode[i].bCanBeImpersonate);
		if (tokenList.pTokenListNode[i].tProcName != nullptr) {
			printf("ProcessName: %S\n", tokenList.pTokenListNode[i].tProcName);
		}
		else {
			printf("ProcessName: None\n");
		}
		if (tokenList.pTokenListNode[i].tUserName != nullptr) {
			printf("TokenUser: %S\n", tokenList.pTokenListNode[i].tUserName);
		}
		else {
			printf("TokenUser: None\n");
		}
		printf("\n");
	}
	return TRUE;
}



BOOL AddTokenListNode() {
	return TRUE;
}

BOOL AddTokenList(PTokenList pDstTokenList, PTokenList pSrcTokenList) {
	DWORD dwProcCountIncrPer = 1000;
	DWORD dwProcList[1000] = { 0 };
	DWORD dwProcCount = 0;
	// [+]210508:存储进程的主令牌
	for (DWORD dwTmpI = 0; dwTmpI < sizeof(dwProcList); dwTmpI++) {

	}
	return TRUE;

}
/*
初始化TokenListNode
*/
//#define USERNAME_CHAR_COUNT 50
//#define PROCNAME_CHAR_COUNT 260


/*获取系统中的所有令牌*/
BOOL TokenInforUtil::GetTokens(PTokenList pTokenList) {
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION_EX pshi = (PSYSTEM_HANDLE_INFORMATION_EX)calloc(1,sizeof(SYSTEM_HANDLE_INFORMATION_EX));
	if (!pshi) {
		printf("\tmalloc失败，ERROR: %d\n", GetLastError());
		return FALSE;
	}
	NTQUERYSYSTEMINFORMATION NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(_T("NTDLL.DLL")), "NtQuerySystemInformation");
	TCHAR* tUsername = NULL;
	TCHAR* tProcName = NULL;
	DWORD dwRet = 0;
	DWORD dwIL = -1;
	DWORD dwTokenType = -1; //令牌类型，1：主令牌，2：模拟令牌
	PTOKEN_GROUPS_AND_PRIVILEGES pTokenGroupsAndPrivileges = NULL;
	HANDLE hObject = NULL;
	HANDLE hProc = NULL;
	BOOL bCanBeImpersonate = FALSE;

	if (pshi) {
		status = NtQuerySystemInformation(SystemHandleInformation, pshi, sizeof(SYSTEM_HANDLE_INFORMATION_EX), NULL);
		//printf("pshi->NumberOfHandles: %lu\n", pshi->NumberOfHandles);
		DWORD tmpPid = 0;
		for (ULONG r = 0; r < pshi->NumberOfHandles; r++)
		{
			// 用来获取每个进程（除了0）的主令牌
			// TODO
			// Info1. 句柄所在的进程ID
			//(pTokenList->pTokenListNode + pTokenList->dwLength)->dwPID = pshi->Information[r].ProcessId;
			// Info2. 句柄在进程句柄表中的offset
			//(pTokenList->pTokenListNode + pTokenList->dwLength)->dwHandleOffset = pshi->Information[r].Handle;
			// 打开进程句柄
			if (pshi->Information[r].ProcessId != tmpPid){
				tmpPid = pshi->Information[r].ProcessId;
				// 获取主令牌
				hProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, (DWORD)pshi->Information[r].ProcessId);
				if (hProc == NULL) {
					hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pshi->Information[r].ProcessId);
					if (hProc == NULL) {
						// 下个句柄
						continue;
					}
				}
				// Info3. 进程所在文件名
				// 获取PID对应的进程名
				tProcName = (TCHAR*)calloc(MAX_PATH, sizeof(TCHAR));
				if (!tProcName) {
					printf("\tcalloc失败，ERROR: %d\n", GetLastError());
					return FALSE;
				}
				else {
					if (!ProcessInforUtil::GetProcessNameFromPid((DWORD)pshi->Information[r].ProcessId, tProcName)) {
						goto loopCon;
					}
				}
				// 获取进程的主令牌
				SetLastError(0);
				HANDLE tmpHToken;
				BOOL getToken = OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tmpHToken);
				if (getToken) {
					//printf("[+] OpenProcessToken() success!\n");
				}
				else
				{
					//printf("[-] OpenProcessToken() Return Code: %i\n", getToken);
					//printf("[-] OpenProcessToken() Error: %i\n", GetLastError());
					// 报错Access Denied: 5的原因可能是当前正在模拟其他用户
					// 查看当前模拟的是哪个用户
					//if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS,TRUE, &tmpHToken) == TRUE) {
					//
					//	// 从token中获取用户名
					//	tUsername = (TCHAR*)calloc(DOMAIN_CHAR_COUNT + 1 + USERNAME_CHAR_COUNT + 1, sizeof(TCHAR));
					//	if (!tUsername) {
					//		printf("\tcalloc失败,ERROR: %d\n", GetLastError());
					//		return FALSE;
					//	}
					//	else {
					//		if (!GetDomainUsernameFromToken(tmpHToken, tUsername)) {
					//			//(pTokenList->pTokenListNode + pTokenList->dwLength)->tUserName = (TCHAR*)calloc(_tcslen(tUsername) + 1, sizeof(TCHAR));
					//			//_tcscpy((pTokenList->pTokenListNode + pTokenList->dwLength)->tUserName, tUsername);
					//			goto loopCon;
					//		}
					//	}
					//}
					//else {
					//	printf("[-] OpenThreadToken() Error: %i\n", GetLastError());
					//}
					goto loopCon;
				}
				// 复制主令牌到当前进程句柄表中
				SetLastError(0);
				if (!DuplicateTokenEx(tmpHToken, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, NULL, SecurityImpersonation, TokenPrimary, &hObject)) {
					printf("[-]Error:%d\n", GetLastError());
					goto loopCon;
				}
				// Info9. 获取令牌类型
				GetTokenTypeFromToken(tmpHToken, &dwTokenType);
				CloseHandle(tmpHToken);
				// Info4. token句柄
					// 从token中获取登录会话ID
				dwRet = 0;
				GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet);
				if (dwRet == 0) {
					//printf("\tdwreterror,ERROR: %d\n", GetLastError());
					goto loopCon;
				}
				else {
					pTokenGroupsAndPrivileges = (PTOKEN_GROUPS_AND_PRIVILEGES)calloc(dwRet, 1);
					if (!GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet)) {
						// Info5. 令牌所关联的登录会话
						//(pTokenList->pTokenListNode + pTokenList->dwLength)->luLogonID = pTokenGroupsAndPrivileges->AuthenticationId;
						goto loopCon;
					}
				}
				// Info6. 用户名
				// 从token中获取用户名
				tUsername = (TCHAR*)calloc(DOMAIN_CHAR_COUNT + 1 + USERNAME_CHAR_COUNT + 1, sizeof(TCHAR));
				if (!tUsername) {
					printf("\tcalloc失败,ERROR: %d\n", GetLastError());
					return FALSE;
				}
				else {
					if (!GetDomainUsernameFromToken(hObject, tUsername)) {
						//(pTokenList->pTokenListNode + pTokenList->dwLength)->tUserName = (TCHAR*)calloc(_tcslen(tUsername) + 1, sizeof(TCHAR));
						//_tcscpy((pTokenList->pTokenListNode + pTokenList->dwLength)->tUserName, tUsername);
						goto loopCon;
					}
				}
				// Info7. 令牌模拟等级
				// 获取令牌模拟等级
				dwIL = -1;
				if (!TokenInforUtil::GetTokenILFromToken(hObject, &dwIL)) {
					//(pTokenList->pTokenListNode + pTokenList->dwLength)->dwIL = dwIL;
					goto loopCon;
				}
				// Info8. 令牌是否可以被模拟
				bCanBeImpersonate = FALSE;
				if (!CanBeImpersonate(hObject, &bCanBeImpersonate)) {
					goto loopCon;
				}
				goto ADDListNode;
			
			}

			// Token类型的值是5
			if (pshi->Information[r].ObjectTypeNumber == 5)
			{
				// Info1. 句柄所在的进程ID
				//(pTokenList->pTokenListNode + pTokenList->dwLength)->dwPID = pshi->Information[r].ProcessId;
				// Info2. 句柄在进程句柄表中的offset
				//(pTokenList->pTokenListNode + pTokenList->dwLength)->dwHandleOffset = pshi->Information[r].Handle;
				// 打开进程句柄
				hProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, (DWORD)pshi->Information[r].ProcessId);
				if (hProc == NULL) {
					hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pshi->Information[r].ProcessId);
					if (hProc == NULL) {
						// 下个句柄
						continue;
					}
				}
				// Info3. 进程所在文件名
				// 获取PID对应的进程名
				tProcName = (TCHAR*)calloc(MAX_PATH,sizeof(TCHAR));
				if (!tProcName) {
					printf("\tcalloc失败，ERROR: %d\n", GetLastError());
					return FALSE;
				}
				else {
					if (!ProcessInforUtil::GetProcessNameFromPid((DWORD)pshi->Information[r].ProcessId, tProcName)) {
						goto loopCon;
					}
				}
				// 复制token句柄到当前进程的句柄表中
				if (!DuplicateHandle(hProc, (HANDLE)(pshi->Information[r].Handle), GetCurrentProcess(), &hObject, MAXIMUM_ALLOWED, FALSE, 0x02)) {
					goto loopCon;
				}else{
					// Info4. token句柄
					// 从token中获取登录会话ID
					dwRet = 0;
					GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet);
					if (dwRet == 0) {
						//printf("\tdwreterror,ERROR: %d\n", GetLastError());
						goto loopCon;
					}
					else {
						pTokenGroupsAndPrivileges = (PTOKEN_GROUPS_AND_PRIVILEGES)calloc(dwRet, 1);
						if (!GetTokenInformation(hObject, TokenGroupsAndPrivileges, pTokenGroupsAndPrivileges, dwRet, &dwRet)) {
							// Info5. 令牌所关联的登录会话
							//(pTokenList->pTokenListNode + pTokenList->dwLength)->luLogonID = pTokenGroupsAndPrivileges->AuthenticationId;
							goto loopCon;
						}
					}
					// Info6. 用户名
					// 从token中获取用户名
					tUsername = (TCHAR*)calloc(DOMAIN_CHAR_COUNT + 1 + USERNAME_CHAR_COUNT+1,sizeof(TCHAR));
					if (!tUsername) {
						printf("\tcalloc失败,ERROR: %d\n", GetLastError());
						return FALSE;
					}
					else {
						if (!GetDomainUsernameFromToken(hObject, tUsername)) {
							//(pTokenList->pTokenListNode + pTokenList->dwLength)->tUserName = (TCHAR*)calloc(_tcslen(tUsername) + 1, sizeof(TCHAR));
							//_tcscpy((pTokenList->pTokenListNode + pTokenList->dwLength)->tUserName, tUsername);
							goto loopCon;
						}
					}
					// Info7. 令牌模拟等级
					// 获取令牌模拟等级
					dwIL = -1;
					if (!TokenInforUtil::GetTokenILFromToken(hObject,&dwIL)) {
						//(pTokenList->pTokenListNode + pTokenList->dwLength)->dwIL = dwIL;
						goto loopCon;
					}
					// Info8. 令牌是否可以被模拟
					bCanBeImpersonate = FALSE;
					if (!CanBeImpersonate(hObject, &bCanBeImpersonate)) {
						goto loopCon;
					}
					// Info9. 获取令牌类型
					GetTokenTypeFromToken(hObject, &dwTokenType);
					//system("pause");
				}
		
			ADDListNode:
				// Info1. 句柄所在的进程ID
				(pTokenList->pTokenListNode + pTokenList->dwLength)->dwPID = pshi->Information[r].ProcessId;
				// Info2. 句柄在进程句柄表中的offset
				(pTokenList->pTokenListNode + pTokenList->dwLength)->dwHandleOffset = pshi->Information[r].Handle;
				// Info3. 进程所在文件名
				if (tProcName != NULL && _tcscmp(tProcName, L"") != 0) {
					(pTokenList->pTokenListNode + pTokenList->dwLength)->tProcName = (TCHAR*)calloc(_tcslen(tProcName) + 1, sizeof(TCHAR));
					_tcscpy((pTokenList->pTokenListNode + pTokenList->dwLength)->tProcName, tProcName);
				}
				// Info4. token句柄
				(pTokenList->pTokenListNode + pTokenList->dwLength)->hToken = hObject;
				// Info5. 令牌所关联的登录会话
				if (pTokenGroupsAndPrivileges != nullptr) {
					(pTokenList->pTokenListNode + pTokenList->dwLength)->luLogonID = pTokenGroupsAndPrivileges->AuthenticationId;
				}
				// Info6. 用户名
				if (tUsername != NULL && _tcscmp(tUsername, L"") != 0) {
					(pTokenList->pTokenListNode + pTokenList->dwLength)->tUserName = (TCHAR*)calloc(_tcslen(tUsername) + 1, sizeof(TCHAR));
					if (!((pTokenList->pTokenListNode + pTokenList->dwLength)->tUserName)) {
						return FALSE;
					}
					_tcscpy((pTokenList->pTokenListNode + pTokenList->dwLength)->tUserName, tUsername);
				}
				// Info7. 令牌模拟等级
				(pTokenList->pTokenListNode + pTokenList->dwLength)->dwIL = dwIL;
				// Info8. 令牌是否可以被模拟
				(pTokenList->pTokenListNode + pTokenList->dwLength)->bCanBeImpersonate = bCanBeImpersonate;
				// Info9. 令牌类型，1：主令牌，2：模拟令牌
				(pTokenList->pTokenListNode + pTokenList->dwLength)->dwTokenType = dwTokenType;
				
				pTokenList->dwLength++;
//#define Token_List_Node_Count 1000
				if ((pTokenList->dwLength % Token_List_Node_Count) == 0) {
					pTokenList->pTokenListNode = (PTokenListNode)realloc(pTokenList->pTokenListNode, (pTokenList->dwLength / Token_List_Node_Count + 1)* Token_List_Node_Count*sizeof(TokenListNode));
					memset(pTokenList->pTokenListNode + pTokenList->dwLength, 0, Token_List_Node_Count * sizeof(TokenListNode));
				}
			loopCon:
				if (hProc != NULL) {
					CloseHandle(hProc);
					hProc = NULL;
				}
				if (tUsername != NULL) {
					free(tUsername);
					tUsername = NULL;
				}
				if (tProcName != NULL) {
					free(tProcName);
					tProcName = NULL;
				}
				if (pTokenGroupsAndPrivileges != NULL) {
					free(pTokenGroupsAndPrivileges);
					pTokenGroupsAndPrivileges = NULL;
				}
			}
		}
		free(pshi);
		pshi = NULL;
	}else {
		return FALSE;
	}
	return TRUE;
}



BOOL TokenInforUtil::TrySwitchTokenPriv(HANDLE hToken,LPCWSTR lpPrivName, BOOL bStatus,DWORD* pdwErr)
{
	DWORD dwError = 0;
	TOKEN_PRIVILEGES privileges;
	BOOL isNull = FALSE;
	if (hToken == NULL) {
		isNull = TRUE;
	}
	if (hToken == NULL && !OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken))
	{
		dwError = GetLastError();
		//printf("[test] error: %d\n", dwError);
		goto exit;
	}
	if (!LookupPrivilegeValue(NULL, lpPrivName, &privileges.Privileges[0].Luid))
	{
		dwError = GetLastError();
		goto exit;
	}
	if (bStatus) {
		privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else {
		privileges.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
	}
	privileges.PrivilegeCount = 1;

	if (AdjustTokenPrivileges(hToken, FALSE, &privileges, 0, NULL, NULL) == 0)
	{
		dwError = GetLastError();
		goto exit;
	}

exit:
	// 如果传进来没有传入hToken,则将新打开的token关闭
	if (isNull) {
		CloseHandle(hToken);
	}
	if(pdwErr != NULL)
		*pdwErr = dwError;
	if (dwError != 0) {
		//printf("error: %d\n", dwError);
		return FALSE;
	}
	else {
		return TRUE;
	}
}




/*判断是否具有SeAssignPrimaryTokenPrivilege权限*/
BOOL TokenInforUtil::HasAssignPriv(HANDLE hToken)
{
	LUID luid;
	LPVOID TokenPrivilegesInfo[BUF_SIZE];
	DWORD returned_privileges_length, returned_name_length, i;
	TCHAR privilege_name[BUF_SIZE];

	if (!LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luid)) {
		goto exit;
	}

	if (GetTokenInformation(hToken, TokenPrivileges, TokenPrivilegesInfo, BUF_SIZE, &returned_privileges_length))
	{
		for (i = 0; i < ((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->PrivilegeCount; i++)
		{
			returned_name_length = BUF_SIZE;
			LookupPrivilegeName(NULL, &(((TOKEN_PRIVILEGES*)TokenPrivilegesInfo)->Privileges[i].Luid), privilege_name, &returned_name_length);
			if (_tcscmp(privilege_name, _T("SeAssignPrimaryTokenPrivilege")) == 0)
				return TRUE;
		}
	}

exit:
	return FALSE;
}