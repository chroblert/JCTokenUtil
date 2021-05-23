#pragma once
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <iostream>
#include "psapi.h"

#include "ProcessInforUtil.h"
#include "settings.h"
#include "StructureInfo.h"

typedef struct _TokenListNode {
	HANDLE hToken; //令牌句柄
	TCHAR* tUserName; // 令牌所属用户
	DWORD dwPID; //令牌所属进程id
	DWORD dwTID; //令牌所属线程id
	TCHAR* tProcName; //令牌所属进程的文件名
	DWORD dwIL; // 模拟等级
	DWORD dwTokenType; //令牌类型
    DWORD dwHandleOffset;
    LUID luLogonID; //令牌对应的登录会话
    BOOL bCanBeImpersonate; //是否能被模拟
}TokenListNode,*PTokenListNode;

typedef struct _TokenList {
	TokenListNode* pTokenListNode;
	DWORD dwLength;
}TokenList,*PTokenList;

class TokenInforUtil
{
public:
	static BOOL GetTokenByUsername(TokenList tokenList,TCHAR* tUsernameArg, HANDLE* hOutToken);
    static BOOL GetTokenByProcessid(TokenList tokenList, DWORD dwPid, HANDLE* hOutToken);
    static BOOL GetTokenByUserProc(TokenList tokenList, TCHAR* tUsernameArg, DWORD dwPid, HANDLE* hOutToken);
	static BOOL GetDomainUsernameFromToken(HANDLE token, TCHAR* full_name_to_return);
    //static BOOL GetDomainUsernameFromToken(HANDLE token, char* full_name_to_return);
	static BOOL GetTokens(PTokenList pTokenList);
    static BOOL PrintTokens(TokenList tokenList);
    static BOOL GetTokenILFromToken(HANDLE hToken, DWORD* dwIL);
    static BOOL CanBeImpersonate(HANDLE hToken, BOOL* bRet);
    static BOOL GetTokenTypeFromToken(HANDLE hToken, DWORD* dwTokenType);
    static BOOL ReleaseTokenList(TokenList* pTokenList);
    static BOOL ReleaseTokenListNode(TokenListNode* pTokenListNode);
    static BOOL PrintPriv(HANDLE hToken);
    static BOOL TrySwitchTokenPriv(HANDLE hToken, LPCWSTR lpPrivName, BOOL bStatus, DWORD* pdwErr);
    static BOOL HasAssignPriv(HANDLE hToken);
};

/*

*/