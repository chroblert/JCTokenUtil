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
	HANDLE hToken; //���ƾ��
	TCHAR* tUserName; // ���������û�
	DWORD dwPID; //������������id
	DWORD dwTID; //���������߳�id
	TCHAR* tProcName; //�����������̵��ļ���
	DWORD dwIL; // ģ��ȼ�
	DWORD dwTokenType; //��������
    DWORD dwHandleOffset;
    LUID luLogonID; //���ƶ�Ӧ�ĵ�¼�Ự
    BOOL bCanBeImpersonate; //�Ƿ��ܱ�ģ��
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