#include "Helper.h"
#include <tchar.h>
#include <stdio.h>

void Helper::print_usage() {
	const char* rawBanner = R"(
===============TokenUtil================
|          author:JC0o0l               |
|          wechat:JC_SecNotes          |
|          version:1.0[2105]           |
========================================)";
	printf("%s\n\n", rawBanner);

	const char* rawUsageMsg = R"(
Usage: TokenUtil.exe <module> [OPTION]

[MODULE]
	ListTokens
[OPTION]
	-p <pid>: �г�ĳ�������е�����
	-P <procName>: �г�ĳ�����̵�����
	-u <username>: �г�ĳ���û�������
	-v : ��ϸģʽ // ����-v��ÿ���û�ֻ���һ��

example:
	TokenUtils.exe ListTokens -u "NT AUTHORITY\SYSTEM" 
	TokenUtils.exe ListTokens -P "cmd"
	TokenUtils.exe ListTokens -P "cmd" -u "NT AUTHORITY\SYSTEM" 

[MODULE]	
	Execute
[OPTION]
	-p <pid>: ��ָ��pid��tokenִ������
	-u <username>: ��ĳ���û�ִ�������-e <command>���ʹ��
	-e <command> : ִ������
	-c: �Ƿ��ڵ�ǰ�ն���ִ��
	-v : ��ϸģʽ

example:
	TokenUtils.exe Execute -p <pid> -e whoami -c
	TokenUtils.exe Execute -u "NT AUTHORITY\SYSTEM" -e whoami -c
	TokenUtils.exe Execute -p <pid> -u "NT AUTHORITY\SYSTEM" -e whoami -c

)";
	printf("%s\n\n",rawUsageMsg);
}