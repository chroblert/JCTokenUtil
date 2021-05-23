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
	-p <pid>: 列出某个进程中的令牌
	-P <procName>: 列出某个进程的令牌
	-u <username>: 列出某个用户的令牌
	-v : 详细模式 // 不加-v，每个用户只输出一次

example:
	TokenUtils.exe ListTokens -u "NT AUTHORITY\SYSTEM" 
	TokenUtils.exe ListTokens -P "cmd"
	TokenUtils.exe ListTokens -P "cmd" -u "NT AUTHORITY\SYSTEM" 

[MODULE]	
	Execute
[OPTION]
	-p <pid>: 以指定pid的token执行命令
	-u <username>: 以某个用户执行命令，与-e <command>结合使用
	-e <command> : 执行命令
	-c: 是否在当前终端下执行
	-v : 详细模式

example:
	TokenUtils.exe Execute -p <pid> -e whoami -c
	TokenUtils.exe Execute -u "NT AUTHORITY\SYSTEM" -e whoami -c
	TokenUtils.exe Execute -p <pid> -u "NT AUTHORITY\SYSTEM" -e whoami -c

)";
	printf("%s\n\n",rawUsageMsg);
}