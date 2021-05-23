#pragma once
#include <tchar.h>
#include <windows.h>

#include <NTSecAPI.h>
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

int EnumLogonSessions();