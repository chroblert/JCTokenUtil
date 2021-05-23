//#pragma once
#include <tchar.h>
#ifndef GETOPT_H__
	#define GETOPT_H__

	#ifdef __cplusplus
	extern "C" {
	#endif

		extern TCHAR* optarg;
		extern int optind;

		int getopt(int argc, TCHAR* const argv[], const char* optstring);

	#ifdef __cplusplus
	}
	#endif

#endif