#include "getopt.h"
#include <windows.h>
#include <tchar.h>
#include <stdio.h>

TCHAR* optarg = NULL;
int optind = 1;

int getopt(int argc, TCHAR* const argv[], const char* optstring)
{
    if ((optind >= argc) || (argv[optind][0] != '-') || (argv[optind][0] == 0))
    {
        return -1;
    }

    int opt = argv[optind][1];
    const char* p = strchr(optstring, opt);

    if (p == NULL)
    {
        return '?';
    }
    //wcscpy_s(optarg,_countof(L"no"),L"no");
    //_tcscpy(optarg, L"no");
    if (p[1] == ':')
    {
        optind++;
        if (optind >= argc)
        {
            return '?';
        }
        optarg = argv[optind];
    }
    optind++;
    return opt;
}