#pragma once

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

using f_LoadLibraryA = HINSTANCE  (WINAPI*) (const char* lpLibFilename);
using f_GetProcAddress = UINT_PTR (WINAPI*) (HINSTANCE hModule, const char* lpProcModule);
using f_DLL_ENTRY_POINT = BOOL    (WINAPI*) (void* hDll, DWORD dwReason, void* pReserved);


struct MANUAL_MAPPING_DATA {
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
	HINSTANCE hMod;
};

// only abs paths.
bool ManualMap(HANDLE hProc, const char* szDllFiles);
void Shellcode(MANUAL_MAPPING_DATA* pdata);

