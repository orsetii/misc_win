#include "injection.h"

const char szDllFile[] = "C:\\Users\\Tom French\\source\\repos\\misc_win\\Map.dll";
const char szProc[] = "Test Console.exe";

int main()
{
	PROCESSENTRY32 PE32{ 0 };

	PE32.dwSize = sizeof(PE32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap == INVALID_HANDLE_VALUE) {
		DWORD Err = GetLastError();
		std::cout << "Error in creating CreateToolhelp32Snapshot: 0x" << std::hex << Err << std::endl;
		system("PAUSE");
		return 0;
	}

	DWORD PID = 0;
	BOOL bRet = Process32First(hSnap, &PE32);
	while (bRet) {

		if (!strcmp(szProc, PE32.szExeFile)) {

			PID = PE32.th32ProcessID;
			break;
		}
		bRet = Process32Next(hSnap, &PE32);
	}

	CloseHandle(hSnap);

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	if (!hProc) {
	DWORD Err = GetLastError();
		std::cout << "Error in OpenProcess: 0x" << std::hex << Err << std::endl;
		system("PAUSE");
		return EXIT_FAILURE;

	}

	if (!ManualMap(hProc, szDllFile)) {

		CloseHandle(hProc);
		std::cout << "Error in ManualMap" << std::endl;
		system("PAUSE");
		return EXIT_FAILURE;
	}

	CloseHandle(hProc);

	return 0;
}
