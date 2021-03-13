#include "injection.h"

bool ManualMap(HANDLE hProc, const char* szDllFile)
{
	BYTE*				pSrcData		= nullptr;
	IMAGE_NT_HEADERS*   pOldNtHeader	= nullptr;
	IMAGE_FILE_HEADER*  pOldFileHeader = nullptr;
	IMAGE_OPTIONAL_HEADER*  pOldOptHeader = nullptr;
	BYTE*			    pTargetBase		= nullptr;

	if (!GetFileAttributesA(szDllFile)) {
	
		std::cout << "File doesn't exist" << std::endl;
		return false;
	}

	std::ifstream File(szDllFile, std::ios::binary | std::ios::ate);

	if (File.fail()) {
		std::cout << "Opening the file failed" << std::hex << (DWORD)File.rdstate() << std::endl;
		return false;
	}

	auto FileSize = File.tellg();
	if (FileSize < 0x1000) {

		std::cout << "Filesize is invalid" << std::endl;
		File.close();
		return false;
	}

	// Now we can start reading the file into memory.

	pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];
	if (!pSrcData) {
		std::cout << "mem alloc failed" << std::endl;
		File.close();
		return false;
	}

	// now fp pointing at beginning
	File.seekg(0, std::ios::beg);

	File.read(reinterpret_cast<char*> (pSrcData), FileSize);
	File.close();

	// reinterpret SrcData into image dos header
	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) { // check if magic bytes are valid

		std::cout << "Invalid file" << std::endl;
		delete[] pSrcData;
		return false;

	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*> (pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

#ifdef _WIN64
	auto arch = IMAGE_FILE_MACHINE_AMD64;
#else
	auto arch = IMAGE_FILE_MACHINE_I386;
#endif

	if (pOldFileHeader->Machine != arch) {
		std::cout << "Invalid arch" << std::endl;
		delete[] pSrcData;
		return false;
	}



	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pTargetBase) {

		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr,  pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

		if (!pTargetBase) {

			// if we get here, there is no way to alloc mem in the target process, for whatever reason
			std::cout << "memory allocation failed (ex) 0x" << std::hex << GetLastError() << std::endl;
			delete[] pSrcData;
			return false;

		}
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

	// now we start mapping the sections.

	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);

	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {


		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
				std::cout << "cant map sections: 0x" << std::hex << GetLastError() << std::endl;

				delete[] pSrcData;
				VirtualFreeEx(hProc, pTargetBase,  0, MEM_RELEASE);
				return false;

			}
		}
	}

	memcpy(pSrcData, &data, sizeof(data));
	WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000 ,nullptr);
	
	delete[] pSrcData;

	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		std::cout << "memory allocation failed error code: 0x" << std::hex << GetLastError() << std::endl;
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr);

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);

	if (!hThread) {
		std::cout << "memory allocation failed error code: 0x" << std::hex << GetLastError() << std::endl;
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}

	CloseHandle(hThread);

	HINSTANCE hCheck = NULL;
	while (!hCheck) {
		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;
		Sleep(10);
	}

	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);

	return true;

}

static BOOL isRelocFlag(WORD* pRelativeInfo) {
#ifdef _WIN64
	if ((*pRelativeInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW) return true;
	else return false;
#else
	if ((*pRelativeInfo >> 0x0C) == IMAGE_REL_BASED_DIR64) return true;
	else return false;

#endif
}



void __stdcall Shellcode(MANUAL_MAPPING_DATA* pdata)
{

	if (!pdata) {
		return;
	}

	BYTE* pBase = reinterpret_cast<BYTE*>(pdata);
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pdata)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pdata->pLoadLibraryA;
	auto _GetProcAddress = pdata->pGetProcAddress;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	// relocation...
	
	// is there relocation data?
	BYTE* LocationDelta = pBase - pOpt->ImageBase;

	if (LocationDelta != 0 ) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			return;
		}

		// grab first base relocation entry
		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress) {
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {

				
				if (isRelocFlag(pRelativeInfo)) {

					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);

				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {

		auto* pImportDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescriptor->Name) {

			char* szMod = reinterpret_cast<char*>(pBase + pImportDescriptor->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);
			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->FirstThunk);

			if (!pThunkRef) {
				pThunkRef = pFuncRef;
			}

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {

				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescriptor;


		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {

		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback) {
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}

	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pdata->hMod = reinterpret_cast<HINSTANCE>(pBase);

	return;
}

