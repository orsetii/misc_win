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
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
		std::cout << "Invalid arch" << std::endl;
		delete[] pSrcData;
		return false;
	}

#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
		std::cout << "Invalid arch" << std::endl;
		delete[] pSrcData;
		return false;
	}
#endif



	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (pTargetBase) {

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
				VirtualFreeEx(hProc, pTargetBase, MEM_RELEASE );
				return false;

			}
		}
	}
	delete[] pSrcData;
}

void Shellcode(MANUAL_MAPPING_DATA* pdata)
{
}

