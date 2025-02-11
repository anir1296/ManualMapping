#include <string>
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <cstddef>
#include <fstream>
#include <iterator>

HANDLE FindProcess(const WCHAR* processImageName);

typedef HMODULE(WINAPI* f_loadLibrary)(LPCSTR fileName);
typedef FARPROC(WINAPI* f_getProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef BOOL(WINAPI* f_dllEntryPoint)(void* hDll, DWORD dwReason, void* pReserved);

typedef BOOL(WINAPI* f_WriteConsole)(HANDLE hConsoleOutput,
	CONST CHAR_INFO* lpBuffer,
	COORD dwBufferSize,
	COORD dwBufferCoord,
	PSMALL_RECT lpWriteRegion);


typedef HANDLE(WINAPI* f_GetStdHandle)(DWORD nStdHandle);

struct MappingData
{
	f_loadLibrary pLoadLibary;
	f_getProcAddress pGetProcAddress;

	LPVOID pBase; // image base
	HINSTANCE hMod;

	f_WriteConsole pWriteConsoleA;
	f_GetStdHandle pGetStdHandle;

	char buffer[100];
};

// right shift a WORD (16 bits) by 12 to get high 4 bits, which is the Type of the relocation
#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

// Code in target process that will do all the adjustments for the DLL
// Perform base relocations, do imports, TLS callbacks, and invoke DLLMain

// need these two to avoid MSVC ompiler injecting thunks (jmp instructions)
// also need to disable JMC and incremental linking
// this is copied almost directly from Cruz's Manual Mapper

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall Shellcode(MappingData* pData) {
	if (!pData) {
		pData->hMod = (HINSTANCE)0x404040;
		return;
	}

	// Print a message in the target program - since this is shell code we can't use string literals as they are in static .ro (read only) rection
	// std::cout and printf are much simpler but there does not seem to be any guarantee of their address so we use WriteConsoleOutputA
	SMALL_RECT writeRect;
	writeRect.Bottom = 1; writeRect.Top = 1; writeRect.Left = 0; writeRect.Right = 19;

	CHAR_INFO chiBuffer[20];
	for (int i = 0; i < 20; i++) {
		chiBuffer[i].Char.AsciiChar = pData->buffer[i];
		chiBuffer[i].Attributes = FOREGROUND_BLUE | FOREGROUND_GREEN;
	}

	COORD coordBufSize;
	coordBufSize.Y = 1;
	coordBufSize.X = 20;

	COORD coordBufCoord;
	coordBufCoord.Y = 0;
	coordBufCoord.X = 0;

	auto pWriteConsoleA = pData->pWriteConsoleA;
	auto pGetStdHandle = pData->pGetStdHandle;

	HANDLE stdOut = pGetStdHandle(STD_OUTPUT_HANDLE);
	pWriteConsoleA(stdOut, chiBuffer, coordBufSize, coordBufCoord, &writeRect);

	BYTE* pBase = reinterpret_cast<BYTE *>(pData->pBase);
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibary;
	auto _GetProcAddress = pData->pGetProcAddress;

	auto _DllMain = reinterpret_cast<f_dllEntryPoint>(pBase + pOpt->AddressOfEntryPoint);

	// perform base relocations - no need if dll is already loaded at preferred base

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG64(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	// perform imports for the dll 

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	// perform tls callbacks

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	bool ExceptionSupportFailed = false;

	_DllMain(pBase, DLL_PROCESS_ATTACH, 0);
}

void Stub() {}

static bool ParseAndValidatePeHeader(std::vector<std::byte>& dllFileContents, IMAGE_NT_HEADERS64& peHeader, DWORD& pHeader)
{
	// Skip the first part, which is the DOS header, and read the offset to the PE signature (4 bytes); 	IMAGE_DOS_HEADER is the struct for the first part
	// TODO: Need to add some basic file size validation here, otherwise we will run out of bounds for some files

	static const unsigned int peSignatureOffset = 0x3c; // this is the offset to lfa_new
	long peSignatureFileAddress = 0;
	memcpy(&peSignatureFileAddress, (dllFileContents.data() + peSignatureOffset), sizeof(long));

	// Read the four bytes of the signature, they should be "PE\0\0"
	int signatureIndex = peSignatureFileAddress;
	char sigByteOne = (char)dllFileContents[signatureIndex++];
	char sigByteTwo = (char)dllFileContents[signatureIndex++];
	char sigByteThree = (char)dllFileContents[signatureIndex++];
	char sigByteFour = (char)dllFileContents[signatureIndex];

	if (sigByteOne != 'P' || sigByteTwo != 'E' || sigByteThree != '\0' || sigByteFour != '\0')
	{
		std::cerr << "Could not verify PE signature of dll file!";
		return false;
	}

	pHeader = peSignatureFileAddress;
	memcpy(&peHeader, (dllFileContents.data() + peSignatureFileAddress), sizeof(_IMAGE_NT_HEADERS));

	if (peHeader.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		std::cerr << "Unsupported platfrom for dll file! Currently only supporting 64 bit..";
		return false;
	}

	if ((peHeader.FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)
	{
		std::cerr << "Given file is not a DLL file!";
		return false;
	}

	unsigned long szOptionalHeader = peHeader.FileHeader.SizeOfOptionalHeader;
	if (szOptionalHeader == 0)
	{
		std::cerr << "Size of optional header for dll was 0?";
		return false;
	}

	if (peHeader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		std::cerr << "Currently only PE64 suppored!";
		return false;
	}

	return true;
}

static bool LaunchShellcode(HANDLE hProcess, LPVOID pBase) {
	MappingData data{ 0 };

	// Default allocation granularity can be observed by calling GetSystemInfo - generally configured by OS, it is 64kb (note that page size is generally 4kb)
	SYSTEM_INFO sysInfo{ 0 };
	GetSystemInfo(&sysInfo);

	const std::string message = "Shellcode injected.";
	for (int i = 0; i < 20; i++) {
		data.buffer[i] = message[i];
	}
	data.buffer[20] = '\0';
	data.pWriteConsoleA = WriteConsoleOutputA;
	data.pGetStdHandle = GetStdHandle;
	data.pLoadLibary = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;

	LPVOID pShellCodeMemory = VirtualAllocEx(
		hProcess,
		nullptr,
		sysInfo.dwAllocationGranularity,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (pShellCodeMemory == nullptr)
	{
		std::cerr << "Could not allocate memory for shellcode" << std::endl;
		return false;
	};

	data.pBase = pBase;
	DWORD old;

	// seems uneccessary but documentation does suggest to invoke this for execute
	VirtualProtectEx(hProcess, pShellCodeMemory, sysInfo.dwAllocationGranularity, PAGE_EXECUTE_READWRITE, &old);

	SIZE_T numBytesWritten = 0;
#pragma warning(suppress: 6387)
	if (!WriteProcessMemory(
		hProcess,
		pShellCodeMemory,
		&data,
		sizeof(MappingData),
		&numBytesWritten))
	{
		std::cout << "Failed to write shellcode into target program memory!" << std::endl;
		return false;
	}

	else if (numBytesWritten != sizeof(MappingData))
	{
		std::cout << "Failed to write shellcode into target program memory!" << std::endl;
		return false;
	}

	auto pTargetProcThreadRoutine = (PTHREAD_START_ROUTINE)(reinterpret_cast<BYTE*>(pShellCodeMemory) + sizeof(MappingData));

	// dirty trick here to approximately determine the size of the shellcode function - not sure if reliable
	// std::abs(reinterpret_cast<int>(ShellCode) - reinterpret_cast<int>(Stub))
	// alternatively we can just use a really big number

	if (!WriteProcessMemory(
		hProcess,
		reinterpret_cast<LPVOID>(pTargetProcThreadRoutine),
		reinterpret_cast<LPVOID>(Shellcode),
		0x1000,
		&numBytesWritten))
	{
		std::cout << "Failed to write shellcode into target program memory!" << std::endl;
		return false;
	}

	std::cout << "Starting new thread in process." << std::endl;
	std::cout << pShellCodeMemory << std::endl;

	HANDLE hThread = CreateRemoteThread(
		hProcess,
		nullptr,
		0 /* use default stack size*/,
		pTargetProcThreadRoutine,
		pShellCodeMemory,
		0,
		nullptr
	);

	if (hThread == nullptr || hThread == INVALID_HANDLE_VALUE)
	{
		std::cout << "Failed to start remote thread in process!" << std::endl;
		return false;
	}

	system("pause");
	// wait until the thread completes
	DWORD res = WaitForSingleObject(hThread, INFINITE);
}

int main()
{
	HANDLE hProcess = FindProcess(L"TargetProgram.exe");

	if (hProcess == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Could not find target process!";
		return 1;
	}

	// 2. LOAD THE DLL TO BE INJECTED INTO OUR MEMORY

	static const std::string pathToDll = "<path to dll>";

	// Be careful to not use boolean || for second parameter flags
	std::basic_ifstream<std::byte> ifs(pathToDll, std::ifstream::in | std::ios::binary);
	if (!ifs)
	{
		std::cerr << "Injection dll could not be found!";
		return 1;
	}

	// Default constructed istreambuf_iterator is equal to end of file iterator
	std::vector<std::byte> dllFileContents(std::istreambuf_iterator<std::byte>(ifs), (std::istreambuf_iterator<std::byte>()));

	std::cout << "Read " << std::to_string(dllFileContents.size()) << " bytes from dll..." << std::endl << std::endl;

	// 3. PARSE THE PE HEADER OF THE FILE
	IMAGE_NT_HEADERS64 peHeader{ 0 };
	DWORD headerOffset;
	if (!ParseAndValidatePeHeader(dllFileContents, peHeader, headerOffset))
		return 1;

	// Note that this is a virtual size - nothing to do with physical size on disk
	unsigned long szBytesImage = peHeader.OptionalHeader.SizeOfImage;

	// 4. ALLOCATE MEMORY IN THE TARGET PROCESS
	LPVOID pMemory = VirtualAllocEx(
		hProcess,
		nullptr,
		szBytesImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (pMemory == nullptr)
	{
		std::cerr << "Could not allocate memory for dll in target process!" << std::endl;
		return 1;
	}

	// Make sure to write the dll file header itself into memory
	if (!WriteProcessMemory(hProcess, pMemory, dllFileContents.data(), 0x1000, nullptr)) { //only first 0x1000 bytes for the header
		printf("Can't write file header 0x%X\n", GetLastError());
		return false;
	}

	//5. WRITE SECTIONS TO MEMORY 
	DWORD alignment = peHeader.OptionalHeader.SectionAlignment;
	WORD numSections = peHeader.FileHeader.NumberOfSections;

	// Read sections into our memory
	PIMAGE_NT_HEADERS pHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(dllFileContents.data() + headerOffset);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pHeader);

	for (int i = 0; i < numSections; i++, pSection++)
	{
		std::string sectionName((char*)(&(pSection->Name[0])));
		std::cout << "Parsing and writing section " << sectionName << std::endl;

		SIZE_T numBytesWritten = 0;

		if (!WriteProcessMemory(
			hProcess,
			reinterpret_cast<LPVOID>((BYTE *)pMemory + pSection->VirtualAddress),
			(dllFileContents.data() + pSection->PointerToRawData),
			pSection->SizeOfRawData,
			&numBytesWritten
		))
		{
			std::cout << "Failed to map section " << sectionName << std::endl;
			return 1;
		}
		// Note that we should be guaranteed that the contents are initially 0 b/c of VirtualAllocEx
	}

	std::cout << std::endl;

	LaunchShellcode(hProcess, pMemory);

	return 0;
}
