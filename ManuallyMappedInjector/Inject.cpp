#include <string>
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <cstddef>
#include <fstream>
#include <iterator>

/* 
* Manual mapped injection (also called retrospective/introspective injection)
* involves mapping a dll into a target process without calling LoadLibrary in the target process
* This is more evasive because some applications will hook into LoadLibrary to detect the dlls being loaded
* However, it is very complicated because you have to emulate everything LoadLibrary does
*/

/*
* Resources and Examples:
* ==============================================================================
* Stack Overflow post describing high level overview of manual mapped injection:
* https://stackoverflow.com/questions/55768291/manual-dll-injection
* Complete video tutorial:
* https://www.youtube.com/watch?v=qzZTXcBu3cE&feature=emb_title
* Github of memory module written in C:
* https://github.com/fancycode/MemoryModule/tree/master/doc
* MSDN documentation:
* https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
* PE format docs:
* https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
* ==============================================================================
* 
* NOTE: Currently only working on 32 bit platforms for simplicity
* NOTE: Even though a dll is not allowed to execute directly, it is still considered an "executable image" in PE terminology
* DWORD = unsigned long
*/

HANDLE FindProcess(const WCHAR* processImageName);

typedef HMODULE (__stdcall *loadLibrary)(LPCSTR fileName);

struct MappingData
{
	bool relocationNeeded;
	DWORD dllBaseAddress;
	//... What else do we need here?
	//GetProcAddress
};


//Code in target process that will do all the adjustments for the DLL
//Perform base relocations, do imports, TLS callbacks, and invoke DLLMain
void ShellCode(MappingData *data)
{
	//6. PERFORM RELOCATIONS


}

void stub() {}

static bool ParseAndValidatePeHeader(std::vector<std::byte>& dllFileContents, _IMAGE_NT_HEADERS& peHeader, DWORD& pHeader)
{
	//Skip the first part, which is the DOS header, and read the offset to the PE signature (4 bytes); 	IMAGE_DOS_HEADER is the struct for the first part
	//TODO: Need to add some basic file size validation here, otherwise we will run out of bounds for some files
	static const unsigned int peSignatureOffset = 0x3c;
	long peSignatureFileAddress = 0;
	memcpy(&peSignatureFileAddress, (dllFileContents.data() + peSignatureOffset), sizeof(long));

	//Read the four bytes of the signature, they should be "PE\0\0"
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

	if (peHeader.FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
	{
		std::cerr << "Unsupported platfrom for dll file! Currently only supporting 32 bit..";
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

	if (peHeader.OptionalHeader.Magic != 0x10b)
	{
		std::cerr << "Currently only PE32 suppored!";
		return false;
	}

	return true;
}

static bool LaunchShellcode(HANDLE hProcess)
{
	MappingData data{ 0 };

	SYSTEM_INFO sysInfo{ 0 };
	GetSystemInfo(&sysInfo);

	LPVOID pShellCodeMemory = VirtualAllocEx(
		hProcess													/*hProcess*/,
		nullptr														/*lpAddress*/,
		sysInfo.dwAllocationGranularity								/*dwSize*/,
		MEM_COMMIT | MEM_RESERVE									/*flAllocationType*/,
		PAGE_EXECUTE_READWRITE);

	if (pShellCodeMemory == nullptr)
	{
		std::cerr << "Could not allocate memory for shellcode" << std::endl;
		return false;
	};

	DWORD numBytesWritten = 0;
#pragma warning(suppress: 6387)
	if (!WriteProcessMemory(
		hProcess																/*hProcess*/,
		pShellCodeMemory														/*lpBaseAddress*/,
		&data																	/*lpBuffer*/,
		sizeof(MappingData)														/*nSize*/,
		&numBytesWritten														/*lpNumberOfBytesWritten*/))
	{
		std::cout << "Failed to write shellcode into target program memory!" << std::endl;
		return false;
	}

	else if (numBytesWritten != sizeof(MappingData))
	{
		std::cout << "Failed to write shellcode into target program memory!" << std::endl;
		return false;
	}

	auto pTargetProcThreadRoutine = (PTHREAD_START_ROUTINE)(reinterpret_cast<DWORD>(pShellCodeMemory) + sizeof(MappingData));

	//We are using a dirty trick here to determine the size of the shellcode function
	if (!WriteProcessMemory(
		hProcess																/*hProcess*/,
		reinterpret_cast<LPVOID>(pTargetProcThreadRoutine)						/*lpBaseAddress*/,
		reinterpret_cast<LPVOID>(ShellCode)										/*lpBuffer*/,
		(reinterpret_cast<DWORD>(ShellCode) - reinterpret_cast<DWORD>(stub))	/*nSize*/,
		&numBytesWritten														/*lpNumberOfBytesWritten*/))
	{
		std::cout << "Failed to write shellcode into target program memory!" << std::endl;
		return false;
	}

	std::cout << "Starting new thread in process." << std::endl;

	HANDLE hThread = CreateRemoteThread(
		hProcess											/*hProcess*/,
		nullptr												/*lpThreadAttributes*/,
		0													/*dwStackSize*/,
		pTargetProcThreadRoutine							/*lpStartAddress*/,
		reinterpret_cast<MappingData*>(pShellCodeMemory)	/*lpParameter*/,
		0													/*dwCreationFlags*/,
		nullptr												/*lpThreadId*/
	);

	if (hThread == nullptr || hThread == INVALID_HANDLE_VALUE)
	{
		std::cout << "Failed to start remote thread in process!" << std::endl;
		return false;
	}

	::WaitForSingleObject(hThread, INFINITE);

	return true;
}

int main()
{
	//1. FIRST FIND THE PROCESS WE WANT TO INJECT INTO

	HANDLE hProcess = FindProcess(L"TargetProgram.exe");

	if (hProcess == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Could not find target process!";
		return 1;
	}

	//2. LOAD THE DLL TO BE INJECTED INTO OUR MEMORY

	static const std::string pathToDll = "C:\\Users\\Anirudh\\source\\repos\\ManualMapping\\Debug\\InjectionDll.dll";

	//Be careful to not use boolean || for second parameter flags
	std::basic_ifstream<std::byte> ifs(pathToDll, std::ifstream::in | std::ios::binary);
	if (!ifs)
	{
		std::cerr << "Injection dll could not be found!";
		return 1;
	}

	//Default constructed istreambuf_iterator is equal to end of file iterator
	std::vector<std::byte> dllFileContents(std::istreambuf_iterator<std::byte>(ifs), (std::istreambuf_iterator<std::byte>()));

	std::cout << "Read " << std::to_string(dllFileContents.size()) << " bytes from dll..." << std::endl << std::endl;

	//3. PARSE THE PE HEADER OF THE FILE
	IMAGE_NT_HEADERS32 peHeader{ 0 };
	DWORD headerOffset;
	if (!ParseAndValidatePeHeader(dllFileContents, peHeader, headerOffset))
		return 1;

	// Note that this is a virtual size - nothing to do with physical size on disk
	unsigned long szBytesImage = peHeader.OptionalHeader.SizeOfImage;

	//4. ALLOCATE MEMORY IN THE TARGET PROCESS

	LPVOID pMemory = VirtualAllocEx(
		hProcess													/*hProcess*/,
		reinterpret_cast<LPVOID>(peHeader.OptionalHeader.ImageBase)	/*lpAddress*/,
		szBytesImage												/*dwSize*/,
		MEM_COMMIT | MEM_RESERVE									/*flAllocationType*/,
		PAGE_EXECUTE_READWRITE										/*flProtect*/
	);

	bool relocationNeeded = false;
	if (pMemory == nullptr)
	{
		//The allocation granularity can be observed by calling GetSystemInfo - generally configured by OS, it is 64kb (note that page size is generally 4kb)
		relocationNeeded = true;
		pMemory = VirtualAllocEx(
			hProcess													/*hProcess*/,
			nullptr														/*lpAddress*/,
			szBytesImage												/*dwSize*/,
			MEM_COMMIT | MEM_RESERVE									/*flAllocationType*/,
			PAGE_EXECUTE_READWRITE);
		if (pMemory == nullptr)
		{
			std::cerr << "Could not allocate memory for dll in target process!" << std::endl;
			return 1;
		}
	}

	//5. WRITE SECTIONS TO MEMORY 
	DWORD alignment = peHeader.OptionalHeader.SectionAlignment;
	WORD numSections = peHeader.FileHeader.NumberOfSections;

	//Read sections into our memory
	PIMAGE_NT_HEADERS pHeader = reinterpret_cast<PIMAGE_NT_HEADERS32>(dllFileContents.data() + headerOffset);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pHeader);

	for (int i = 0; i < numSections; i++, pSection++)
	{
		std::string sectionName((char *)(&(pSection->Name[0])));
		std::cout << "Parsing and writing section " << sectionName << std::endl;

		DWORD numBytesWritten = 0;

		if (!WriteProcessMemory(
			hProcess																/*hProcess*/,
			reinterpret_cast<LPVOID>((DWORD)pMemory + pSection->VirtualAddress)		/*lpBaseAddress*/,
			(dllFileContents.data() + pSection->PointerToRawData)					/*lpBuffer*/,
			pSection->SizeOfRawData													/*nSize*/,
			&numBytesWritten														/*lpNumberOfBytesWritten*/
		))
		{
			std::cout << "Failed to map section " << sectionName << std::endl;
			return 1;
		}
		//Note that we should be guaranteed that the contents are initially 0 b/c of VirtualAllocEx
	}

	//6. ALLOCATE AND EXECUTE SHELLCODE
	if (!LaunchShellcode(hProcess))
		return 1;



	return 0;
}
