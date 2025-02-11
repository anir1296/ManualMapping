#include <Windows.h>
#include <string>
#include <tlhelp32.h>
#include <processthreadsapi.h>
#include <memoryapi.h>
#include <synchapi.h>

HANDLE FindProcess(const WCHAR* processImageName);

static const std::string pathToDll = "C:\\Users\\Anirudh\\source\\repos\\ManualMapping\\x64\\Debug\\InjectionDll.dll";

int main()
{
	//1. First find the process we want to inject into
	HANDLE hProcess = FindProcess(L"TargetProgram.exe");

	//2. Virtually allocate memory for path of dll in target process 
	auto szBytesDllPath = pathToDll.length() * sizeof(char) + 1;
	LPVOID lpDllPath = VirtualAllocEx(hProcess, nullptr, szBytesDllPath, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpDllPath == 0)
		return 1;

	//3. Write to the memory of the target process
	SIZE_T szNumBytesWritten = 0;
	if (WriteProcessMemory(hProcess, lpDllPath, pathToDll.c_str(), szBytesDllPath, &szNumBytesWritten) == 0)
		return 1;

	if (szNumBytesWritten != szBytesDllPath)
		return 1;

	//This warning makes no sense
	//Warning	C6387	'Temp_value_#957' could be '0':  this does not adhere to the specification for the function 'GetProcAddress'.
#pragma warning(suppress:6387)
	auto lpLoadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32"), "LoadLibraryA");

	DWORD threadId;
	//4. Create a remote thread in the target process
	HANDLE remoteThreadHandle = CreateRemoteThread(
		hProcess,
		NULL,
		0,
		lpLoadLibraryAddr,
		lpDllPath,
		0,
		&threadId
	);

	if (remoteThreadHandle == NULL)
		return 1;

	//5. Wait for thread to complete
	WaitForSingleObject(remoteThreadHandle, INFINITE);

	return 0;
}

