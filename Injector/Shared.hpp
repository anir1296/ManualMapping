#include <Windows.h>
#include <processthreadsapi.h>
#include <tlhelp32.h>

//https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
//Do a process walk
HANDLE FindProcess(const WCHAR* processImageName)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return INVALID_HANDLE_VALUE;

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnap, &pe32))
	{
		CloseHandle(hSnap);
		return INVALID_HANDLE_VALUE;
	}

	HANDLE hProcess = INVALID_HANDLE_VALUE;
	do {
		if (lstrcmpiW(pe32.szExeFile, processImageName) == 0)
		{
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			break;
		}
	} while (Process32Next(hSnap, &pe32));

	CloseHandle(hSnap);
	return hProcess;
}


