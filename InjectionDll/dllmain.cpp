// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

BOOL APIENTRY DllMain(HMODULE hModule,
					DWORD  ul_reason_for_call,
					LPVOID lpReserved
					)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	{
		::MessageBoxW(::GetConsoleWindow(), L"The dll has been succesfully injected into this program", L"Injection successful", MB_OKCANCEL | MB_ICONEXCLAMATION);
		break;
	}
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

