#include <iostream>
#include <Windows.h>
#include <ProcessEnv.h>
#include <ConsoleApi2.h>
#include <ConsoleApi3.h>
#include <chrono>
#include <thread>

int main()
{
	::SetConsoleTextAttribute(::GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_GREEN);
	std::wcout << L"Starting infinite echo!\n";

	//Load a dummy dll, most programs will have at least one dll loaded already
	//This way we can test injector rebasing - note that this dll was compiled w/ the DYNAMICBASE flag off to force the dll to load at default dll image base 0x10000000
	HMODULE hMod = ::LoadLibraryA("C:\\Users\\Anirudh\\source\\repos\\ManualMapping\\Debug\\DummyDll.dll");
	if (hMod == INVALID_HANDLE_VALUE || hMod == nullptr)
		return 1;

	while (true)
	{
		using namespace std::literals::chrono_literals;
		std::wcout << L"Echo!\n";
		std::this_thread::sleep_for(2000ms);
	}
}
