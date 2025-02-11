#include <iostream>
#include <Windows.h>
#include <ProcessEnv.h>
#include <ConsoleApi2.h>
#include <ConsoleApi3.h>
#include <chrono>
#include <thread>

int main()
{
	//::SetConsoleTextAttribute(::GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_GREEN);
	std::wcout << L"Starting target program!\n";

	int counter = 1;

	while (true)
	{
		//using namespace std::literals::chrono_literals;
		//std::wcout << L"Echo " << counter++ << std::endl;
		//std::this_thread::sleep_for(5000ms);
	}
}
