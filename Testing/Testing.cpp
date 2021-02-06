#include <Windows.h>

int add(int a, int b)
{
	int result = a + b;
	return result;
}

int main()
{
	//Question: How does linker resolve the add function call?
	//How does it compute the address for the function?

	::GetCurrentProcess();

	int a = 1, b = 2;
	int c = add(a, b);

	return 0;
}