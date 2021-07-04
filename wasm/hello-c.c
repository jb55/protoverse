#include <stdio.h>

int add(int a, int b, int c, int d)
{
	return a + b + c + d;
}

int main(int argc, const char *argv[])
{
	printf("Hello, world? %d\n", add(1,2,3,4));
	return 0;
}


