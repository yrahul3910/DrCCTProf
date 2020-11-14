#include <stdlib.h>

int main()
{
	char* ptr = (char*) malloc(100 * sizeof(char));
	ptr[102]++;

	return 0;
}
