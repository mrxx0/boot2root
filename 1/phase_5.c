
#include <stdio.h>
#include <string.h>

void phase_5(char *line) 
{
    if (strlen(line) != 6)
	{
		printf("Bad length\n");
		return ;
	}
	int i = 0;
    char *string = "isrveawhobpnutfg";
    while (i < 6) {
        line[i] = string[line[i] & 0xf];
		printf("%s\n", line);
        i++;
    }
		printf("\n%s\n", line);
	if (strcmp(line, "giants") != 0)
	{
		printf("Bad input\n");
		return;
    }
    return;
}

int main(int argc, char **argv)
{
	if (argc != 2)
		return (0);
	phase_5(argv[1]);
}
