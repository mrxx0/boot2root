#include <stdlib.h>
#include <stdio.h>

int func4(int param_1)

{
  int iVar1;
  int iVar2;
  
  if (param_1 < 2) {
    iVar2 = 1;
  }
  else {
    iVar1 = func4(param_1 + -1);
    iVar2 = func4(param_1 + -2);
    iVar2 = iVar2 + iVar1;
  }
  return iVar2;
}

int main(int argc, char **argv)
{
	if (argc != 2)
		return (0);
	int param_1 = atoi(argv[1]);
	int ret = func4(param_1);

	printf("%d\n", ret);
}


