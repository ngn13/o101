#include <string.h>
#include <stdio.h>

int main(){
  char name[40], answer[16];

  puts("Hello, what's your name?");
  scanf("%s", name);

  printf(name);
  printf("? [yes/no]\n");

  scanf("%s", answer);
  if(strcmp(answer, "yes")==0)
    printf("Nice to meet you %s!\n", name);

  return 0;
}
