#include <string.h>
#include <stdio.h>

int main(){
  char overflow[32];

  puts("Hello, what's your name?");

  // !! OVERFLOW HERE !!
  gets(overflow);

  printf("Nice to meet you %s!\n", overflow);
  return 0;
}
