#include <string.h>
#include <stdio.h>

void cant_get_here() {
  puts("How did we get here?");
}

int main() {
  char overflow[32];

  puts("Hello, what's your name?");

  // !! OVERFLOW HERE !!
  scanf("%s", overflow);

  printf("Nice to meet you %s!\n", overflow);
  return 0;
}
