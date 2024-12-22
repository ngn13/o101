#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

int main() {
  uint64_t *a = malloc(16);
  printf("malloc = %p\n", a);

  free(a);
  printf("free = %p\n", a);

  printf("a->key = %p\n", a[1]);
  a[1] = 0xdeadbeef;
  printf("a->key = %p\n", a[1]);

  free(a);
  printf("free = %p\n", a);

  printf("malloc = %p\n", malloc(16));
  printf("malloc = %p\n", malloc(16));
  printf("malloc = %p\n", malloc(16));
}
