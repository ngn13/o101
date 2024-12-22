#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#define PROTECT_PTR(pos, ptr) ((__typeof(ptr))((((size_t)pos) >> 12) ^ ((size_t)ptr)))
#define REVEAL_PTR(ptr)       PROTECT_PTR(&ptr, ptr)

int main() {
  char poison_buffer[16];
  printf("poison_buffer = %p\n", poison_buffer);

  uint64_t *a = malloc(16);
  printf("(a) malloc = %p\n", a);

  uint64_t *b = malloc(16);
  printf("(b) malloc = %p\n", b);

  free(a);
  printf("(a) free = %p\n", a);

  free(b); // b->next = a
  printf("(b) free = %p\n", b);

  printf("b->next = %p (%p)\n", b[0], REVEAL_PTR(b[0]));
  b[0] = (uint64_t)PROTECT_PTR(b, (void *)poison_buffer);
  printf("b->next = %p (%p)\n", b[0], REVEAL_PTR(b[0]));

  a = malloc(16);
  printf("malloc = %p\n", a);

  b = malloc(16);
  printf("malloc = %p\n", b);
}
