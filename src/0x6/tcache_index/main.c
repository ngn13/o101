#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

int main() {
  void    *a = NULL, *b = NULL;
  uint64_t size = 16;

  for (; size < 64 * 18; size += 16) {
    a = malloc(size);
    printf("(a) malloc(%lu) = %p\n", size, a);

    b = malloc(size);
    printf("(b) malloc(%lu) = %p\n", size, b);

    free(a);
    printf("(a) free = %p\n", a);

    free(b);
    printf("(b) free = %p\n", b);
  }
}
