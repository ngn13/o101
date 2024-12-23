#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#define PROTECT_PTR(pos, ptr) ((__typeof(ptr))((((size_t)pos) >> 12) ^ ((size_t)ptr)))
#define REVEAL_PTR(ptr)       PROTECT_PTR(&ptr, ptr)

struct malloc_chunk {
  uint64_t mchunk_prev_size;
  uint64_t mchunk_size;

  struct malloc_chunk *fd;
  struct malloc_chunk *bk;

  struct malloc_chunk *fd_nextsize;
  struct malloc_chunk *bk_nextsize;
};

int main() {
  setbuf(stdout, NULL);

  struct malloc_chunk *a_chunk = NULL, *b_chunk = NULL;
  void                *tcache_allocs[7];
  uint8_t              i = 0;

  for (i = 0; i < 7; i++) {
    tcache_allocs[i] = malloc(16);
    printf("malloc = %p\n", tcache_allocs[i]);
  }

  uint64_t *a = malloc(16);
  printf("(a) malloc = %p\n", a);

  uint64_t *b = malloc(16);
  printf("(b) malloc = %p\n", b);

  for (i = 0; i < 7; i++) {
    free(tcache_allocs[i]);
    printf("free = %p\n", tcache_allocs[i]);
  }

  free(b);
  printf("(b) free = %p\n", b);

  printf("b_chunk = %p (b-16)\n", b_chunk = (void *)(b - 2));
  printf("b_chunk->fd = %p (%p)\n", b_chunk->fd, REVEAL_PTR(b_chunk->fd));
  printf("b_chunk->bk = %p\n", b_chunk->bk);
  printf("b_chunk->fd_nextsize = %p\n", b_chunk->fd_nextsize);
  printf("b_chunk->bk_nextsize = %p\n", b_chunk->bk_nextsize);

  free(a);
  printf("(a) free = %p\n", a);

  printf("a_chunk = %p (a-16)\n", a_chunk = (void *)(a - 2));
  printf("a_chunk->fd = %p (%p)\n", a_chunk->fd, REVEAL_PTR(a_chunk->fd));
  printf("a_chunk->bk = %p\n", a_chunk->bk);
  printf("a_chunk->fd_nextsize = %p\n", a_chunk->fd_nextsize);
  printf("a_chunk->bk_nextsize = %p\n", a_chunk->bk_nextsize);

  printf("b_chunk = %p (b-16)\n", b_chunk);
  printf("b_chunk->fd = %p (%p)\n", b_chunk->fd, REVEAL_PTR(b_chunk->fd));
  printf("b_chunk->bk = %p\n", b_chunk->bk);
  printf("b_chunk->fd_nextsize = %p\n", b_chunk->fd_nextsize);
  printf("b_chunk->bk_nextsize = %p\n", b_chunk->bk_nextsize);

  return EXIT_SUCCESS;
}
