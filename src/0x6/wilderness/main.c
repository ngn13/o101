#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

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

  struct malloc_chunk *wilderness_chunk = NULL;
  uint64_t             mem_size         = 16;
  char                *mem              = NULL;

  mem = malloc(mem_size);
  printf("malloc(%lu) = %p\n", mem_size, mem);

  printf("wilderness_chunk = %p\n", (wilderness_chunk = (void *)(mem + mem_size)));
  printf("wilderness_chunk->mchunk_size = %lu\n", wilderness_chunk->mchunk_size);

  mem = malloc(mem_size);
  printf("malloc(%lu) = %p\n", mem_size, mem);

  printf("wilderness_chunk = %p\n", (wilderness_chunk = (void *)(mem + mem_size)));
  printf("wilderness_chunk->mchunk_size = %lu\n", wilderness_chunk->mchunk_size);

  mem_size = 4096 - 16;

  while (wilderness_chunk->mchunk_size > mem_size) {
    mem = malloc(mem_size);
    printf("malloc(%lu) = %p\n", mem_size, mem);

    printf("wilderness_chunk = %p\n", (wilderness_chunk = (void *)(mem + mem_size)));
    printf("wilderness_chunk->mchunk_size = %lu\n", wilderness_chunk->mchunk_size);
  }

  mem = malloc(mem_size);
  printf("malloc(%lu) = %p\n", mem_size, mem);

  printf("wilderness_chunk = %p\n", (wilderness_chunk = (void *)(mem + mem_size)));
  printf("wilderness_chunk->mchunk_size = %lu\n", wilderness_chunk->mchunk_size);

  return EXIT_SUCCESS;
}
