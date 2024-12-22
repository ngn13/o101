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

void print_mchunK_size(struct malloc_chunk *chunk) {
  if (chunk->mchunk_size & 1)
    printf("%lu (PREV_INUSE)\n", chunk->mchunk_size);
  else
    printf("%lu\n", chunk->mchunk_size);
}

int main(int argc, char *argv[]) {
  setbuf(stdout, NULL);

  if (argc != 2)
    return EXIT_FAILURE;

  struct malloc_chunk *a_chunk = NULL, *b_chunk = NULL;
  int64_t              alloc_size = atol(argv[1]);
  printf("alloc_size = %ld\n", alloc_size);

  uint64_t *a = malloc(alloc_size);
  printf("(a) malloc = %p\n", a);

  uint64_t *b = malloc(alloc_size);
  printf("(b) malloc = %p\n", b);

  free(a);

  a_chunk = (void *)(a - 2);
  printf("a_chunk = %p (a-16)\n", a_chunk);

  b_chunk = (void *)(b - 2);
  printf("b_chunk = %p (b-16)\n", b_chunk);

  printf("a_chunk->mchunk_prev_size = %lu\n", a_chunk->mchunk_prev_size);
  printf("a_chunk->mchunk_size = ");
  print_mchunK_size(a_chunk);

  printf("b_chunk->mchunk_prev_size = %lu\n", b_chunk->mchunk_prev_size);
  printf("b_chunk->mchunk_size = ");
  print_mchunK_size(b_chunk);

  return EXIT_SUCCESS;
}
