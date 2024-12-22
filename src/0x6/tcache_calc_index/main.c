#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// sysdeps/generic/malloc-size.h
#define INTERNAL_SIZE_T   size_t
#define SIZE_SZ           (sizeof(INTERNAL_SIZE_T))
#define MALLOC_ALIGNMENT  16
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)

// malloc/malloc.c
#define TCACHE_MAX_BINS 64

struct malloc_chunk {

  INTERNAL_SIZE_T mchunk_prev_size;
  INTERNAL_SIZE_T mchunk_size;

  struct malloc_chunk *fd;
  struct malloc_chunk *bk;

  struct malloc_chunk *fd_nextsize;
  struct malloc_chunk *bk_nextsize;
};

#define MIN_CHUNK_SIZE (offsetof(struct malloc_chunk, fd_nextsize))
#define MINSIZE        (unsigned long)(((MIN_CHUNK_SIZE + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))
#define request2size(req)                                                                                              \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE) ? MINSIZE                                                           \
                                                   : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
#define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
#define usize2tidx(x) csize2tidx(request2size(x))

int main(int argc, char *argv[]) {
  if (argc != 2)
    return EXIT_FAILURE;

  int64_t size = 1, indx = 0, prev_indx = -1;
  int64_t arg_size   = atol(argv[1]);
  int64_t found_indx = usize2tidx(arg_size);

  printf("index = %ld (size = %ld)\n", found_indx, arg_size);

  while (indx < TCACHE_MAX_BINS) {
    if (prev_indx != (indx = usize2tidx(size)) && indx != 0) {
      if (found_indx == prev_indx)
        printf(">>> index = %ld\tmax size = %ld\n", prev_indx, size - 1);
      else
        printf("    index = %ld\tmax size = %ld\n", prev_indx, size - 1);
    }

    prev_indx = indx;
    size++;
  }

  return EXIT_SUCCESS;
}
