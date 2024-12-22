main.elf: *.c
	gcc -o $@ $^

run:
	@LD_LIBRARY_PATH=../../glibc-2.40/build ./main.elf 1983

.PHONY: run
