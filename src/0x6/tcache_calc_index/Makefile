main.elf: *.c
	gcc -o $@ $^

run:
	@LD_LIBRARY_PATH=../../glibc-2.40/build ./main.elf 42

.PHONY: run
