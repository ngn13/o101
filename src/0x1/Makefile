$(notdir $(shell pwd)).elf: main.c
	gcc -no-pie -z execstack -fno-stack-protector -o $@ $^
