$(notdir $(shell pwd)): main.c
	gcc -no-pie -z execstack -fno-stack-protector -o $@ $^ 
