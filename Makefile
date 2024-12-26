PYSRCS = $(shell find src -type f -name '*.py')
CSRCS  = $(shell find src -type f -name '*.c')

all:
	./scripts/root.sh

glibc:
	./scripts/glibc.sh

qemu:
	./scripts/qemu.sh dist/bzImage

format:
	clang-format -i -style=file $(CSRCS)
	black $(PYSRCS)

.PHONY: qemu glibc format
