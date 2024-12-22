CSRCS  = $(wildcard 0x*/*.c) $(wildcard 0x*/*/*.c)
PYSRCS = $(wildcard solves/*.py)

format:
	clang-format -i -style=file $(CSRCS)
	black $(PYSRCS)

.PHONY: format
