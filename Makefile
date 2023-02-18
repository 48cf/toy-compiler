K_FILES=$(shell find src -name '*.k')

.PHONY: all clean

all: out/bootstrap out/selfhost1 out/selfhost2

clean:
	rm -rf out

out/bootstrap: bootstrap.c
	@mkdir -p $(@D)
	$(CC) -std=gnu11 -Werror -Wextra -g -o $@ $<

out/selfhost1: out/bootstrap $(K_FILES)
	@mkdir -p $(@D)
	$< src/main.k $@

out/selfhost2: out/selfhost1 $(K_FILES)
	@mkdir -p $(@D)
	$< src/main.k $@
