SELFHOST_FILES=$(shell find src -name '*.k')
KERNEL_FILES=$(shell find kernel -name '*.k')

.PHONY: all clean run

all: out/bootstrap out/selfhost1 out/selfhost2

clean:
	rm -rf out

run: out/test.iso
	qemu-system-x86_64 -M q35 -m 1G -cdrom $< -boot d

run-kvm: out/test.iso
	qemu-system-x86_64 -M q35 -m 1G -cdrom $< -boot d -enable-kvm

limine:
	git clone https://github.com/limine-bootloader/limine.git --branch=v4.x-branch-binary --depth=1
	make -C limine

out/bootstrap: bootstrap.c
	@mkdir -p $(@D)
	$(CC) -std=gnu11 -Werror -Wextra -g -o $@ $<

out/selfhost1: out/bootstrap $(SELFHOST_FILES)
	@mkdir -p $(@D)
	$< src/main.k $@

# out/selfhost2: out/selfhost1 $(SELFHOST_FILES)
# 	@mkdir -p $(@D)
# 	$< src/main.k $@

out/kernel: out/bootstrap $(KERNEL_FILES)
	@mkdir -p $(@D)
	$< kernel/main.k $@

out/test.iso: limine out/kernel limine.cfg
	rm -rf out/iso_root
	mkdir -p out/iso_root
	cp out/kernel limine.cfg limine/limine.sys limine/limine-cd.bin out/iso_root
	xorriso -as mkisofs -b limine-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table out/iso_root -o $@
	limine/limine-deploy $@
	rm -rf out/iso_root
