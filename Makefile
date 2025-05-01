BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
BPF_HEADERS ?= /usr/include
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I$(BPF_HEADERS)
LIBBPF_DIR = /usr/include/bpf
LIBBPF_OBJ = -lbpf

all: vmlinux.h netmon

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

netmon.bpf.o: netmon.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

netmon.skel.h: netmon.bpf.o
	bpftool gen skeleton $< > $@

netmon: netmon.c netmon.skel.h
	$(CC) -g -O2 -o $@ netmon.c $(LIBBPF_OBJ) -lelf -lz

test: netmon
	sudo strace ./netmon

clean:
	rm -f netmon netmon.bpf.o netmon.skel.h vmlinux.h

