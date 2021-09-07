project_root=.
uname=$(shell uname -r)
kernel_src ?= /usr/src/linux-headers-5.4.128

all: build copy

build:
	clang \
      -D__KERNEL__ \
      -D__ASM_SYSREG_H \
      -Wno-address-of-packed-member \
      -O2 -emit-llvm -c trace.c \
      -I $(project_root)/common/bpf \
      -I $(kernel_src)/arch/x86/include \
      -I $(kernel_src)/arch/x86/include/generated \
      -I $(kernel_src)/include \
      -o - | \
      llc -march=bpf -filetype=obj -o trace.o

copy:
	go run $(project_root)/scripts/bin_data.go -pkg socket socket.o socket.o > bin_data.go
	mv bin_data.go ..

.PHONY: all build copy
