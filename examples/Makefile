clean:
	-$(RM) kprobe_example.c
build:
	clang-10 -O2 -g -Wall -Werror -emit-llvm -c kprobe_example.c -o - | llc-10 -march=bpf -mcpu=probe -filetype=obj -o kprobe_example
