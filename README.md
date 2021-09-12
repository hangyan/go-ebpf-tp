# go-ebpf-tp

This project is a demo using cilium/ebpf library to build a Non-CGO go binary which will loads ebpf program at some net tracepoints.


## Tested Kernels
1. 5.2: the oldest kernel we can support 
2. 5.4: widely used for now, no btf
3. 5.8: with btf



## Cases
1. Use Map to config filter
2. Use const global vars to do filter ? 
3. use CO-RE or not 

