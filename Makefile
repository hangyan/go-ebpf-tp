all: gen build

gen:
	go generate

build:
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build .

clean:
	rm -f go-ebpf-tp
	rm -f flowsnoop_bpfel.o
	rm -f flowsnoop_bpfel.go
