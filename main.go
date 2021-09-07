package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"time"

	bpf "github.com/iovisor/gobpf/elf"
)

type rcvEvent struct {
	Sport uint16
	Dport uint16
	Saddr uint32
	Daddr uint32
	Rtt   uint32
}

func main() {
	m := bpf.NewModule("./rtt.o")
	defer m.Close()

	if err := m.Load(nil); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load program: %v\n", err)
		os.Exit(1)
	}

	kChan := m.IterKprobes()
	for kprobe := range kChan {
		fmt.Printf("kprobe: %v\n", kprobe)
	}

	mChan := m.IterMaps()
	for bpfMap := range mChan {
		fmt.Printf("kprobe: %v\n", bpfMap.Name)
	}

	if err := m.EnableKprobe("kprobe/tcp_set_state", -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to enable kprobe: %v\n", err)
		os.Exit(1)
	}

	rcvChan := make(chan []byte)
	pmap, err := bpf.InitPerfMap(m, "tcp_rcv_event", rcvChan, nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	pmap.PollStart()
	defer pmap.PollStop()
	time.Sleep(2 * time.Second)
	go func() {
		var event rcvEvent
		for {
			data := <-rcvChan
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				if err != io.EOF {
					fmt.Printf("failed to decode received data: %s\n", err)
				}
				continue
			}
			fmt.Printf("src: %s:%d, => dst: %s:%d RTT: %s\n", toIP(event.Saddr).String(), event.Sport, toIP(event.Daddr).String(), event.Dport, time.Duration(event.Rtt))
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	<-sig
}

func toIP(addr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, addr)
	return ip
}
