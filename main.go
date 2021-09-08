package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang flowsnoop ./c/flowsnoop.bpf.c -- -I.
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/spf13/cast"
	"golang.org/x/sys/unix"
	"log"
	"math/big"
	"net"
	"os"
)


type data struct {
	SAddr uint32
	DAddr uint32
	SPort uint16
	DPort uint16
	Proto uint8
}


type gdata struct {
	SAddr string
	DAddr string
	SPort uint
	DPort uint
	Proto uint
}

func setlimit() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}
}

// IPv4Int...
func IP4toInt(IPv4Address net.IP) int64 {
	IPv4Int := big.NewInt(0)
	IPv4Int.SetBytes(IPv4Address.To4())
	return IPv4Int.Int64()
}

//similar to Python's socket.inet_aton() function
//https://docs.python.org/3/library/socket.html#socket.inet_aton

func Pack32BinaryIP4(ip4Address string) string {
	ipv4Decimal := IP4toInt(net.ParseIP(ip4Address))

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, uint32(ipv4Decimal))

	if err != nil {
		fmt.Println("Unable to write to buffer:", err)
	}

	// present in hexadecimal format
	result := fmt.Sprintf("%x", buf.Bytes())
	return result
}

func main() {
	setlimit()

	objs := flowsnoopObjects{}
	err := loadFlowsnoopObjects(&objs, nil)
	if err != nil {
		panic(err)
	}

	value := cast.ToUint32("0x" + Pack32BinaryIP4("192.168.227.4"))
	k := uint32(1)
	err = objs.ConfigMap.Update(k, value, 0)
	if err != nil {
		panic(err)
	}

	_, err = link.Tracepoint("net", "netif_receive_skb", objs.TracepointNetNetifReceiveSkb)
	if err != nil {
		panic(err)
	}
	_, err = link.Tracepoint("net", "net_dev_start_xmit", objs.TracepointNetNetDevStartXmit)
	if err != nil {
		panic(err)
	}

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("read events map error")
	}

	for {
		ev, err := rd.Read()
		if err != nil {
			log.Fatalf("read fail")
		}

		fmt.Printf("fuck get one: %d", ev.CPU)

		if ev.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", ev.LostSamples)
			continue
		}


		b_arr := bytes.NewBuffer(ev.RawSample)
		var data data
		if err := binary.Read(b_arr, binary.LittleEndian, &data); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		fmt.Printf("On cpu %02d %s ran : %d %s\n",
			ev.CPU, data.SAddr, data.Proto, data.DAddr)

	}

}
