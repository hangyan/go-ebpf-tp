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

	fmt.Println("attach tracepoints...")

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("read events map error")
	}

	for {
		ev, err := rd.Read()
		if err != nil {
			log.Fatalf("read fail")
		}

		if ev.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", ev.LostSamples)
			continue
		}

		b_arr := bytes.NewBuffer(ev.RawSample)
		var dt data
		if err := binary.Read(b_arr, binary.LittleEndian, &dt); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		var bsport = make([]byte, 2)
		var bdport = make([]byte, 2)
		binary.BigEndian.PutUint16(bsport, dt.SPort)
		binary.BigEndian.PutUint16(bdport, dt.DPort)

		godata := gdata{
			Proto: uint(dt.Proto),
			SPort: uint(binary.LittleEndian.Uint16(bsport)),
			DPort: uint(binary.LittleEndian.Uint16(bdport)),
		}

		var LeSAddr = make([]byte, 4)
		var LeDAddr = make([]byte, 4)

		binary.LittleEndian.PutUint32(LeSAddr, dt.SAddr)
		binary.LittleEndian.PutUint32(LeDAddr, dt.DAddr)
		godata.SAddr = net.IP.String(LeSAddr)
		godata.DAddr = net.IP.String(LeDAddr)

		fmt.Fprintf(os.Stdout, "(proto: %d) %s (%d) => %s (%d)\n",
			godata.Proto,
			godata.SAddr, godata.SPort,
			godata.DAddr, godata.DPort)

	}

}
