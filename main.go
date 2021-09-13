package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang  flowsnoop ./c/flowsnoop-count.bpf.c -- -I. -fno-jump-tables
import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/spf13/cast"
	"golang.org/x/sys/unix"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

type data struct {
	ID    uint32
	SAddr uint32
	DAddr uint32
	SPort uint16
	DPort uint16
	Proto uint8
}

type gdata struct {
	ID    uint
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

func secound(objs *flowsnoopObjects, ip *string) {
	time.Sleep(5 * time.Second)
	k := uint32(2)
	value := cast.ToUint32("0x" + Pack32BinaryIP4(*ip))
	if err := objs.ConfigMap.Update(k, value, 0); err != nil {
		log.Fatalf("add another filter error: %s", err.Error())
	}

}

func mark_index(objs *flowsnoopObjects, min uint32, count uint32) {
	k := uint32(0)
	if err := objs.Count.Update(k, min, 0); err != nil {
		log.Fatalf("update map index error: %s", err.Error())
	}
	k = uint32(1)
	if err := objs.Count.Update(k, count, 0); err != nil {
		log.Fatalf("update map index error: %s", err.Error())
	}

}

func main() {

	// parse args
	idPtr := flag.Int("id", 1, "give this program an id")
	ip := flag.String("ip", "127.0.0.1", "filter by this ip")
	flag.Parse()

	id := *idPtr
	k := uint32(id)
	value := cast.ToUint32("0x" + Pack32BinaryIP4("127.0.0.1"))
	log.Printf("k: %d, v: %s\n", k, *ip)

	setlimit()

	var events *ebpf.Map

	// load this program.
	objs := flowsnoopObjects{}
	err := loadFlowsnoopObjects(&objs, nil)
	if err != nil {
		panic(err)
	}

	err = objs.ConfigMap.Update(k, value, 0)
	if err != nil {
		panic(err)
	}
	mark_index(&objs, 1, 1)

	events = objs.Events

	_, err = link.Tracepoint("net", "netif_receive_skb", objs.TracepointNetNetifReceiveSkb)
	if err != nil {
		panic(err)
	}
	_, err = link.Tracepoint("net", "net_dev_start_xmit", objs.TracepointNetNetDevStartXmit)
	if err != nil {
		panic(err)
	}

	fmt.Println("attach tracepoints...")
	mark_index(&objs, 1, 2)
	go secound(&objs, ip)

	rd, err := perf.NewReader(events, os.Getpagesize())
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
			ID:    uint(dt.ID),
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

		fmt.Fprintf(os.Stdout, "[%d](proto: %d) %s (%d) => %s (%d)\n",
			godata.ID,
			godata.Proto,
			godata.SAddr, godata.SPort,
			godata.DAddr, godata.DPort)

	}

}
