package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb lb.c

import (
	"log"
	"net"
	"flag"
	"os"
	"context"
	"os/signal"
	"syscall"
	"fmt"
	"encoding/binary"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var (
    ifname       string
    backendOneIP string
    //backendTwoIP string
)

func parseIPv4(s string) (uint32, error) {
    ip := net.ParseIP(s).To4()
    if ip == nil {
        return 0, fmt.Errorf("invalid IPv4: %s", s)
    }
    return binary.LittleEndian.Uint32(ip), nil
}

func main() {
	flag.StringVar(&ifname, "i", "lo", "Network interface to attach eBPF programs")
	flag.StringVar(&backendOneIP, "b-ip1", "", "IP address of backend #1")
	//flag.StringVar(&backendTwoIP, "b-ip2", "", "IP address of backend #2")
	flag.Parse()
 
	// TODO: add second backend
	if backendOneIP == "" {
		fmt.Fprintf(os.Stderr, "Error: missing required backend flags\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Signal handling / context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs lbObjects
	if err := loadLbObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	back_ip, err := parseIPv4(backendOneIP)
        if err != nil {
                log.Fatal(err)
        }

    	back_ep := lbEndpoint{
		Ip:  back_ip,
    	}
	if err := objs.lbMaps.Backends.Put(uint32(0), &back_ep); err != nil {
                log.Fatalf("Error adding Load Balancers' endpoint to eBPF Map: %s", err)
        }

	// Attach XDP program to the network interface.
	xdplink, err := link.AttachXDP(link.XDPOptions{
				Program:   objs.XdpLoadBalancer,
				Interface: iface.Index,
				Flags: link.XDPGenericMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdplink.Close()
	log.Println("XDP program successfully attached. Press Enter to exit.")

	// Wait for SIGINT/SIGTERM (Ctrl+C) before exiting
	<-ctx.Done()
	log.Println("Received signal, exiting...")
}
