// Configure only two reserved loopback addresses inside the network-none fixture.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func main() {
	marker, err := os.ReadFile("/etc/cloud8021x-task11-fixture")
	if err != nil || string(marker) != "synthetic-only-v1\n" {
		panic("synthetic guest marker required")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	if len(interfaces) != 1 || interfaces[0].Name != "lo" {
		panic("network-none loopback-only fixture required")
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		panic(err)
	}
	defer func() { _ = unix.Close(fd) }()
	for index, address := range []string{"10.203.11.10", "169.254.169.254"} {
		ip := net.ParseIP(address).To4()
		body := make([]byte, 8)
		body[0] = unix.AF_INET
		body[1] = 32
		body[3] = unix.RT_SCOPE_HOST
		binary.NativeEndian.PutUint32(body[4:], uint32(interfaces[0].Index))
		for _, kind := range []uint16{unix.IFA_LOCAL, unix.IFA_ADDRESS} {
			attr := make([]byte, 8)
			binary.NativeEndian.PutUint16(attr, 8)
			binary.NativeEndian.PutUint16(attr[2:], kind)
			copy(attr[4:], ip)
			body = append(body, attr...)
		}
		message := make([]byte, 16)
		binary.NativeEndian.PutUint32(message, uint32(16+len(body)))
		binary.NativeEndian.PutUint16(message[4:], unix.RTM_NEWADDR)
		binary.NativeEndian.PutUint16(message[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
		binary.NativeEndian.PutUint32(message[8:], uint32(index+1))
		message = append(message, body...)
		if err = unix.Sendto(fd, message, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
			panic(err)
		}
		reply := make([]byte, 4096)
		n, _, err := unix.Recvfrom(fd, reply, 0)
		if err != nil || n < 20 {
			panic("netlink acknowledgement unavailable")
		}
		if binary.NativeEndian.Uint16(reply[4:]) != unix.NLMSG_ERROR || int32(binary.NativeEndian.Uint32(reply[16:])) != 0 {
			panic("loopback setup refused")
		}
	}
	addresses, err := interfaces[0].Addrs()
	if err != nil {
		panic(err)
	}
	for _, address := range addresses {
		fmt.Println(address.String())
	}
}
