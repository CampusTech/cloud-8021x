package host

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func proveSQLPeer(conn net.Conn, uid int) error {
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("local SQL peer required")
	}
	raw, e := c.SyscallConn()
	if e != nil {
		return e
	}
	var proof error
	e = raw.Control(func(fd uintptr) {
		p, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil || int(p.Uid) != uid {
			proof = errors.New("local SQL server owner differs")
		}
	})
	if e != nil {
		return e
	}
	return proof
}
