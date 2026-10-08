//go:build !linux

package host

import (
	"errors"
	"net"
)

func proveSQLPeer(net.Conn, int) error { return errors.New("linux SQL peer evidence required") }
