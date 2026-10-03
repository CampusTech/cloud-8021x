package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// serveServers binds every listener before serving and tears all of them down
// on cancellation or any listener/TLS failure. A partially running service is an error.
func serveServers(ctx context.Context, servers []*http.Server, certFile, keyFile string) error {
	listeners := make([]net.Listener, 0, len(servers))
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	for _, srv := range servers {
		listener, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", srv.Addr, err)
		}
		listeners = append(listeners, listener)
	}
	results := make(chan error, len(servers))
	for i, srv := range servers {
		go func() {
			err := srv.ServeTLS(listeners[i], certFile, keyFile)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				results <- fmt.Errorf("serve %s: %w", srv.Addr, err)
			} else {
				results <- nil
			}
		}()
	}
	var result error
	select {
	case <-ctx.Done():
	case result = <-results:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_ = srv.Close()
			result = errors.Join(result, err)
		}
	}
	return result
}
