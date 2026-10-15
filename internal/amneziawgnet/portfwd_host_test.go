package amneziawgnet

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestHostDialReachesThePeerAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
		close(accepted)
	}()

	ap, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialForwardTCP(ctx, true, nil, ap.Addr(), int(ap.Port()))
	if err != nil {
		t.Fatalf("dialForwardTCP: %v", err)
	}
	conn.Close()
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("peer listener did not accept the host dial")
	}
}
