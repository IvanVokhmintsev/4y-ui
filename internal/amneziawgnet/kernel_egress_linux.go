//go:build linux

package amneziawgnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func dialKernel(ctx context.Context, network string, k kernelEgress, dest netip.AddrPort) (net.Conn, error) {
	d := net.Dialer{Control: bindDevice(k.ifname), Timeout: portForwardDialTimeout}
	if ip := localFor(k.addrs, dest.Addr()); ip != nil {
		if strings.HasPrefix(network, "tcp") {
			d.LocalAddr = &net.TCPAddr{IP: ip}
		} else {
			d.LocalAddr = &net.UDPAddr{IP: ip}
		}
	}
	return d.DialContext(ctx, network, dest.String())
}

func bindDevice(ifname string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifname)
		}); err != nil {
			return err
		}
		return sockErr
	}
}

func localFor(addrs []netip.Addr, dest netip.Addr) net.IP {
	for _, addr := range addrs {
		if dest.Is4() && addr.Is4() {
			return addr.AsSlice()
		}
		if dest.Is6() && addr.Is6() {
			return addr.AsSlice()
		}
	}
	return nil
}

func kernelResolve(ctx context.Context, k kernelEgress, dnsServer, host string) (netip.Addr, error) {
	ap, err := netip.ParseAddrPort(dnsServer)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("dns %q: %w", dnsServer, err)
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialKernel(ctx, "udp", k, ap)
		},
	}
	ips, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if ok && tunnelSupportsAddr(k.addrs, addr) {
			return addr.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("dns %s returned no usable address", host)
}
