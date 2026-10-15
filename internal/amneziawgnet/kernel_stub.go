//go:build !linux

package amneziawgnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

func kernelToolsReady() bool { return false }

func kernelLinkDel(string) error { return nil }

func kernelNFTRemove(string) error { return nil }

func kernelDump(string) (string, error) {
	return "", fmt.Errorf("kernel amneziawg is linux-only")
}

func (m *Manager) ensureKernelLocked(Desired) error {
	return fmt.Errorf("kernel amneziawg is linux-only")
}

func (m *OutboundManager) ensureKernelOutbound(OutboundDesired) error {
	return fmt.Errorf("kernel amneziawg is linux-only")
}

func dialKernel(context.Context, string, kernelEgress, netip.AddrPort) (net.Conn, error) {
	return nil, fmt.Errorf("kernel amneziawg is linux-only")
}

func kernelResolve(context.Context, kernelEgress, string, string) (netip.Addr, error) {
	return netip.Addr{}, fmt.Errorf("kernel amneziawg is linux-only")
}
