package amneziawgnet

import (
	"context"
	"net"
	"net/netip"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// kernelEgress is one kernel client interface the SOCKS egress server dials
// through, bound to that link so Xray still owns routing and stats.
type kernelEgress struct {
	ifname string
	addrs  []netip.Addr
}

// SetKernel registers the kernel interface backing an outbound tag.
func (s *socks5EgressServer) SetKernel(tag, ifname string, addrs []netip.Addr, dnsServer ...string) {
	norm := ""
	if len(dnsServer) > 0 && dnsServer[0] != "" {
		norm = amneziawg.NormalizeDNSServer(dnsServer[0])
	}
	s.mu.Lock()
	if s.kernels == nil {
		s.kernels = map[string]kernelEgress{}
	}
	delete(s.stacks, tag)
	s.kernels[tag] = kernelEgress{ifname: ifname, addrs: addrs}
	prev := s.dns[tag]
	if norm != "" {
		s.dns[tag] = norm
	} else {
		delete(s.dns, tag)
	}
	s.mu.Unlock()
	if prev != norm {
		flushTunnelDNSCacheForTag(tag)
	}
}

// DeleteKernel drops a kernel outbound registration.
func (s *socks5EgressServer) DeleteKernel(tag string) {
	s.mu.Lock()
	delete(s.kernels, tag)
	delete(s.dns, tag)
	s.mu.Unlock()
	flushTunnelDNSCacheForTag(tag)
}

func (s *socks5EgressServer) kernelFor(tag string) (kernelEgress, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.kernels[tag]
	return k, ok
}

func (s *socks5EgressServer) resolveKernelTarget(tag string, k kernelEgress, t socksTarget) (netip.AddrPort, error) {
	if t.ip.IsValid() {
		if !tunnelSupportsAddr(k.addrs, t.ip) {
			return netip.AddrPort{}, errNoKernelRoute(t.ip)
		}
		return netip.AddrPortFrom(t.ip, t.port), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), tunnelResolveTimeout)
	defer cancel()
	addr, err := kernelResolve(ctx, k, s.currentDNSServer(tag), t.host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, t.port), nil
}

func errNoKernelRoute(ip netip.Addr) error {
	return &kernelRouteError{ip: ip}
}

type kernelRouteError struct{ ip netip.Addr }

func (e *kernelRouteError) Error() string {
	return "tunnel has no route for " + e.ip.String()
}

func (s *socks5EgressServer) serveKernelTCP(k kernelEgress, tag string, upstream net.Conn, target socksTarget) {
	dest, err := s.resolveKernelTarget(tag, k, target)
	if err != nil {
		logger.Warningf("amneziawgnet: egress %q: resolve %s: %v", tag, target, err)
		writeSocksReply(upstream, 0x04, netip.AddrPort{})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), portForwardDialTimeout)
	defer cancel()
	tunnel, err := dialKernel(ctx, "tcp", k, dest)
	if err != nil {
		logger.Warningf("amneziawgnet: egress %q: dial kernel %s: %v", tag, dest, err)
		writeSocksReply(upstream, 0x01, netip.AddrPort{})
		return
	}
	defer tunnel.Close()
	if _, err := upstream.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	pipeBothWays(upstream, tunnel)
}

func (s *socks5EgressServer) serveKernelUDP(k kernelEgress, tag string, ctl udpControl, target socksTarget) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		logger.Warningf("amneziawgnet: egress %q: udp bind: %v", tag, err)
		writeSocksReply(ctl.conn, 0x01, netip.AddrPort{})
		return
	}
	defer udpConn.Close()
	local := udpConn.LocalAddr().(*net.UDPAddr)
	ip4 := local.IP.To4()
	reply := []byte{0x05, 0x00, 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], byte(local.Port >> 8), byte(local.Port)}
	if _, err := ctl.conn.Write(reply); err != nil {
		return
	}
	sessions := &udpEgressSessions{m: map[netip.AddrPort]*egressUDPSession{}}
	go s.readKernelUDP(k, tag, udpConn, sessions)
	buf := make([]byte, 512)
	for {
		if _, err := ctl.conn.Read(buf); err != nil {
			sessions.closeAll()
			return
		}
	}
}

func (s *socks5EgressServer) readKernelUDP(k kernelEgress, tag string, udpConn *net.UDPConn, sessions *udpEgressSessions) {
	var client netip.AddrPort
	buf := make([]byte, 65536)
	for {
		n, from, err := udpConn.ReadFrom(buf)
		if err != nil {
			return
		}
		if src, ok := udpAddrPort(from); ok {
			if client.IsValid() && src != client {
				continue
			}
			client = src
		}
		data := buf[:n]
		if len(data) < 4 {
			continue
		}
		atyp := data[3]
		if atyp == 0x03 {
			name, port, hdrLen, perr := parseDatagramDomainHeader(data)
			if perr != nil {
				continue
			}
			go func(client netip.AddrPort, name string, port uint16, hdrLen int, datagram []byte) {
				daddr, rerr := s.resolveKernelHost(tag, k, name)
				if rerr != nil {
					logger.Warningf("amneziawgnet: egress %q: resolve udp %q: %v", tag, name, rerr)
					return
				}
				s.deliverKernelUDP(k, tag, udpConn, client, sessions, netip.AddrPortFrom(daddr, port), datagram[hdrLen:])
			}(client, name, port, hdrLen, append([]byte(nil), data...))
			continue
		}
		hdrLen := 4 + addrLen(atyp) + 2
		if hdrLen <= 6 || len(data) < hdrLen {
			continue
		}
		dst, derr := parseDatagramHeader(data[:hdrLen])
		if derr != nil {
			continue
		}
		s.deliverKernelUDP(k, tag, udpConn, client, sessions, dst, append([]byte(nil), data[hdrLen:]...))
	}
}

func (s *socks5EgressServer) resolveKernelHost(tag string, k kernelEgress, host string) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), tunnelResolveTimeout)
	defer cancel()
	return kernelResolve(ctx, k, s.currentDNSServer(tag), host)
}

func (s *socks5EgressServer) deliverKernelUDP(k kernelEgress, tag string, udpConn *net.UDPConn, client netip.AddrPort, sessions *udpEgressSessions, dst netip.AddrPort, payload []byte) {
	if !client.IsValid() {
		return
	}
	sess := sessions.dialKernel(k, tag, udpConn, client, dst)
	if sess == nil {
		return
	}
	if _, err := sess.conn.Write(payload); err != nil {
		logger.Warningf("amneziawgnet: egress %q: send udp to %s: %v", tag, dst, err)
	}
}

func (s *udpEgressSessions) dialKernel(k kernelEgress, tag string, udpConn *net.UDPConn, client, dst netip.AddrPort) *egressUDPSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.m[dst]; ok {
		return existing
	}
	if !tunnelSupportsAddr(k.addrs, dst.Addr()) {
		return nil
	}
	conn, err := dialKernel(context.Background(), "udp", k, dst)
	if err != nil {
		logger.Warningf("amneziawgnet: egress %q: dial udp %s: %v", tag, dst, err)
		return nil
	}
	sess := &egressUDPSession{dst: dst, conn: conn}
	s.m[dst] = sess
	go pumpUDPEgress(udpConn, client, sess, s)
	return sess
}
