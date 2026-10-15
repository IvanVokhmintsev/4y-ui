//go:build linux

package amneziawgnet

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// kernelRelayHook, when set, records a decapsulated TCP flow instead of
// dialing SOCKS. Production leaves it nil; tests set it.
var kernelRelayHook func(email string, dst netip.AddrPort)

// kernelUDPHook is the UDP counterpart of kernelRelayHook.
var kernelUDPHook func(email string, dst netip.AddrPort)

func (k *kernelInbound) serve() error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", ":0")
	if err != nil {
		ln, err = lc.Listen(context.Background(), "tcp", "0.0.0.0:0")
		if err != nil {
			return fmt.Errorf("amneziawgnet: kernel relay listen: %w", err)
		}
	}
	port := ln.Addr().(*net.TCPAddr).Port
	pc, err := lc.ListenPacket(context.Background(), "udp", fmt.Sprintf(":%d", port))
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("amneziawgnet: kernel udp relay listen: %w", err)
	}
	udp, ok := pc.(*net.UDPConn)
	if !ok {
		_ = ln.Close()
		_ = pc.Close()
		return fmt.Errorf("amneziawgnet: kernel udp relay listen: unexpected %T", pc)
	}
	k.ln = ln
	k.udp = udp
	k.port = port
	k.wg.Add(2)
	go k.acceptTCP()
	go k.readUDP()
	return nil
}

func (k *kernelInbound) acceptTCP() {
	defer k.wg.Done()
	for {
		conn, err := k.ln.Accept()
		if err != nil {
			return
		}
		go k.handleTCP(conn)
	}
}

func (k *kernelInbound) handleTCP(conn net.Conn) {
	defer conn.Close()
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	dst, err := originalTCPDest(tcp)
	if err != nil {
		logger.Warningf("amneziawgnet: kernel relay: original dest: %v", err)
		return
	}
	src, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return
	}
	peer, ok := k.lookup(src.Addr().Unmap())
	if !ok {
		return
	}
	if kernelRelayHook != nil {
		kernelRelayHook(peer.Email, dst)
		return
	}
	k.relay.RelayTCP(conn, peer.Email, dst)
}

func (k *kernelInbound) readUDP() {
	defer k.wg.Done()
	raw, err := k.udp.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVORIGDSTADDR, 1)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
	})
	buf := make([]byte, 65535)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofSockaddrInet6))
	for {
		n, oobn, _, addr, err := k.udp.ReadMsgUDP(buf, oob)
		if err != nil {
			return
		}
		if addr == nil {
			continue
		}
		src := addr.AddrPort()
		dst, ok := origDstFromOOB(oob[:oobn])
		if !ok {
			continue
		}
		peer, ok := k.lookup(src.Addr().Unmap())
		if !ok {
			continue
		}
		if kernelUDPHook != nil {
			kernelUDPHook(peer.Email, dst)
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		k.udpRelay.Handle(src, dst, peer.Email, payload)
	}
}

func (k *kernelInbound) writeUDPReply(_, to netip.AddrPort, payload []byte) error {
	if k.udp == nil {
		return net.ErrClosed
	}
	_, err := k.udp.WriteTo(payload, net.UDPAddrFromAddrPort(to))
	return err
}

func originalTCPDest(conn *net.TCPConn) (netip.AddrPort, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var dst netip.AddrPort
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		dst, sockErr = getsockoptOrigDst(int(fd))
	}); err != nil {
		return netip.AddrPort{}, err
	}
	return dst, sockErr
}

func getsockoptOrigDst(fd int) (netip.AddrPort, error) {
	var sa unix.RawSockaddrAny
	var last error
	for _, level := range []int{unix.IPPROTO_IP, unix.IPPROTO_IPV6} {
		slen := uint32(unix.SizeofSockaddrAny)
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), 80,
			uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&slen)), 0)
		if errno != 0 {
			last = errno
			continue
		}
		return addrPortFromRaw(&sa)
	}
	if last == nil {
		last = unix.ENOTCONN
	}
	return netip.AddrPort{}, last
}

func addrPortFromRaw(sa *unix.RawSockaddrAny) (netip.AddrPort, error) {
	raw := unsafe.Slice((*byte)(unsafe.Pointer(sa)), unix.SizeofSockaddrAny)
	family := binary.LittleEndian.Uint16(raw[:2])
	switch family {
	case unix.AF_INET:
		port := binary.BigEndian.Uint16(raw[2:4])
		var ip [4]byte
		copy(ip[:], raw[4:8])
		return netip.AddrPortFrom(netip.AddrFrom4(ip), port), nil
	case unix.AF_INET6:
		port := binary.BigEndian.Uint16(raw[2:4])
		var ip [16]byte
		copy(ip[:], raw[8:24])
		return netip.AddrPortFrom(netip.AddrFrom16(ip), port), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported sockaddr family %d", family)
	}
}

func sockaddrToAddrPort(sa unix.Sockaddr) (netip.AddrPort, bool) {
	switch v := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(v.Addr), uint16(v.Port)), true
	case *unix.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(v.Addr), uint16(v.Port)), true
	default:
		return netip.AddrPort{}, false
	}
}

func origDstFromOOB(oob []byte) (netip.AddrPort, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, false
	}
	for i := range msgs {
		sa, err := unix.ParseOrigDstAddr(&msgs[i])
		if err != nil {
			continue
		}
		if ap, ok := sockaddrToAddrPort(sa); ok {
			return ap, true
		}
	}
	return netip.AddrPort{}, false
}
