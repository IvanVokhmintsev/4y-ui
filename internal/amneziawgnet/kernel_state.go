package amneziawgnet

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
)

// kernelInbound is one amneziawg kernel interface whose cleartext TCP/UDP
// is redirected back into this process and then into Xray's SOCKS inbound.
type kernelInbound struct {
	name     string
	port     int
	ln       net.Listener
	udp      *net.UDPConn
	peers    atomic.Pointer[PeerIndex]
	relay    SocksRelay
	udpRelay *UDPRelay
	stop     chan struct{}
	wg       sync.WaitGroup
}

func (k *kernelInbound) lookup(addr netip.Addr) (amneziawg.Peer, bool) {
	peers := k.peers.Load()
	if peers == nil {
		return amneziawg.Peer{}, false
	}
	return peers.Lookup(addr)
}

func (k *kernelInbound) stopSockets() {
	if k.stop != nil {
		select {
		case <-k.stop:
		default:
			close(k.stop)
		}
	}
	if k.ln != nil {
		_ = k.ln.Close()
	}
	if k.udp != nil {
		_ = k.udp.Close()
	}
	if k.udpRelay != nil {
		k.udpRelay.Close()
	}
	k.wg.Wait()
}

func (k *kernelInbound) close() {
	k.stopSockets()
	_ = kernelLinkDel(k.name)
	_ = kernelNFTRemove(k.name)
}
