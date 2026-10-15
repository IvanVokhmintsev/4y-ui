//go:build linux

package amneziawgnet

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

type recordRunner struct {
	cmds  []string
	files map[string]string
}

func (r *recordRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.cmds = append(r.cmds, name+" "+strings.Join(args, " "))
	if r.files == nil {
		r.files = map[string]string{}
	}
	if name == "awg" && len(args) >= 3 && args[0] == "syncconf" {
		body, err := os.ReadFile(args[2])
		if err != nil {
			return nil, err
		}
		r.files[args[1]] = string(body)
	}
	if name == "nft" && len(args) == 2 && args[0] == "-f" {
		body, err := os.ReadFile(args[1])
		if err != nil {
			return nil, err
		}
		r.files["nft"] = string(body)
	}
	return nil, nil
}

func (r *recordRunner) countPrefix(prefix string) int {
	n := 0
	for _, cmd := range r.cmds {
		if strings.HasPrefix(cmd, prefix) {
			n++
		}
	}
	return n
}

func TestKernelEnsureSyncsLinkAndAttributesTCP(t *testing.T) {
	prev := runCmd
	rec := &recordRunner{}
	runCmd = rec
	t.Cleanup(func() {
		kernelRelayHook = nil
		runCmd = prev
	})

	priv, _, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, pub, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	inst := amneziawg.Instance{
		Id: 4242, InterfaceName: "awg4242", ListenPort: 51820,
		PrivateKey: priv, Address: []string{"10.8.1.1/24"},
		Peers: []amneziawg.Peer{{
			Email: "a@x", PublicKey: pub, AllowedIPs: []string{"127.0.0.1/32"},
		}},
	}
	m := &Manager{ifaces: map[int]*managed{}}
	if err := m.ensureKernelLocked(Desired{Instance: inst}); err != nil {
		t.Fatalf("ensureKernelLocked: %v", err)
	}
	t.Cleanup(func() { m.Remove(inst.Id) })

	joined := strings.Join(rec.cmds, "\n")
	for _, want := range []string{
		"ip link add dev awg4242 type amneziawg",
		"ip addr replace 10.8.1.1/24 dev awg4242",
		"awg syncconf awg4242 ",
		"ip link set dev awg4242 mtu ",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("commands missing %q:\n%s", want, joined)
		}
	}
	if !strings.Contains(rec.files["awg4242"], "PublicKey = "+pub) {
		t.Fatalf("syncconf file = %s", rec.files["awg4242"])
	}
	if !strings.Contains(rec.files["nft"], `iifname "awg4242"`) || !strings.Contains(rec.files["nft"], "redirect to :") {
		t.Fatalf("nft = %s", rec.files["nft"])
	}

	syncs := rec.countPrefix("awg syncconf")
	if err := m.ensureKernelLocked(Desired{Instance: inst}); err != nil {
		t.Fatal(err)
	}
	if got := rec.countPrefix("awg syncconf"); got != syncs {
		t.Fatalf("unchanged ensure ran syncconf (%d -> %d)", syncs, got)
	}

	kern := m.ifaces[inst.Id].kern
	got := make(chan string, 1)
	kernelRelayHook = func(email string, dst netip.AddrPort) {
		if int(dst.Port()) != kern.port {
			t.Errorf("original dest port = %d, want %d", dst.Port(), kern.port)
		}
		got <- email
	}
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(kern.port)))
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	select {
	case email := <-got:
		if email != "a@x" {
			t.Fatalf("attributed %q", email)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("kernel relay did not attribute the connection")
	}
	conn.Close()

	udpGot := make(chan string, 1)
	kernelUDPHook = func(email string, dst netip.AddrPort) {
		if int(dst.Port()) != kern.port {
			t.Errorf("udp original dest port = %d, want %d", dst.Port(), kern.port)
		}
		udpGot <- email
	}
	t.Cleanup(func() { kernelUDPHook = nil })
	udpConn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(kern.port)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udpConn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case email := <-udpGot:
		if email != "a@x" {
			t.Fatalf("udp attributed %q", email)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("kernel relay did not attribute the udp datagram")
	}
	udpConn.Close()

	inst.Peers[0].AllowedIPs = []string{"10.9.9.9/32"}
	if err := m.ensureKernelLocked(Desired{Instance: inst}); err != nil {
		t.Fatal(err)
	}
	kernelRelayHook = func(email string, _ netip.AddrPort) { got <- "bad:" + email }
	conn, err = net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(kern.port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case email := <-got:
		t.Fatalf("attributed %s from a source outside AllowedIPs", email)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestKernelOutboundSyncsClientConf(t *testing.T) {
	prev := runCmd
	rec := &recordRunner{}
	runCmd = rec
	t.Cleanup(func() { runCmd = prev })

	priv, _, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, pub, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	tag := "awg-out-test"
	t.Cleanup(func() { GetEgressServer().DeleteKernel(tag) })
	m := &OutboundManager{iface: map[string]*managedOutbound{}}
	err = m.ensureKernelOutbound(OutboundDesired{Instance: amneziawg.OutboundInstance{
		Tag: tag, Address: []string{"10.9.0.2/32"}, PrivateKey: priv,
		Peers: []amneziawg.OutboundPeer{{
			PublicKey: pub, Endpoint: "203.0.113.10:51820",
			AllowedIPs: []string{"0.0.0.0/0"}, KeepAlive: 25,
		}},
	}})
	if err != nil {
		t.Fatalf("ensureKernelOutbound: %v", err)
	}
	t.Cleanup(func() { m.Remove(tag) })
	name, err := kernelOutboundName(tag)
	if err != nil {
		t.Fatal(err)
	}
	body := rec.files[name]
	if !strings.Contains(body, "Endpoint = 203.0.113.10:51820") || !strings.Contains(body, "PersistentKeepalive = 25") {
		t.Fatalf("client syncconf = %s", body)
	}
	k, ok := GetEgressServer().kernelFor(tag)
	if !ok || k.ifname != name {
		t.Fatalf("kernel egress = %+v ok=%v, want %s", k, ok, name)
	}
}
