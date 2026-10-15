package amneziawgnet

import (
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
)

func TestBuildKernelSetconfCarriesObfuscationAndPeer(t *testing.T) {
	priv, _, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	_, pub, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	psk, _, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatalf("psk: %v", err)
	}
	inst := amneziawg.Instance{
		ListenPort: 51820,
		PrivateKey: priv,
		Obfuscation: amneziawg.Obfuscation31{
			Jc: 4, Jmin: 40, Jmax: 70, S1: 15, S2: 16, S3: 17, S4: 18,
			H1: "100-110", I1: "<b 0x1234>",
			HeaderProtectionKey:    priv,
			ContentPaddingAddition: "8-16",
			RandomTrailers:         true,
		},
		Peers: []amneziawg.Peer{{
			Email: "a@x", PublicKey: pub, PresharedKey: psk,
			AllowedIPs: []string{"10.8.1.2/32", "fd86::2/128"},
		}},
	}
	conf, err := buildKernelSetconf(inst, DeviceOptions{
		HeaderProtectionKey:    inst.Obfuscation.HeaderProtectionKey,
		ContentPaddingAddition: inst.Obfuscation.ContentPaddingAddition,
		RandomTrailers:         true,
	})
	if err != nil {
		t.Fatalf("buildKernelSetconf: %v", err)
	}
	for _, want := range []string{
		"[Interface]",
		"PrivateKey = " + priv,
		"ListenPort = 51820",
		"Jc = 4",
		"S4 = 18",
		"H1 = 100-110",
		"I1 = <b 0x1234>",
		"HeaderProtectionKey = " + priv,
		"ContentPaddingAddition = 8-16",
		"RandomTrailers = on",
		"DisableCookies = off",
		"[Peer]",
		"PublicKey = " + pub,
		"PresharedKey = " + psk,
		"AllowedIPs = 10.8.1.2/32, fd86::2/128",
	} {
		if !strings.Contains(conf, want) {
			t.Fatalf("setconf missing %q\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "Address =") || strings.Contains(conf, "MTU =") {
		t.Fatalf("setconf includes awg-quick-only keys:\n%s", conf)
	}
}

func TestBuildKernelSetconfRejectsNewlineInPeerKey(t *testing.T) {
	priv, _, err := wireguard.GenerateWireguardKeypair()
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	inst := amneziawg.Instance{
		ListenPort: 1,
		PrivateKey: priv,
		Peers:      []amneziawg.Peer{{PublicKey: "bad\nPostUp = iptables -F"}},
	}
	if _, err := buildKernelSetconf(inst, DeviceOptions{}); err == nil {
		t.Fatal("buildKernelSetconf accepted a newline in a peer key")
	}
}

func TestInterfaceKeysDroppedOnlyForRemovedDeviceLines(t *testing.T) {
	prev := "[Interface]\nPrivateKey = a\nContentPaddingAddition = 8-16\n\n[Peer]\nPublicKey = b\n"
	next := "[Interface]\nPrivateKey = a\n\n[Peer]\nPublicKey = c\n"
	if !interfaceKeysDropped(prev, next) {
		t.Fatal("removing ContentPaddingAddition must force a link rebuild")
	}
	same := "[Interface]\nPrivateKey = a\nContentPaddingAddition = 1-2\n"
	if interfaceKeysDropped(prev, same) {
		t.Fatal("rewriting a device value is not a dropped key")
	}
}

func TestRenderNFTRedirectsEachInterface(t *testing.T) {
	got := renderNFT(map[string]int{"awg2": 40002, "awg1": 40001})
	want1 := `iifname "awg1" meta l4proto { tcp, udp } redirect to :40001`
	want2 := `iifname "awg2" meta l4proto { tcp, udp } redirect to :40002`
	if !strings.Contains(got, want1) || !strings.Contains(got, want2) {
		t.Fatalf("renderNFT = %s", got)
	}
	if strings.Index(got, want1) > strings.Index(got, want2) {
		t.Fatalf("renderNFT did not sort interface names:\n%s", got)
	}
}

func TestParseWGDumpMapsHandshakeAndTraffic(t *testing.T) {
	dump := strings.Join([]string{
		"priv pub 51820 off",
		"peerkey (none) 203.0.113.9:51820 10.8.1.2/32 1710000000 100 200 off",
		"quiet (none) (none) 10.8.1.3/32 0 0 0 off",
	}, "\n")
	peers := []amneziawg.Peer{
		{Email: "a@x", PublicKey: "peerkey", AllowedIPs: []string{"10.8.1.2/32"}},
		{Email: "b@x", PublicKey: "quiet", AllowedIPs: []string{"10.8.1.3/32"}},
		{Email: "c@x", PublicKey: "absent", AllowedIPs: []string{"10.8.1.4/32"}},
	}
	diag := parseWGDump(dump, peers)
	if !diag.Running || diag.ListenPort != 51820 || diag.Backend != string(BackendKernel) {
		t.Fatalf("diag header = %+v", diag)
	}
	if len(diag.Clients) != 3 {
		t.Fatalf("clients = %d", len(diag.Clients))
	}
	a := diag.Clients[0]
	if a.Email != "a@x" || a.Endpoint != "203.0.113.9:51820" || a.RxBytes != 100 || a.TxBytes != 200 || a.LastHandshake.Unix() != 1710000000 {
		t.Fatalf("connected peer = %+v", a)
	}
	if diag.Clients[1].Connected() {
		t.Fatalf("zero handshake must be offline: %+v", diag.Clients[1])
	}
	if diag.Clients[2].AllowedIPs != "10.8.1.4/32" {
		t.Fatalf("missing dump peer allowed IPs = %q", diag.Clients[2].AllowedIPs)
	}
}

func TestKernelOutboundNameIsStableAndFitsIFNAMSIZ(t *testing.T) {
	a, err := kernelOutboundName("warp")
	if err != nil {
		t.Fatal(err)
	}
	b, err := kernelOutboundName("warp")
	if err != nil {
		t.Fatal(err)
	}
	c, err := kernelOutboundName("other")
	if err != nil {
		t.Fatal(err)
	}
	if a != b || a == c {
		t.Fatalf("names a=%s b=%s c=%s", a, b, c)
	}
	if len(a) > 15 || !strings.HasPrefix(a, "awgo") {
		t.Fatalf("name %q is not a short awgo interface", a)
	}
	if _, err := kernelOutboundName(""); err == nil {
		t.Fatal("empty tag must be rejected")
	}
}
