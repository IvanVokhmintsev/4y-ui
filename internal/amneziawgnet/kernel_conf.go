package amneziawgnet

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
)

type kernelPeerLine struct {
	PublicKey    string
	PresharedKey string
	AllowedIPs   []string
	Endpoint     string
	KeepAlive    int
}

// buildKernelSetconf renders an `awg syncconf` file for a server interface.
// Address and MTU are applied with ip(8); awg rejects those awg-quick keys.
func buildKernelSetconf(inst amneziawg.Instance, opts DeviceOptions) (string, error) {
	if inst.ListenPort <= 0 || inst.ListenPort > 65535 {
		return "", fmt.Errorf("invalid listen port %d", inst.ListenPort)
	}
	peers := make([]kernelPeerLine, len(inst.Peers))
	for i, p := range inst.Peers {
		peers[i] = kernelPeerLine{
			PublicKey: p.PublicKey, PresharedKey: p.PresharedKey, AllowedIPs: p.AllowedIPs,
		}
	}
	return renderKernelConf(inst.PrivateKey, inst.ListenPort, inst.Obfuscation, opts, peers)
}

// buildKernelClientConf renders an `awg syncconf` file for a client interface.
func buildKernelClientConf(inst amneziawg.OutboundInstance, opts DeviceOptions) (string, error) {
	if inst.ListenPort < 0 || inst.ListenPort > 65535 {
		return "", fmt.Errorf("invalid listen port %d", inst.ListenPort)
	}
	peers := make([]kernelPeerLine, len(inst.Peers))
	for i, p := range inst.Peers {
		if strings.TrimSpace(p.Endpoint) == "" {
			return "", fmt.Errorf("peer %d: missing endpoint", i)
		}
		peers[i] = kernelPeerLine{
			PublicKey: p.PublicKey, PresharedKey: p.PresharedKey, AllowedIPs: p.AllowedIPs,
			Endpoint: p.Endpoint, KeepAlive: p.KeepAlive,
		}
	}
	return renderKernelConf(inst.PrivateKey, inst.ListenPort, inst.Obfuscation, opts, peers)
}

func renderKernelConf(priv string, listenPort int, o amneziawg.Obfuscation31, opts DeviceOptions, peers []kernelPeerLine) (string, error) {
	if err := validateWGKey("PrivateKey", priv); err != nil {
		return "", err
	}
	hp := opts.HeaderProtectionKey
	if hp == "" {
		hp = disabledHeaderKey()
	}
	if err := validateWGKey("HeaderProtectionKey", hp); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", priv)
	if listenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", listenPort)
	}
	fmt.Fprintf(&b, "Jc = %d\nJmin = %d\nJmax = %d\n", o.Jc, o.Jmin, o.Jmax)
	fmt.Fprintf(&b, "S1 = %d\nS2 = %d\nS3 = %d\nS4 = %d\n", o.S1, o.S2, o.S3, o.S4)
	for _, line := range []struct{ k, v string }{
		{"H1", o.H1},
		{"H2", o.H2},
		{"H3", o.H3},
		{"H4", o.H4},
		{"I1", o.I1},
		{"I2", o.I2},
		{"I3", o.I3},
		{"I4", o.I4},
		{"I5", o.I5},
		{"ContentPaddingAddition", opts.ContentPaddingAddition},
		{"RekeyAfterTime", opts.RekeyAfterTime},
		{"RekeyTimeout", opts.RekeyTimeout},
		{"RejectAfterTime", opts.RejectAfterTime},
		{"KeepaliveTimeout", opts.KeepaliveTimeout},
		{"MaxHandshakeAttempts", opts.MaxHandshakeAttempts},
	} {
		if line.v == "" {
			continue
		}
		if err := rejectControl(line.k, line.v); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s = %s\n", line.k, line.v)
	}
	fmt.Fprintf(&b, "HeaderProtectionKey = %s\n", hp)
	fmt.Fprintf(&b, "RandomTrailers = %s\n", boolWord(opts.RandomTrailers))
	fmt.Fprintf(&b, "DisableCookies = %s\n", boolWord(opts.DisableCookies))

	for i, p := range peers {
		if err := validateWGKey(fmt.Sprintf("peer %d PublicKey", i), p.PublicKey); err != nil {
			return "", err
		}
		if p.PresharedKey != "" {
			if err := validateWGKey(fmt.Sprintf("peer %d PresharedKey", i), p.PresharedKey); err != nil {
				return "", err
			}
		}
		if err := rejectControl("Endpoint", p.Endpoint); err != nil {
			return "", err
		}
		for _, cidr := range p.AllowedIPs {
			if err := rejectControl("AllowedIPs", cidr); err != nil {
				return "", err
			}
		}
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		}
		if p.KeepAlive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.KeepAlive)
		}
	}
	return b.String(), nil
}

func boolWord(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func disabledHeaderKey() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

func validateWGKey(field, v string) error {
	if err := rejectControl(field, v); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("invalid %s", field)
	}
	return nil
}

func rejectControl(field, v string) error {
	for _, r := range v {
		if r == '\n' || r == '\r' || r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid %s", field)
		}
	}
	return nil
}

// interfaceKeysDropped reports an [Interface] key present in prev and absent
// from next. awg keeps omitted device fields, so that case rebuilds the link.
func interfaceKeysDropped(prev, next string) bool {
	if prev == "" {
		return false
	}
	have := interfaceKeys(next)
	for k := range interfaceKeys(prev) {
		if _, ok := have[k]; !ok {
			return true
		}
	}
	return false
}

func interfaceKeys(conf string) map[string]struct{} {
	keys := map[string]struct{}{}
	section := ""
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		if section != "[Interface]" {
			continue
		}
		k, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		keys[strings.TrimSpace(k)] = struct{}{}
	}
	return keys
}

// kernelOutboundName is a stable 14-byte link name for an outbound tag.
func kernelOutboundName(tag string) (string, error) {
	if tag == "" {
		return "", fmt.Errorf("empty outbound tag")
	}
	sum := sha256.Sum256([]byte(tag))
	return fmt.Sprintf("awgo%x", sum[:5]), nil
}

// renderNFT is the inet nat table that redirects decapsulated tunnel flows
// into this process. Names are sorted so the text is stable.
func renderNFT(ports map[string]int) string {
	names := make([]string, 0, len(ports))
	for name := range ports {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("table inet awgpanel {\n  chain prerouting {\n    type nat hook prerouting priority dstnat; policy accept;\n")
	for _, name := range names {
		fmt.Fprintf(&b, "    iifname %q meta l4proto { tcp, udp } redirect to :%d\n", name, ports[name])
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

// parseWGDump reads `awg show <iface> dump` into the diagnostics shape.
func parseWGDump(dump string, peers []amneziawg.Peer) Diagnostics {
	diag := Diagnostics{Running: true, Backend: string(BackendKernel)}
	byKey := map[string]ClientDiagnostic{}
	first := true
	for _, line := range strings.Split(dump, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if first {
			first = false
			if len(f) >= 3 {
				diag.ListenPort, _ = strconv.Atoi(f[2])
			}
			continue
		}
		if len(f) < 7 {
			continue
		}
		cd := ClientDiagnostic{Endpoint: f[2], AllowedIPs: f[3]}
		if hs, err := strconv.ParseInt(f[4], 10, 64); err == nil && hs > 0 {
			cd.LastHandshake = time.Unix(hs, 0)
		}
		cd.RxBytes, _ = strconv.ParseUint(f[5], 10, 64)
		cd.TxBytes, _ = strconv.ParseUint(f[6], 10, 64)
		byKey[f[0]] = cd
	}
	diag.Clients = make([]ClientDiagnostic, 0, len(peers))
	for _, p := range peers {
		st := byKey[p.PublicKey]
		st.Email = p.Email
		if st.AllowedIPs == "" {
			st.AllowedIPs = strings.Join(p.AllowedIPs, ", ")
		}
		diag.Clients = append(diag.Clients, st)
	}
	return diag
}
