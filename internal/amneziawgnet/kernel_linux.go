//go:build linux

package amneziawgnet

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
)

type cmdRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

var runCmd cmdRunner = execRunner{}

func kernelToolsReady() bool {
	if _, err := os.Stat(kernelModuleStat); err != nil {
		return false
	}
	for _, bin := range []string{"awg", "ip", "nft"} {
		if _, err := exec.LookPath(bin); err != nil {
			return false
		}
	}
	return true
}

func runCmdTimeout(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := runCmd.Run(ctx, name, args...)
	return err
}

func runSoft(name string, args ...string) error {
	err := runCmdTimeout(name, args...)
	if err == nil || strings.Contains(err.Error(), "File exists") || strings.Contains(err.Error(), "No such file") {
		return nil
	}
	return err
}

// kernelPrepareLink creates the interface, assigns addresses, and syncs awg.
// The link stays down until the redirect listener is bound.
func kernelPrepareLink(name string, addrs []string, conf string) error {
	if err := amneziawg.ValidateInterfaceName(name); err != nil {
		return err
	}
	if err := runSoft("ip", "link", "add", "dev", name, "type", "amneziawg"); err != nil {
		return err
	}
	for _, addr := range addrs {
		if err := runCmdTimeout("ip", "addr", "replace", addr, "dev", name); err != nil {
			return err
		}
	}
	return kernelSync(name, conf)
}

func kernelSync(name, conf string) error {
	f, err := os.CreateTemp("", "awg-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(conf); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return runCmdTimeout("awg", "syncconf", name, f.Name())
}

func kernelSetUp(name string, mtu int) error {
	if mtu <= 0 {
		mtu = 1280
	}
	if err := runCmdTimeout("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up"); err != nil {
		return err
	}
	// Strict reverse-path filtering drops decrypted packets whose source is a
	// tunnel address learned on this interface. Loose mode is per-link only.
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/"+name+"/rp_filter", []byte("2\n"), 0o644)
	return nil
}

func kernelLinkDel(name string) error {
	if name == "" {
		return nil
	}
	return runSoft("ip", "link", "del", "dev", name)
}

func kernelDump(ifname string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := runCmd.Run(ctx, "awg", "show", ifname, "dump")
	return string(out), err
}

var (
	nftMu    sync.Mutex
	nftPorts = map[string]int{}
)

func kernelNFTAdd(ifname string, port int) error {
	nftMu.Lock()
	defer nftMu.Unlock()
	nftPorts[ifname] = port
	return applyNFTLocked()
}

func kernelNFTRemove(ifname string) error {
	nftMu.Lock()
	defer nftMu.Unlock()
	delete(nftPorts, ifname)
	return applyNFTLocked()
}

func applyNFTLocked() error {
	if len(nftPorts) == 0 {
		return runSoft("nft", "delete", "table", "inet", "awgpanel")
	}
	f, err := os.CreateTemp("", "awg-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(renderNFT(nftPorts)); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return runCmdTimeout("nft", "-f", f.Name())
}
