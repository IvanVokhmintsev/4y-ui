package amneziawgnet

import (
	"fmt"
	"os"
	"strings"
)

// Backend selects how AmneziaWG interfaces are created.
type Backend string

const (
	// BackendUserspace is amneziawg-go over the in-process netstack.
	BackendUserspace Backend = "userspace"
	// BackendKernel is the host amneziawg module, configured from this process.
	BackendKernel Backend = "kernel"
)

// kernelModuleStat is the sysfs node that exists once the module is loaded.
// Tests point it at a missing path.
var kernelModuleStat = "/sys/module/amneziawg"

// detectBackend reads XUI_AWG_BACKEND. Unset stays on the userspace engine.
// auto uses the kernel module when it and awg/ip/nft are present.
func detectBackend() (Backend, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("XUI_AWG_BACKEND"))) {
	case "", "userspace":
		return BackendUserspace, nil
	case "auto":
		if kernelToolsReady() {
			return BackendKernel, nil
		}
		return BackendUserspace, nil
	case "kernel":
		if !kernelToolsReady() {
			return "", fmt.Errorf("XUI_AWG_BACKEND=kernel but the amneziawg module or awg/ip/nft is missing")
		}
		return BackendKernel, nil
	default:
		return "", fmt.Errorf("invalid XUI_AWG_BACKEND %q", os.Getenv("XUI_AWG_BACKEND"))
	}
}
