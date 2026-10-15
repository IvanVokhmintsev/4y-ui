package amneziawgnet

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	wildcardBindHost = "127.0.0.1"
	// A host that actually has the module must not flip this package's
	// embedded-device tests onto kernel interfaces.
	_ = os.Setenv("XUI_AWG_BACKEND", "userspace")
	os.Exit(m.Run())
}
