package amneziawgnet

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectBackendUnsetStaysUserspace(t *testing.T) {
	t.Setenv("XUI_AWG_BACKEND", "")
	got, err := detectBackend()
	if err != nil {
		t.Fatalf("detectBackend: %v", err)
	}
	if got != BackendUserspace {
		t.Fatalf("detectBackend = %q, want userspace when unset", got)
	}
}

func TestDetectBackendUserspace(t *testing.T) {
	t.Setenv("XUI_AWG_BACKEND", "userspace")
	got, err := detectBackend()
	if err != nil {
		t.Fatalf("detectBackend: %v", err)
	}
	if got != BackendUserspace {
		t.Fatalf("detectBackend = %q, want userspace", got)
	}
}

func TestDetectBackendRejectsUnknownMode(t *testing.T) {
	t.Setenv("XUI_AWG_BACKEND", "wireguard")
	_, err := detectBackend()
	if err == nil || !strings.Contains(err.Error(), "wireguard") {
		t.Fatalf("detectBackend err = %v, want the invalid mode named", err)
	}
}

func TestDetectBackendKernelRequiresModule(t *testing.T) {
	t.Setenv("XUI_AWG_BACKEND", "kernel")
	prev := kernelModuleStat
	kernelModuleStat = filepath.Join(t.TempDir(), "amneziawg-missing")
	t.Cleanup(func() { kernelModuleStat = prev })

	_, err := detectBackend()
	if err == nil {
		t.Fatal("detectBackend succeeded without an amneziawg module")
	}
}

func TestDetectBackendAutoFallsBackWithoutModule(t *testing.T) {
	t.Setenv("XUI_AWG_BACKEND", "auto")
	prev := kernelModuleStat
	kernelModuleStat = filepath.Join(t.TempDir(), "amneziawg-missing")
	t.Cleanup(func() { kernelModuleStat = prev })

	got, err := detectBackend()
	if err != nil {
		t.Fatalf("detectBackend: %v", err)
	}
	if got != BackendUserspace {
		t.Fatalf("detectBackend = %q, want userspace when the module is absent", got)
	}
}
