//go:build linux

package amneziawgnet

import (
	"fmt"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// ensureKernelOutbound brings one client interface up on the kernel module.
// Caller holds OutboundManager.mu.
func (m *OutboundManager) ensureKernelOutbound(d OutboundDesired) error {
	inst, opts := d.Instance, d.Options
	name, err := kernelOutboundName(inst.Tag)
	if err != nil {
		return fmt.Errorf("amneziawgnet: %w", err)
	}
	conf, err := buildKernelClientConf(inst, opts)
	if err != nil {
		return fmt.Errorf("amneziawgnet: %w", err)
	}
	fp := outboundFingerprint(inst)
	cur := m.iface[inst.Tag]
	if cur != nil && cur.ifname == "" {
		cur.shutdown(inst.Tag)
		delete(m.iface, inst.Tag)
		cur = nil
	}
	if cur != nil && cur.structFP == fp && !interfaceKeysDropped(cur.uapiConfig, conf) {
		if conf != cur.uapiConfig {
			if err := kernelSync(name, conf); err != nil {
				return fmt.Errorf("amneziawgnet: reconfigure outbound %q: %w", inst.Tag, err)
			}
			cur.uapiConfig = conf
		}
		addrs, err := hostAddresses(inst.Address)
		if err != nil {
			return fmt.Errorf("amneziawgnet: %w", err)
		}
		GetEgressServer().SetKernel(inst.Tag, name, addrs, inst.DNS)
		return nil
	}
	if cur != nil {
		cur.shutdown(inst.Tag)
		delete(m.iface, inst.Tag)
	}
	if err := kernelPrepareLink(name, inst.Address, conf); err != nil {
		_ = kernelLinkDel(name)
		return fmt.Errorf("amneziawgnet: kernel outbound %q: %w", inst.Tag, err)
	}
	mtu := amneziawg.EffectiveMTU(inst.MTU, inst.Obfuscation.S4)
	if err := kernelSetUp(name, mtu); err != nil {
		_ = kernelLinkDel(name)
		return fmt.Errorf("amneziawgnet: kernel outbound %q up: %w", inst.Tag, err)
	}
	addrs, err := hostAddresses(inst.Address)
	if err != nil {
		_ = kernelLinkDel(name)
		return fmt.Errorf("amneziawgnet: %w", err)
	}
	m.iface[inst.Tag] = &managedOutbound{ifname: name, uapiConfig: conf, structFP: fp}
	GetEgressServer().SetKernel(inst.Tag, name, addrs, inst.DNS)
	logger.Infof("amneziawgnet: started kernel outbound %s on %s (%d peers)", inst.Tag, name, len(inst.Peers))
	return nil
}
