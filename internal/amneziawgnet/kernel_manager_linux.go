//go:build linux

package amneziawgnet

import (
	"fmt"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/amneziawg"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// ensureKernelLocked brings one inbound up on the amneziawg kernel module.
// Caller holds Manager.mu, same contract as ensureLocked.
func (m *Manager) ensureKernelLocked(d Desired) error {
	inst, opts := d.Instance, d.Options
	name := inst.InterfaceName
	if name == "" {
		name = fmt.Sprintf("awg%d", inst.Id)
	}
	if err := amneziawg.ValidateInterfaceName(name); err != nil {
		return fmt.Errorf("amneziawgnet: %w", err)
	}
	conf, err := buildKernelSetconf(inst, opts)
	if err != nil {
		return fmt.Errorf("amneziawgnet: %w", err)
	}
	fp := addressFingerprint(inst)

	if cur, ok := m.ifaces[inst.Id]; ok && cur.kern == nil {
		applyV6Aliases(diffV6Aliases(cur.inst, amneziawg.Instance{}))
		cur.close()
		delete(m.ifaces, inst.Id)
	}

	cur := m.ifaces[inst.Id]
	var old amneziawg.Instance
	if cur != nil {
		old = cur.inst
	}
	if cur != nil && cur.structFP == fp && !interfaceKeysDropped(cur.uapiConfig, conf) {
		if conf == cur.uapiConfig {
			idx := NewPeerIndex(inst.Peers)
			cur.kern.peers.Store(idx)
			cur.peers.Store(idx)
			cur.inst = inst
			applyV6Aliases(diffV6Aliases(old, inst))
			cur.portForwards.Reconcile(inst)
			return nil
		}
		if err := kernelSync(name, conf); err != nil {
			return fmt.Errorf("amneziawgnet: reconfigure inbound %d: %w", inst.Id, err)
		}
		idx := NewPeerIndex(inst.Peers)
		cur.kern.peers.Store(idx)
		cur.peers.Store(idx)
		cur.inst = inst
		cur.uapiConfig = conf
		applyV6Aliases(diffV6Aliases(old, inst))
		cur.portForwards.Reconcile(inst)
		return nil
	}
	if cur != nil {
		applyV6Aliases(diffV6Aliases(old, amneziawg.Instance{}))
		cur.close()
		delete(m.ifaces, inst.Id)
	}

	if err := kernelPrepareLink(name, inst.Address, conf); err != nil {
		_ = kernelLinkDel(name)
		return fmt.Errorf("amneziawgnet: kernel link %s: %w", name, err)
	}
	kern := &kernelInbound{
		name:  name,
		relay: socksRelayForInstance(inst),
		stop:  make(chan struct{}),
	}
	kern.peers.Store(NewPeerIndex(inst.Peers))
	kern.udpRelay = NewUDPRelay(kern.relay, nil)
	kern.udpRelay.reply = kern.writeUDPReply
	if err := kern.serve(); err != nil {
		kern.close()
		return err
	}
	if err := kernelNFTAdd(name, kern.port); err != nil {
		kern.close()
		return fmt.Errorf("amneziawgnet: nft %s: %w", name, err)
	}
	mtu := amneziawg.EffectiveMTU(inst.MTU, inst.Obfuscation.S4)
	if err := kernelSetUp(name, mtu); err != nil {
		kern.close()
		return fmt.Errorf("amneziawgnet: link up %s: %w", name, err)
	}
	pfs := NewHostPortForwardSet(inst.Id)
	next := &managed{
		kern:         kern,
		portForwards: pfs,
		inst:         inst,
		structFP:     fp,
		uapiConfig:   conf,
	}
	next.peers.Store(NewPeerIndex(inst.Peers))
	m.ifaces[inst.Id] = next
	applyV6Aliases(diffV6Aliases(old, inst))
	pfs.Reconcile(inst)
	warnKernelListen(inst)
	logger.Infof("amneziawgnet: started kernel interface %s for inbound %d", name, inst.Id)
	return nil
}

func warnKernelListen(inst amneziawg.Instance) {
	listen := strings.TrimSpace(inst.Listen)
	switch listen {
	case "", "0.0.0.0", "::", "[::]":
		return
	}
	logger.Warningf("amneziawgnet: inbound %d listen %s is ignored in kernel mode; the module binds every address in this network namespace", inst.Id, listen)
}
