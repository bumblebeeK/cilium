package ipam

import (
	"context"
	"fmt"
	ipamStats "github.com/cilium/cilium/pkg/ipam/stats"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/sirupsen/logrus"
	"time"
)

type pool interface {
	maintainCRDIPPool(ctx context.Context) (poolMutated bool, err error)
	allocationNeeded() bool
	releaseNeeded() (needed bool)
	requirePoolMaintenance()
	waitingForMaintenance() bool
	GetAvailable() ipamTypes.AllocationMap
	getPreAllocate() int
	getMinAllocate() int
	getMaxAllocate() int
	getStatics() *Statistics
	recalculate(ipamTypes.AllocationMap, ipamStats.InterfaceStats)
	updateLastResync(syncTime time.Time)
	poolMaintenanceComplete()
	requireResync()
	allocateStaticIP(ip string, pool Pool) error
	requireSyncCsip()
	syncCsipComplete()
	waitingForSyncCsip() bool
}

// MaintainIPPoolV2 attempts to allocate or release all required IPs to fulfill
// the needed gap. If required, interfaces are created.
func (n *Node) MaintainIPPoolV2(ctx context.Context) error {
	log.Infoln("@@@ MaintainIPPoolV2")
	// As long as the instances API is unstable, don't perform any
	// operation that can mutate state.
	if !n.manager.InstancesAPIIsReady() {
		if n.retry != nil {
			n.retry.Trigger()
		}
		return fmt.Errorf("instances API is unstable. Blocking mutating operations. See logs for details.")
	}

	// If the instance has stopped running for less than a minute, don't attempt any deficit
	// resolution and wait for the custom resource to be updated as a sign
	// of life.
	if !n.isInstanceRunning() && n.instanceStoppedRunning.Add(time.Minute).After(time.Now()) {
		return nil
	}

	var instanceMutated bool
	var err error
	var poolMutated bool
	for _, pool := range n.pools {
		if pool.waitingForMaintenance() {
			poolMutated, err = pool.maintainCRDIPPool(ctx)
			if poolMutated {
				instanceMutated = true
			}
			if err == nil {
				n.logger().Debug("Setting resync needed")
				pool.requireResync()
			}
			pool.poolMaintenanceComplete()
		}

		if pool.waitingForSyncCsip() {
			instanceMutated = true
			pool.syncCsipComplete()
		}
	}
	n.recalculateV2()

	if instanceMutated || err != nil {
		log.Infoln("@@@@ n.instanceSync ready Trigger()")

		n.instanceSync.Trigger()
		log.Infoln("@@@@ n.instanceSync end Trigger()")
	} else {
		log.Infoln("@@@ MaintainIPPoolV2 end")
	}
	return err
}

func (n *Node) recalculateV2() {
	// Skip any recalculation if the CiliumNode resource does not exist yet
	if !n.resourceAttached() {
		return
	}
	scopedLog := n.logger()

	a, stats, err := n.ops.ResyncInterfacesAndIPsByPool(context.TODO(), scopedLog)
	log.Infoln("@@@ ResyncInterfacesAndIPsByPool")
	n.mutex.Lock()
	defer n.mutex.Unlock()
	if err != nil {
		scopedLog.Warning("Instance not found! Please delete corresponding ciliumnode if instance has already been deleted.")
		for _, statistics := range n.poolStats {
			statistics.NeededIPs = 0
			statistics.ExcessIPs = 0
		}
		return
	}

	n.stats.UsedIPs = 0

	for _, poolUsed := range n.resource.Status.IPAM.PoolUsed {
		n.stats.UsedIPs += len(poolUsed)
	}
	n.stats.NeededIPs = 0
	n.stats.AvailableIPs = 0
	n.stats.ExcessIPs = 0

	for name, pool := range n.pools {
		pool.recalculate(a[name], stats)
		n.poolStats[name] = pool.getStatics()
		n.stats.AvailableIPs += pool.getStatics().AvailableIPs
		n.stats.NeededIPs += pool.getStatics().NeededIPs
		n.stats.ExcessIPs += pool.getStatics().ExcessIPs
	}
	n.stats.RemainingInterfaces = stats.RemainingAvailableInterfaceCount
	n.stats.Capacity = stats.NodeCapacity
	scopedLog.WithFields(logrus.Fields{
		"available":                 n.stats.AvailableIPs,
		"capacity":                  n.stats.Capacity,
		"used":                      n.stats.UsedIPs,
		"toAlloc":                   n.stats.NeededIPs,
		"toRelease":                 n.stats.ExcessIPs,
		"waitingForPoolMaintenance": n.waitingForPoolMaintenance,
		"resyncNeeded":              n.resyncNeeded,
		"remainingInterfaces":       stats.RemainingAvailableInterfaceCount,
	}).Debug("Recalculated needed addresses")

}

// allocationNeeded returns true if this node requires IPs to be allocated
func (n *Node) allocationNeededV2() (needed bool) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	for _, p := range n.pools {
		if p.allocationNeeded() {
			needed = true
			return
		}
	}
	return
}

// releaseNeeded returns true if this node requires IPs to be released
func (n *Node) releaseNeededV2() (needed bool) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	for pool, p := range n.pools {
		if p.releaseNeeded() {
			log.Infof("@@@  releaseNeededV2 %v", pool)
			needed = true
			return
		}
	}

	return
}

// CrdPools returns the IP allocation pool available to the node
func (n *Node) CrdPools() (pools map[string]ipamTypes.AllocationMap) {
	pools = map[string]ipamTypes.AllocationMap{}
	n.mutex.RLock()
	for name, p := range n.pools {
		po := map[string]ipamTypes.AllocationIP{}
		for k, allocationIP := range p.GetAvailable() {
			po[k] = allocationIP
		}
		pools[name.String()] = po
	}
	n.mutex.RUnlock()
	return
}

// syncToAPIServerV2 synchronizes the contents of the CiliumNode resource
// [(*Node).resource)] with the K8s apiserver. This operation occurs on an
// interval to refresh the CiliumNode resource.
//
// For Azure and ENI IPAM modes, this function serves two purposes: (1)
// finalizes the initialization of the CiliumNode resource (setting
// PreAllocate) and (2) to keep the resource up-to-date with K8s.
//
// To initialize, or seed, the CiliumNode resource, the PreAllocate field is
// populated with a default value and then is adjusted as necessary.
func (n *Node) syncToAPIServerV2() (err error) {
	scopedLog := n.logger()
	scopedLog.Debug("Refreshing node")

	node := n.ResourceCopy()
	// n.resource may not have been assigned yet
	if node == nil {
		return
	}

	origNode := node.DeepCopy()

	// We create a snapshot of the IP pool before we update the status. This
	// ensures that the pool in the spec is always older than the IPAM
	// information in the status.
	// This ordering is important, because otherwise a new IP could be added to
	// the pool after we updated the status, thereby creating a situation where
	// the agent does not have the necessary IPAM information to use the newly
	// added IP.
	// When an IP is removed, this is also safe. IP release is done via
	// handshake, where the agent will never use any IP where it has
	// acknowledged the release handshake. Therefore, having an already
	// released IP in the pool is fine, as the agent will ignore it.

	pool := n.CrdPools()

	// Always update the status first to ensure that the IPAM information
	// is synced for all addresses that are marked as available.
	//
	// Two attempts are made in case the local resource is outdated. If the
	// second attempt fails as well we are likely under heavy contention,
	// fall back to the controller based background interval to retry.
	for retry := 0; retry < 2; retry++ {
		if node.Status.IPAM.PoolUsed == nil {
			node.Status.IPAM.PoolUsed = map[string]ipamTypes.AllocationMap{}
		}

		n.ops.PopulateStatusFields(node)
		n.PopulateIPReleaseStatus(node)

		err = n.update(origNode, node, retry, true)
		if err == nil {
			break
		}
	}

	if err != nil {
		scopedLog.WithError(err).Warning("Unable to update CiliumNode status")
		return err
	}

	for retry := 0; retry < 2; retry++ {
		node.Spec.IPAM.CrdPools = pool
		scopedLog.WithField("poolCount", len(node.Spec.IPAM.CrdPools)).Debug("Updating node in apiserver")

		// The PreAllocate value is added here rather than where the CiliumNode
		// resource is created ((*NodeDiscovery).mutateNodeResource() inside
		// pkg/nodediscovery), because mutateNodeResource() does not have
		// access to the ipam.Node object. Since we are in the CiliumNode
		// update sync loop, we can compute the value.
		if node.Spec.IPAM.PreAllocate == 0 {
			node.Spec.IPAM.PreAllocate = n.ops.GetMinimumAllocatableIPv4()
		}

		err = n.update(origNode, node, retry, false)
		if err == nil {
			break
		}
	}

	if err != nil {
		scopedLog.WithError(err).Warning("Unable to update CiliumNode spec")
	}

	return err
}

func (n *Node) updateLastResyncV2(syncTime time.Time) {
	for _, pool := range n.pools {
		pool.updateLastResync(syncTime)
	}
}

func (n *Node) requirePoolMaintenanceV2() {
	n.mutex.Lock()
	for _, p := range n.pools {
		p.requirePoolMaintenance()
	}
	n.mutex.Unlock()
}
