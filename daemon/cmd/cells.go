// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	healthApi "github.com/cilium/cilium/api/v1/health/server"
	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/daemon/cmd/cni"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/auth"
	"github.com/cilium/cilium/pkg/bgpv1"
	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/datapath"
	dptypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/egressgateway"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	ipamMetadata "github.com/cilium/cilium/pkg/ipam/metadata"
	"github.com/cilium/cilium/pkg/ipam/staticip"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/l2announcer"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/signal"
	"github.com/cilium/cilium/pkg/statedb"
)

var (
	Agent = cell.Module(
		"agent",
		"Cilium Agent",

		Infrastructure,
		ControlPlane,
		datapath.Cell,
	)

	// Infrastructure provides access and services to the outside.
	// A cell should live here instead of ControlPlane if it is not needed by
	// integrations tests, or needs to be mocked.
	Infrastructure = cell.Module(
		"infra",
		"Infrastructure",

		// Register the pprof HTTP handlers, to get runtime profiling data.
		pprof.Cell,
		cell.Config(pprof.Config{
			PprofAddress: option.PprofAddressAgent,
			PprofPort:    option.PprofPortAgent,
		}),

		// Runs the gops agent, a tool to diagnose Go processes.
		gops.Cell(defaults.GopsPortAgent),

		// Provides Clientset, API for accessing Kubernetes objects.
		k8sClient.Cell,

		cni.Cell,

		// Provide the modular metrics registry, metric HTTP server and legacy metrics cell.
		metrics.Cell,

		// Provide option.Config via hive so cells can depend on the agent config.
		cell.Provide(func() *option.DaemonConfig { return option.Config }),

		// Provides an in-memory transactional database for internal state
		statedb.Cell,

		// Provides a global job registry which cells can use to spawn job groups.
		job.Cell,
	)

	// ControlPlane implement the per-node control functions. These are pure
	// business logic and depend on datapath or infrastructure to perform
	// actions. This separation enables non-privileged integration testing of
	// the control-plane.
	ControlPlane = cell.Module(
		"controlplane",
		"Control Plane",

		// LocalNodeStore holds onto the information about the local node and allows
		// observing changes to it.
		node.LocalNodeStoreCell,

		// Provide a LocalNodeInitializer that is invoked when LocalNodeStore is started.
		// This fills in the initial state before it is accessed by other sub-systems.
		cell.Provide(newLocalNodeInitializer),

		// Shared resources provide access to k8s resources as event streams or as
		// read-only stores.
		agentK8s.ResourcesCell,

		// EndpointManager maintains a collection of the locally running endpoints.
		endpointmanager.Cell,

		// NodeManager maintains a collection of other nodes in the cluster.
		nodeManager.Cell,

		// Certificate manager provides an API for retrieving secrets and certificate in the form of TLS contexts.
		certificatemanager.Cell,

		// Cilium API specification cell makes the swagger model available for reuse
		server.SpecCell,

		// cilium-health connectivity probe API specification cell makes the swagger model available for reuse
		healthApi.SpecCell,

		// daemonCell wraps the legacy daemon initialization and provides Promise[*Daemon].
		daemonCell,

		// Proxy provides the proxy port allocation and related datapath coordination and
		// makes different L7 proxies (Envoy, DNS proxy) usable to Cilium endpoints through
		// a common Proxy 'redirect' abstraction.
		proxy.Cell,

		// The BGP Control Plane which enables various BGP related interop.
		bgpv1.Cell,

		// Brokers datapath signals from signalmap
		signal.Cell,

		// Auth is responsible for authenticating a request if required by a policy.
		auth.Cell,

		// IPCache, policy.Repository and CachingIdentityAllocator.
		cell.Provide(newPolicyTrifecta),

		// IPAM metadata manager, determines which IPAM pool a pod should allocate from
		ipamMetadata.Cell,

		staticip.Cell,

		// Egress Gateway allows originating traffic from specific IPv4 addresses.
		egressgateway.Cell,

		// ServiceCache holds the list of known services correlated with the matching endpoints.
		cell.Provide(func(dp dptypes.Datapath) *k8s.ServiceCache { return k8s.NewServiceCache(dp.LocalNodeAddressing()) }),

		// ClusterMesh is the Cilium's multicluster implementation.
		clustermesh.Cell,

		// L2announcer resolves l2announcement policies, services, node labels and devices into a list of IPs+netdevs
		// which need to be announced on the local network.
		l2announcer.Cell,
	)
)
