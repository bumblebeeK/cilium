package ipam

import (
	"context"
	"fmt"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v2alpha12 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slimclientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/utils"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
	"strings"
	"sync"
	"time"
)

var (
	// slimNodeStore contains all cluster nodes store as slim_core.Node
	slimNodeStore cache.Store
	crdPoolStore  cache.Store
	staticIPStore cache.Store

	nodeController     cache.Controller
	poolController     cache.Controller
	staticIPController cache.Controller

	// multiPoolExtraSynced is closed once the slimNodeStore and crdPoolStore is synced
	// with k8s.
	multiPoolExtraSynced = make(chan struct{})

	queueKeyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc

	multiPoolExtraInit sync.Once

	k8sManager = extraManager{reSyncMap: map[*Node]struct{}{}}

	nodeToPools  map[string]poolSet
	poolsToNodes map[string]set
)

const (
	Deleted poolState = iota
	InUse
	Updated
)

const (
	defaultGCTime                  = time.Second * 10
	defaultAssignTimeOut           = time.Minute * 4
	defaultInUseTimeOut            = time.Minute * 2
	defaultWaitingForAssignTimeOut = time.Minute * 1
)

type set map[string]struct{}
type poolSet map[string]poolState
type poolState int

const (
	poolAnnotation = "ipam.cilium.io/openstack-ip-pool"
	poolLabel      = "openstack-ip-pool"
)

type extraOperation interface {
	ListK8sSlimNode() []*slim_corev1.Node
	GetK8sSlimNode(nodeName string) (*slim_corev1.Node, error)
	LabelNodeWithPool(nodeName string, labels map[string]string) error
	ListCiliumIPPool() []*v2alpha1.CiliumPodIPPool
	updateCiliumNodeManagerPool()
	listStaticIPs() []*v2alpha1.CiliumStaticIP
}

func InitIPAMOpenStackExtra(slimClient slimclientset.Interface, alphaClient v2alpha12.CiliumV2alpha1Interface, stopCh <-chan struct{}) {
	multiPoolExtraInit.Do(func() {
		nodeToPools = map[string]poolSet{}
		poolsToNodes = map[string]set{}

		nodesInit(slimClient, stopCh)
		poolsInit(alphaClient, stopCh)

		k8sManager.client = slimClient
		k8sManager.alphaClient = alphaClient
		staticIPInit(alphaClient, stopCh)

		k8sManager.updateCiliumNodeManagerPool()

		close(multiPoolExtraSynced)
	})

}

// nodesInit starts up a node watcher to handle node events.
func nodesInit(slimClient slimclientset.Interface, stopCh <-chan struct{}) {
	slimNodeStore, nodeController = informer.NewInformer(
		utils.ListerWatcherFromTyped[*slim_corev1.NodeList](slimClient.CoreV1().Nodes()),
		&slim_corev1.Node{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				updateNode(obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if compareNodeAnnotationAndLabelChange(oldObj, newObj) {
					updateNode(newObj)
				}
			},
		},
		transformToNode,
	)
	go func() {
		nodeController.Run(stopCh)
	}()

	cache.WaitForCacheSync(stopCh, nodeController.HasSynced)
}

// poolsInit starts up a node watcher to handle pool events.
func poolsInit(poolGetter v2alpha12.CiliumPodIPPoolsGetter, stopCh <-chan struct{}) {
	crdPoolStore, poolController = informer.NewInformer(
		utils.ListerWatcherFromTyped[*v2alpha1.CiliumPodIPPoolList](poolGetter.CiliumPodIPPools()),
		&v2alpha1.CiliumPodIPPool{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				updatePool(obj)
			},
			UpdateFunc: func(_, newObj interface{}) {
				updatePool(newObj)
			},
			DeleteFunc: func(obj interface{}) {
				deletePool(obj)
			},
		},
		transformToPool,
	)
	go func() {
		poolController.Run(stopCh)
	}()

	cache.WaitForCacheSync(stopCh, poolController.HasSynced)
}

// staticIPInit starts up a node watcher to handle pool events.
func staticIPInit(ipGetter v2alpha12.CiliumStaticIPsGetter, stopCh <-chan struct{}) {
	staticIPStore, staticIPController = informer.NewInformer(
		utils.ListerWatcherFromTyped[*v2alpha1.CiliumStaticIPList](ipGetter.CiliumStaticIPs()),
		&v2alpha1.CiliumStaticIP{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				k8sManager.nodeManager.instancesAPI.ExcludeIP(obj.(*v2alpha1.CiliumStaticIP).Spec.IP)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldObj.(*v2alpha1.CiliumStaticIP).ObjectMeta.ResourceVersion == newObj.(*v2alpha1.CiliumStaticIP).ObjectMeta.ResourceVersion {
					return
				}
				ipCopy := newObj.(*v2alpha1.CiliumStaticIP).DeepCopy()
				k8sManager.updateStaticIP(ipCopy)
			},
			DeleteFunc: func(obj interface{}) {
				k8sManager.nodeManager.instancesAPI.IncludeIP(obj.(*v2alpha1.CiliumStaticIP).Spec.IP)
			},
		},
		transformToStaticIP,
	)
	go func() {
		staticIPController.Run(stopCh)
		log.Infoln("@@ staticIPController stopped")
	}()

	cache.WaitForCacheSync(stopCh, staticIPController.HasSynced)

	go func() {
		k8sManager.maintainStaticIPCRDs(stopCh)
	}()
}

type extraManager struct {
	nodeManager  *NodeManager
	client       slimclientset.Interface
	alphaClient  v2alpha12.CiliumV2alpha1Interface
	updateMutex  sync.Mutex
	processMutex sync.Mutex
	reSync       bool
	reSyncMap    map[*Node]struct{}
}

func (extraManager) requireSync(node *Node) {
	k8sManager.reSyncMap[node] = struct{}{}
	k8sManager.reSync = true
}

func (extraManager) reSyncNeeded() bool {
	return k8sManager.reSync
}

func (extraManager) reSyncCompleted() {
	k8sManager.updateMutex.Lock()
	k8sManager.reSync = false
	for node, _ := range k8sManager.reSyncMap {
		delete(k8sManager.reSyncMap, node)
	}
	k8sManager.updateMutex.Unlock()
}

func (extraManager) ListCiliumIPPool() []*v2alpha1.CiliumPodIPPool {
	poolsInt := crdPoolStore.List()
	out := make([]*v2alpha1.CiliumPodIPPool, 0, len(poolsInt))
	for i := range poolsInt {
		out = append(out, poolsInt[i].(*v2alpha1.CiliumPodIPPool))
	}
	return out
}

func (extraManager) ListK8sSlimNode() []*slim_corev1.Node {
	nodesInt := slimNodeStore.List()
	out := make([]*slim_corev1.Node, 0, len(nodesInt))
	for i := range nodesInt {
		out = append(out, nodesInt[i].(*slim_corev1.Node))
	}
	return out
}

func (extraManager) GetK8sSlimNode(nodeName string) (*slim_corev1.Node, error) {
	nodeInterface, exists, err := slimNodeStore.GetByKey(nodeName)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8sErrors.NewNotFound(schema.GroupResource{
			Group:    "core",
			Resource: "Node",
		}, nodeName)
	}
	return nodeInterface.(*slim_corev1.Node), nil
}

func (extraManager) LabelNodeWithPool(nodeName string, labels map[string]string) error {
	oldNode, err := k8sManager.client.CoreV1().Nodes().Get(context.Background(), nodeName, v1.GetOptions{})
	if err != nil {
		return err
	}
	oldLabel := oldNode.GetLabels()

	// remove all the old pool label
	for k, _ := range oldLabel {
		if strings.HasPrefix(k, poolLabel) {
			delete(oldLabel, k)
		}
	}

	// label all the updated pool
	for k, v := range labels {
		oldLabel[k] = v
	}
	oldNode.SetLabels(oldLabel)
	_, err = k8sManager.client.CoreV1().Nodes().Update(context.Background(), oldNode, v1.UpdateOptions{})
	return err
}

func (extraManager) updateCiliumNodeManagerPool() {
	for _, ipPool := range k8sManager.ListCiliumIPPool() {
		k8sManager.nodeManager.pools[ipPool.Name] = ipPool
	}
}

func transformToNode(obj interface{}) (interface{}, error) {
	switch concreteObj := obj.(type) {
	case *slim_corev1.Node:
		n := &slim_corev1.Node{
			TypeMeta: concreteObj.TypeMeta,
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:            concreteObj.Name,
				ResourceVersion: concreteObj.ResourceVersion,
				Annotations:     concreteObj.Annotations,
				Labels:          concreteObj.Labels,
			},
			Spec: slim_corev1.NodeSpec{
				Taints: concreteObj.Spec.Taints,
			},
			Status: slim_corev1.NodeStatus{
				Conditions: concreteObj.Status.Conditions,
			},
		}
		*concreteObj = slim_corev1.Node{}
		return n, nil
	case cache.DeletedFinalStateUnknown:
		node, ok := concreteObj.Obj.(*slim_corev1.Node)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &slim_corev1.Node{
				TypeMeta: node.TypeMeta,
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            node.Name,
					ResourceVersion: node.ResourceVersion,
					Annotations:     node.Annotations,
					Labels:          node.Labels,
				},
				Spec: slim_corev1.NodeSpec{
					Taints: node.Spec.Taints,
				},
				Status: slim_corev1.NodeStatus{
					Conditions: node.Status.Conditions,
				},
			},
		}
		// Small GC optimization
		*node = slim_corev1.Node{}
		return dfsu, nil
	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
	}
}

func transformToPool(obj interface{}) (interface{}, error) {
	switch concreteObj := obj.(type) {
	case *v2alpha1.CiliumPodIPPool:
		n := &v2alpha1.CiliumPodIPPool{
			TypeMeta: concreteObj.TypeMeta,
			ObjectMeta: v1.ObjectMeta{
				Name:            concreteObj.Name,
				ResourceVersion: concreteObj.ResourceVersion,
			},
			Spec: v2alpha1.IPPoolSpec{
				SubnetId: concreteObj.Spec.SubnetId,
			},
		}
		*concreteObj = v2alpha1.CiliumPodIPPool{}
		return n, nil
	case cache.DeletedFinalStateUnknown:
		p, ok := concreteObj.Obj.(*v2alpha1.CiliumPodIPPool)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &v2alpha1.CiliumPodIPPool{
				TypeMeta: p.TypeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name:            p.Name,
					ResourceVersion: p.ResourceVersion,
				},
				Spec: v2alpha1.IPPoolSpec{
					SubnetId: p.Spec.SubnetId,
				},
			},
		}
		// Small GC optimization
		*p = v2alpha1.CiliumPodIPPool{}
		return dfsu, nil
	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
	}
}

func updatePool(obj interface{}) {
	key, _ := queueKeyFunc(obj)
	p, exists, err := crdPoolStore.GetByKey(key)
	if err != nil {
		log.Errorf("waring: crd pool store get pool: %s error %s", key, err)
	}
	if !exists {
		return
	}
	if poolsToNodes[key] == nil {
		poolsToNodes[key] = map[string]struct{}{}
	} else {
		for node, _ := range poolsToNodes[key] {
			if k8sManager.nodeManager.pools[key].Spec.SubnetId != p.(*v2alpha1.CiliumPodIPPool).Spec.SubnetId {
				nodeToPools[node][key] = Updated
			}
		}
	}
	k8sManager.nodeManager.pools[key] = p.(*v2alpha1.CiliumPodIPPool)

}

func deletePool(obj interface{}) {
	key, _ := queueKeyFunc(obj)
	delete(k8sManager.nodeManager.pools, key)
}

func updateNode(obj interface{}) {
	key, _ := queueKeyFunc(obj)
	var retryCount int
loop:
	node, ok := k8sManager.nodeManager.nodes[key]
	if !ok && retryCount < 3 {
		<-time.After(1 * time.Second)
		retryCount++
		goto loop
	}
	if ok {
		err := k8sManager.nodeManager.SyncMultiPool(node)
		if err != nil {
			log.Error(err)
		}
	}
}

func compareNodeAnnotationAndLabelChange(oldObj, newObj interface{}) bool {
	oldAccessor, _ := meta.Accessor(oldObj)
	newAccessor, _ := meta.Accessor(newObj)
	if oldAccessor.GetAnnotations()[poolAnnotation] != newAccessor.GetAnnotations()[poolAnnotation] {
		return true
	}
	return false
}

func transformToStaticIP(obj interface{}) (interface{}, error) {
	switch concreteObj := obj.(type) {
	case *v2alpha1.CiliumStaticIP:
		n := &v2alpha1.CiliumStaticIP{
			TypeMeta: v1.TypeMeta{
				Kind:       concreteObj.Kind,
				APIVersion: concreteObj.APIVersion,
			},
			ObjectMeta: v1.ObjectMeta{
				Name:            concreteObj.Name,
				ResourceVersion: concreteObj.ResourceVersion,
			},
			Spec: v2alpha1.StaticIPSpec{
				IP:          concreteObj.Spec.IP,
				NodeName:    concreteObj.Spec.NodeName,
				Pool:        concreteObj.Spec.Pool,
				RecycleTime: concreteObj.Spec.RecycleTime,
			},
			Status: v2alpha1.StaticIPStatus{
				IPStatus:   concreteObj.Status.IPStatus,
				UpdateTime: concreteObj.Status.UpdateTime,
			},
		}
		*concreteObj = v2alpha1.CiliumStaticIP{}
		return n, nil
	case cache.DeletedFinalStateUnknown:
		p, ok := concreteObj.Obj.(*v2alpha1.CiliumStaticIP)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &v2alpha1.CiliumStaticIP{
				TypeMeta: p.TypeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name:            p.Name,
					ResourceVersion: p.ResourceVersion,
				},
				Spec: v2alpha1.StaticIPSpec{
					IP:          p.Spec.IP,
					NodeName:    p.Spec.NodeName,
					Pool:        p.Spec.Pool,
					RecycleTime: p.Spec.RecycleTime,
				},
				Status: v2alpha1.StaticIPStatus{
					IPStatus:   p.Status.IPStatus,
					UpdateTime: p.Status.UpdateTime,
				},
			},
		}
		// Small GC optimization
		*p = v2alpha1.CiliumStaticIP{}
		return dfsu, nil
	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
	}
}

func (m extraManager) updateStaticIP(ipCrd *v2alpha1.CiliumStaticIP) {
	k8sManager.updateMutex.Lock()
	defer k8sManager.updateMutex.Unlock()

	node := ipCrd.Spec.NodeName
	pool := ipCrd.Spec.Pool
	ip := ipCrd.Spec.IP
	switch ipCrd.Status.IPStatus {
	case v2alpha1.WaitingForAssign:
		log.Infof("@@@@@ pod: %v  WaitingForAssign", ipCrd.Name)
		log.Infof("@@@@@ updateStaticIP: %v %v  WaitingForAssign", pool, node)
		if n, ok := k8sManager.nodeManager.nodes[node]; ok {
			if p, ok := n.pools[Pool(pool)]; ok {
				log.Infof("@@@@@ pod: %v  allocateStaticIP start ", ipCrd.Name)
				err := p.allocateStaticIP(ip, Pool(pool))
				log.Infof("@@@@@ pod: %v  allocateStaticIP end", ipCrd.Name)

				if err != nil {
					log.Errorf("@@@ allocate static ip %v failed: %s", ip, err)
					return
				}
				k8sManager.requireSync(n)
				log.Errorf("@@@ allocate static ip success: %s, node : %v", ip, node)
				ipCrd.Status.IPStatus = v2alpha1.Assigned
				ipCrd.Status.UpdateTime = slim_metav1.Time(v1.Time{
					Time: time.Now(),
				})
				_, err = k8sManager.alphaClient.CiliumStaticIPs().Update(context.TODO(), ipCrd, v1.UpdateOptions{})
				if err != nil {
					log.Errorf("@@@@ update statip ip status failed: %s.", err)
					return
				}
			} else {
				log.Errorf("@@@ cant not found pool %v from node %v, assign cancel.", pool, n.name)
				return
			}
		} else {
			log.Errorf("@@@@ get node from nodeMap failed, assign cancel.")
			return
		}
		log.Infof("@@@@@ pod: %v  End", ipCrd.Name)
	case v2alpha1.Idle:
		if n, ok := k8sManager.nodeManager.nodes[node]; ok {
			if am, ok := n.resource.Spec.IPAM.CrdPools[pool]; ok {
				if a, ok := am[ip]; ok {
					if a.Resource != "" {
						action := &ReleaseAction{
							InterfaceID: a.Resource,
							IPsToRelease: []string{
								ip,
							},
						}
						log.Infof("@@@ ready to untie static ip %v", ip)
						err := n.Ops().UntieStaticIP(context.TODO(), action)
						if err != nil && !strings.Contains(err.Error(), "no address found attached in eni") {
							log.Infof("@@@ untie ip %v failed : %v", ip, err)
							return
						}
						k8sManager.requireSync(n)
						ipCrd.Status.IPStatus = v2alpha1.Untied
						ipCrd.Status.UpdateTime = slim_metav1.Time(v1.Time{
							Time: time.Now(),
						})
						_, err = k8sManager.alphaClient.CiliumStaticIPs().Update(context.TODO(), ipCrd, v1.UpdateOptions{})
						if err != nil {
							log.Infof("@@@ release ip success : %v ", ip)
						}
						return
					}
				}
			}
		}
	case v2alpha1.WaitingForRelease:
		if n, ok := k8sManager.nodeManager.nodes[node]; ok {
			if am, ok := n.resource.Spec.IPAM.CrdPools[pool]; ok {
				if a, ok := am[ip]; ok {
					if a.Resource != "" {
						log.Infoln("@@@ ready to release static ip")
						err := n.Ops().ReleaseStaticIP(ip, pool)
						if err != nil {
							log.Infof("@@@ release ip failed : %v", err)
							return
						}
						log.Infoln("@@@ release static ip success : %v ")
						err = k8sManager.alphaClient.CiliumStaticIPs().Delete(context.TODO(), ipCrd.Name, v1.DeleteOptions{})
						if err != nil {
							log.Errorf("@@@ delete csip crd failed %s", err)
							return
						}
					}
				}
			}
		}
	}

}

func (extraManager) listStaticIPs() []*v2alpha1.CiliumStaticIP {
	ipsInt := staticIPStore.List()
	out := make([]*v2alpha1.CiliumStaticIP, 0, len(ipsInt))
	for i := range ipsInt {
		out = append(out, ipsInt[i].(*v2alpha1.CiliumStaticIP))
	}
	return out
}

func (extraManager) maintainStaticIPCRDs(stop <-chan struct{}) {
	log.Debugln("@@@ static ip maintainer started")
	for {
		select {
		case <-time.After(defaultGCTime):
			log.Infof("@@ start maintainStaticIPCRDs")
			if k8sManager.reSyncNeeded() {
				for node := range k8sManager.reSyncMap {
					log.Infof("@@@@ node %v reSyncNeeded ", node.name)
					node.poolMaintainer.Trigger()
					node.k8sSync.Trigger()
				}
				k8sManager.reSyncCompleted()
			}

			ipCRDs := k8sManager.listStaticIPs()
			for _, ip := range ipCRDs {
				switch ip.Status.IPStatus {
				case v2alpha1.Untied:
					timeout := ip.Status.UpdateTime.Add(time.Second * time.Duration(ip.Spec.RecycleTime))
					if !timeout.After(time.Now()) {
						ipCopy := ip.DeepCopy()
						ipCopy.Status.IPStatus = v2alpha1.WaitingForRelease
						_, err := k8sManager.alphaClient.CiliumStaticIPs().Update(context.TODO(), ipCopy, v1.UpdateOptions{})
						if err != nil {
							log.Errorf("static ip maintainer update csip: %s failed, err is : %v", ip.Name, err)
						}
					}
				case v2alpha1.Idle:
					ipCopy := ip.DeepCopy()
					ipCopy.Status.UpdateTime = slim_metav1.Time(v1.Time{
						Time: time.Now(),
					})
					_, err := k8sManager.alphaClient.CiliumStaticIPs().Update(context.TODO(), ipCopy, v1.UpdateOptions{})
					if err != nil {
						log.Errorf("static ip maintainer update csip: %s failed, err is : %v", ip.Name, err)
					}
				case v2alpha1.Assigned:
					timeout := ip.Status.UpdateTime.Add(defaultAssignTimeOut)
					if !timeout.After(time.Now()) {
						ipCopy := ip.DeepCopy()
						ipCopy.Status.IPStatus = v2alpha1.Idle
						ipCopy.Status.UpdateTime = slim_metav1.Time(v1.Time{
							Time: time.Now(),
						})
						_, err := k8sManager.alphaClient.CiliumStaticIPs().Update(context.TODO(), ipCopy, v1.UpdateOptions{})
						if err != nil {
							log.Errorf("static ip maintainer update csip: %s failed, before status: %v,expect status: %v, err is: %v",
								ip.Name, v2alpha1.Assigned, v2alpha1.Idle, err)
						}
					} else if timeout.Sub(time.Now()) > 15*time.Second {
						if n, ok := k8sManager.nodeManager.nodes[ip.Spec.NodeName]; ok {
							n.k8sSync.Trigger()
						}
					}
				case v2alpha1.WaitingForRelease:
					ipCopy := ip.DeepCopy()
					ipCopy.Status.UpdateTime = slim_metav1.Time(v1.Time{
						Time: time.Now(),
					})
					_, err := k8sManager.alphaClient.CiliumStaticIPs().Update(context.TODO(), ipCopy, v1.UpdateOptions{})
					if err != nil {
						log.Errorf("static ip maintainer update csip: %s failed, status is :%s err is : %v",
							ip.Name, v2alpha1.WaitingForAssign, err)
					}
				case v2alpha1.WaitingForAssign:
					if !ip.Status.UpdateTime.Time.Add(defaultWaitingForAssignTimeOut).After(time.Now()) {
						ipCopy := ip.DeepCopy()
						ipCopy.Status.IPStatus = v2alpha1.Idle
						ipCopy.Status.UpdateTime = slim_metav1.Time(v1.Time{
							Time: time.Now(),
						})
						_, err := k8sManager.alphaClient.CiliumStaticIPs().Update(context.TODO(), ipCopy, v1.UpdateOptions{})
						if err != nil {
							log.Errorf("static ip maintainer update csip: %s failed, status is :%s err is : %v",
								ip.Name, v2alpha1.WaitingForAssign, err)
						}
					}
				case v2alpha1.InUse:
					if time.Now().Sub(ip.Status.UpdateTime.Time) < defaultInUseTimeOut {
						continue
					}
					if splits := strings.Split(ip.Name, "-"); len(splits) == 2 {
						pod, err := k8sManager.client.CoreV1().Pods(splits[0]).Get(context.TODO(), splits[1], v1.GetOptions{})
						if err != nil {
							log.Errorf("static ip maintainer get pod: %s failed, err is : %v", ip.Name, err)
						}
						if len(pod.Status.PodIPs) > 0 {
							continue
						}
						ipCopy := ip.DeepCopy()
						ipCopy.Status.IPStatus = v2alpha1.Idle
						ipCopy.Status.UpdateTime = slim_metav1.Time(v1.Time{
							Time: time.Now(),
						})
						_, err = k8sManager.alphaClient.CiliumStaticIPs().Update(context.TODO(), ipCopy, v1.UpdateOptions{})
						if err != nil {
							log.Errorf("static ip maintainer update csip: %s failed, before status: %v,expect status: %v, err is: %v",
								ip.Name, v2alpha1.InUse, v2alpha1.Idle, err)
						}
					}
				}
			}
		case <-stop:
			log.Debugln("@@@ static ip maintainer stopped")
			return
		}
	}
}
