// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by informer-gen. DO NOT EDIT.

package v2alpha1

import (
	"context"
	time "time"

	ciliumiov2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	versioned "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	internalinterfaces "github.com/cilium/cilium/pkg/k8s/client/informers/externalversions/internalinterfaces"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/listers/cilium.io/v2alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// CiliumStaticIPInformer provides access to a shared informer and lister for
// CiliumStaticIPs.
type CiliumStaticIPInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v2alpha1.CiliumStaticIPLister
}

type ciliumStaticIPInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewCiliumStaticIPInformer constructs a new informer for CiliumStaticIP type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewCiliumStaticIPInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredCiliumStaticIPInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredCiliumStaticIPInformer constructs a new informer for CiliumStaticIP type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredCiliumStaticIPInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CiliumV2alpha1().CiliumStaticIPs().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CiliumV2alpha1().CiliumStaticIPs().Watch(context.TODO(), options)
			},
		},
		&ciliumiov2alpha1.CiliumStaticIP{},
		resyncPeriod,
		indexers,
	)
}

func (f *ciliumStaticIPInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredCiliumStaticIPInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *ciliumStaticIPInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&ciliumiov2alpha1.CiliumStaticIP{}, f.defaultInformer)
}

func (f *ciliumStaticIPInformer) Lister() v2alpha1.CiliumStaticIPLister {
	return v2alpha1.NewCiliumStaticIPLister(f.Informer().GetIndexer())
}
