// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeCiliumStaticIPs implements CiliumStaticIPInterface
type FakeCiliumStaticIPs struct {
	Fake *FakeCiliumV2alpha1
}

var ciliumstaticipsResource = v2alpha1.SchemeGroupVersion.WithResource("ciliumstaticips")

var ciliumstaticipsKind = v2alpha1.SchemeGroupVersion.WithKind("CiliumStaticIP")

// Get takes name of the ciliumStaticIP, and returns the corresponding ciliumStaticIP object, and an error if there is any.
func (c *FakeCiliumStaticIPs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v2alpha1.CiliumStaticIP, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(ciliumstaticipsResource, name), &v2alpha1.CiliumStaticIP{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2alpha1.CiliumStaticIP), err
}

// List takes label and field selectors, and returns the list of CiliumStaticIPs that match those selectors.
func (c *FakeCiliumStaticIPs) List(ctx context.Context, opts v1.ListOptions) (result *v2alpha1.CiliumStaticIPList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(ciliumstaticipsResource, ciliumstaticipsKind, opts), &v2alpha1.CiliumStaticIPList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v2alpha1.CiliumStaticIPList{ListMeta: obj.(*v2alpha1.CiliumStaticIPList).ListMeta}
	for _, item := range obj.(*v2alpha1.CiliumStaticIPList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested ciliumStaticIPs.
func (c *FakeCiliumStaticIPs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(ciliumstaticipsResource, opts))
}

// Create takes the representation of a ciliumStaticIP and creates it.  Returns the server's representation of the ciliumStaticIP, and an error, if there is any.
func (c *FakeCiliumStaticIPs) Create(ctx context.Context, ciliumStaticIP *v2alpha1.CiliumStaticIP, opts v1.CreateOptions) (result *v2alpha1.CiliumStaticIP, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(ciliumstaticipsResource, ciliumStaticIP), &v2alpha1.CiliumStaticIP{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2alpha1.CiliumStaticIP), err
}

// Update takes the representation of a ciliumStaticIP and updates it. Returns the server's representation of the ciliumStaticIP, and an error, if there is any.
func (c *FakeCiliumStaticIPs) Update(ctx context.Context, ciliumStaticIP *v2alpha1.CiliumStaticIP, opts v1.UpdateOptions) (result *v2alpha1.CiliumStaticIP, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(ciliumstaticipsResource, ciliumStaticIP), &v2alpha1.CiliumStaticIP{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2alpha1.CiliumStaticIP), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeCiliumStaticIPs) UpdateStatus(ctx context.Context, ciliumStaticIP *v2alpha1.CiliumStaticIP, opts v1.UpdateOptions) (*v2alpha1.CiliumStaticIP, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(ciliumstaticipsResource, "status", ciliumStaticIP), &v2alpha1.CiliumStaticIP{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2alpha1.CiliumStaticIP), err
}

// Delete takes name of the ciliumStaticIP and deletes it. Returns an error if one occurs.
func (c *FakeCiliumStaticIPs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(ciliumstaticipsResource, name, opts), &v2alpha1.CiliumStaticIP{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeCiliumStaticIPs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(ciliumstaticipsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v2alpha1.CiliumStaticIPList{})
	return err
}

// Patch applies the patch and returns the patched ciliumStaticIP.
func (c *FakeCiliumStaticIPs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2alpha1.CiliumStaticIP, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(ciliumstaticipsResource, name, pt, data, subresources...), &v2alpha1.CiliumStaticIP{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2alpha1.CiliumStaticIP), err
}
