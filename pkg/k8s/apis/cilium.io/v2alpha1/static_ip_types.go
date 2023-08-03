// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	InUse             = "InUse"
	WaitingForAssign  = "WaitingForAssign"
	Idle              = "Idle"
	Assigned          = "Assigned"
	WaitingForRelease = "WaitingForRelease"
)

const (
	CiliumStaticIPAPIVersion = "cilium.io/v2alpha1"
	CiliumStaticIPKind       = "CiliumStaticIP"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumstaticip",path="ciliumstaticips",scope="Cluster",shortName={csip}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion

// CiliumStaticIP defines
type CiliumStaticIP struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec StaticIPSpec `json:"spec"`

	Status StaticIPStatus `json:"status"`
}

type StaticIPSpec struct {
	// +kubebuilder:validation:Required
	IP string `json:"ip"`

	Pool string `json:"pool"`

	// +kubebuilder:validation:Optional
	NodeName string `json:"node-name"`

	// +kubebuilder:validation:Optional
	RecycleTime int `json:"recycle-time"`
}

type StaticIPStatus struct {
	// +kubebuilder:validation:Optional
	IPStatus string `json:"ip-status"`

	// +kubebuilder:validation:Optional
	ReleaseTime v1.Time `json:"release-time"`

	// +kubebuilder:validation:Optional
	InterfaceId string `json:"interface-id"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumStaticIPList is a list of StaticIP objects.
type CiliumStaticIPList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of StaticIPs.
	Items []CiliumStaticIP `json:"items"`
}
