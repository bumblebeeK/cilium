//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by deepequal-gen. DO NOT EDIT.

package types

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *AllocationIP) DeepEqual(other *AllocationIP) bool {
	if other == nil {
		return false
	}

	if in.Owner != other.Owner {
		return false
	}
	if in.Resource != other.Resource {
		return false
	}
	if in.Pool != other.Pool {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *AllocationMap) DeepEqual(other *AllocationMap) bool {
	if other == nil {
		return false
	}

	if len(*in) != len(*other) {
		return false
	} else {
		for key, inValue := range *in {
			if otherValue, present := (*other)[key]; !present {
				return false
			} else {
				if !inValue.DeepEqual(&otherValue) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IPAMPoolAllocation) DeepEqual(other *IPAMPoolAllocation) bool {
	if other == nil {
		return false
	}

	if in.Pool != other.Pool {
		return false
	}
	if ((in.CIDRs != nil) && (other.CIDRs != nil)) || ((in.CIDRs == nil) != (other.CIDRs == nil)) {
		in, other := &in.CIDRs, &other.CIDRs
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IPAMPoolDemand) DeepEqual(other *IPAMPoolDemand) bool {
	if other == nil {
		return false
	}

	if in.IPv4Addrs != other.IPv4Addrs {
		return false
	}
	if in.IPv6Addrs != other.IPv6Addrs {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IPAMPoolRequest) DeepEqual(other *IPAMPoolRequest) bool {
	if other == nil {
		return false
	}

	if in.Pool != other.Pool {
		return false
	}
	if in.Needed != other.Needed {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IPAMPoolSpec) DeepEqual(other *IPAMPoolSpec) bool {
	if other == nil {
		return false
	}

	if ((in.Requested != nil) && (other.Requested != nil)) || ((in.Requested == nil) != (other.Requested == nil)) {
		in, other := &in.Requested, &other.Requested
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	if ((in.Allocated != nil) && (other.Allocated != nil)) || ((in.Allocated == nil) != (other.Allocated == nil)) {
		in, other := &in.Allocated, &other.Allocated
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IPAMSpec) DeepEqual(other *IPAMSpec) bool {
	if other == nil {
		return false
	}

	if ((in.Pool != nil) && (other.Pool != nil)) || ((in.Pool == nil) != (other.Pool == nil)) {
		in, other := &in.Pool, &other.Pool
		if other == nil || !in.DeepEqual(other) {
			return false
		}
	}

	if !in.Pools.DeepEqual(&other.Pools) {
		return false
	}

	if ((in.CrdPools != nil) && (other.CrdPools != nil)) || ((in.CrdPools == nil) != (other.CrdPools == nil)) {
		in, other := &in.CrdPools, &other.CrdPools
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for key, inValue := range *in {
				if otherValue, present := (*other)[key]; !present {
					return false
				} else {
					if !inValue.DeepEqual(&otherValue) {
						return false
					}
				}
			}
		}
	}

	if ((in.PodCIDRs != nil) && (other.PodCIDRs != nil)) || ((in.PodCIDRs == nil) != (other.PodCIDRs == nil)) {
		in, other := &in.PodCIDRs, &other.PodCIDRs
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	if in.MinAllocate != other.MinAllocate {
		return false
	}
	if in.MaxAllocate != other.MaxAllocate {
		return false
	}
	if in.PreAllocate != other.PreAllocate {
		return false
	}
	if in.MaxAboveWatermark != other.MaxAboveWatermark {
		return false
	}
	if in.PodCIDRAllocationThreshold != other.PodCIDRAllocationThreshold {
		return false
	}
	if in.PodCIDRReleaseThreshold != other.PodCIDRReleaseThreshold {
		return false
	}
	if in.EnableMultiPool != other.EnableMultiPool {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IPAMStatus) DeepEqual(other *IPAMStatus) bool {
	if other == nil {
		return false
	}

	if ((in.Used != nil) && (other.Used != nil)) || ((in.Used == nil) != (other.Used == nil)) {
		in, other := &in.Used, &other.Used
		if other == nil || !in.DeepEqual(other) {
			return false
		}
	}

	if ((in.PoolUsed != nil) && (other.PoolUsed != nil)) || ((in.PoolUsed == nil) != (other.PoolUsed == nil)) {
		in, other := &in.PoolUsed, &other.PoolUsed
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for key, inValue := range *in {
				if otherValue, present := (*other)[key]; !present {
					return false
				} else {
					if !inValue.DeepEqual(&otherValue) {
						return false
					}
				}
			}
		}
	}

	if ((in.PodCIDRs != nil) && (other.PodCIDRs != nil)) || ((in.PodCIDRs == nil) != (other.PodCIDRs == nil)) {
		in, other := &in.PodCIDRs, &other.PodCIDRs
		if other == nil || !in.DeepEqual(other) {
			return false
		}
	}

	if in.OperatorStatus != other.OperatorStatus {
		return false
	}

	if ((in.ReleaseIPs != nil) && (other.ReleaseIPs != nil)) || ((in.ReleaseIPs == nil) != (other.ReleaseIPs == nil)) {
		in, other := &in.ReleaseIPs, &other.ReleaseIPs
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for key, inValue := range *in {
				if otherValue, present := (*other)[key]; !present {
					return false
				} else {
					if inValue != otherValue {
						return false
					}
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *Limits) DeepEqual(other *Limits) bool {
	if other == nil {
		return false
	}

	if in.Adapters != other.Adapters {
		return false
	}
	if in.IPv4 != other.IPv4 {
		return false
	}
	if in.IPv6 != other.IPv6 {
		return false
	}
	if in.HypervisorType != other.HypervisorType {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *OperatorStatus) DeepEqual(other *OperatorStatus) bool {
	if other == nil {
		return false
	}

	if in.Error != other.Error {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *PodCIDRMap) DeepEqual(other *PodCIDRMap) bool {
	if other == nil {
		return false
	}

	if len(*in) != len(*other) {
		return false
	} else {
		for key, inValue := range *in {
			if otherValue, present := (*other)[key]; !present {
				return false
			} else {
				if !inValue.DeepEqual(&otherValue) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *PodCIDRMapEntry) DeepEqual(other *PodCIDRMapEntry) bool {
	if other == nil {
		return false
	}

	if in.Status != other.Status {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *PoolQuota) DeepEqual(other *PoolQuota) bool {
	if other == nil {
		return false
	}

	if in.AvailabilityZone != other.AvailabilityZone {
		return false
	}
	if in.AvailableIPs != other.AvailableIPs {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *PoolQuotaMap) DeepEqual(other *PoolQuotaMap) bool {
	if other == nil {
		return false
	}

	if len(*in) != len(*other) {
		return false
	} else {
		for key, inValue := range *in {
			if otherValue, present := (*other)[key]; !present {
				return false
			} else {
				if !inValue.DeepEqual(&otherValue) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *Subnet) DeepEqual(other *Subnet) bool {
	if other == nil {
		return false
	}

	if in.ID != other.ID {
		return false
	}
	if in.Name != other.Name {
		return false
	}
	if (in.CIDR == nil) != (other.CIDR == nil) {
		return false
	} else if in.CIDR != nil {
		if !in.CIDR.DeepEqual(other.CIDR) {
			return false
		}
	}

	if in.AvailabilityZone != other.AvailabilityZone {
		return false
	}
	if in.VirtualNetworkID != other.VirtualNetworkID {
		return false
	}
	if in.AvailableAddresses != other.AvailableAddresses {
		return false
	}
	if ((in.Tags != nil) && (other.Tags != nil)) || ((in.Tags == nil) != (other.Tags == nil)) {
		in, other := &in.Tags, &other.Tags
		if other == nil || !in.DeepEqual(other) {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *SubnetMap) DeepEqual(other *SubnetMap) bool {
	if other == nil {
		return false
	}

	if len(*in) != len(*other) {
		return false
	} else {
		for key, inValue := range *in {
			if otherValue, present := (*other)[key]; !present {
				return false
			} else {
				if !inValue.DeepEqual(otherValue) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *Tags) DeepEqual(other *Tags) bool {
	if other == nil {
		return false
	}

	if len(*in) != len(*other) {
		return false
	} else {
		for key, inValue := range *in {
			if otherValue, present := (*other)[key]; !present {
				return false
			} else {
				if inValue != otherValue {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *VirtualNetwork) DeepEqual(other *VirtualNetwork) bool {
	if other == nil {
		return false
	}

	if in.ID != other.ID {
		return false
	}
	if in.PrimaryCIDR != other.PrimaryCIDR {
		return false
	}
	if ((in.CIDRs != nil) && (other.CIDRs != nil)) || ((in.CIDRs == nil) != (other.CIDRs == nil)) {
		in, other := &in.CIDRs, &other.CIDRs
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *VirtualNetworkMap) DeepEqual(other *VirtualNetworkMap) bool {
	if other == nil {
		return false
	}

	if len(*in) != len(*other) {
		return false
	} else {
		for key, inValue := range *in {
			if otherValue, present := (*other)[key]; !present {
				return false
			} else {
				if !inValue.DeepEqual(otherValue) {
					return false
				}
			}
		}
	}

	return true
}
