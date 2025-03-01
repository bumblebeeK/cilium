// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_openstack

package cmd

import (
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	flags := rootCmd.Flags()

	flags.String(operatorOption.OpenStackProjectID, "", "Specific project ID for OpenStack.")
	option.BindEnv(Vp, operatorOption.OpenStackProjectID)
	flags.Bool(operatorOption.OpenStackReleaseExcessIPs, true, "Enable releasing excess free IP addresses from OpenStack.")
	option.BindEnv(Vp, operatorOption.OpenStackReleaseExcessIPs)
	flags.String(operatorOption.OpenStackDefaultSubnetID, "", "Specific subnet ID for OpenStack to create default pool")
	option.BindEnv(Vp, operatorOption.OpenStackDefaultSubnetID)

	Vp.BindPFlags(flags)
}
