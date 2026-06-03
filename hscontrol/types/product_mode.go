// Copyright (c) Prvis contributors
// SPDX-License-Identifier: BSD-3-Clause

package types

// ProductMode controls privacy and logging behaviour.
// Set in headscale config.yaml as product_mode: horizon|glue
type ProductMode string

const (
	// ProductHorizon — enterprise, auditable.
	// Identity from IdP is authoritative.
	// Sessions, IPs, and events are logged.
	ProductHorizon ProductMode = "horizon"

	// ProductGlue — consumer, zero logs.
	// Identity is user-supplied, unverified.
	// Nothing about sessions or traffic is stored.
	ProductGlue ProductMode = "glue"
)

// IsGlue returns true when running in zero-log anonymous mode.
func (m ProductMode) IsGlue() bool { return m == ProductGlue }

// IsHorizon returns true when running in auditable enterprise mode.
func (m ProductMode) IsHorizon() bool { return m == ProductHorizon || m == "" }
