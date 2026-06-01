// Copyright (c) vpngw contributors
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/netip"
)

// GatewayProfile maps one LAN source subnet to a routing policy.
// Delivered to the agent via MapResponse.Node.CapMap[CapGatewayPolicy].
type GatewayProfile struct {
	// ID is a stable opaque identifier for this profile.
	// Used by the agent to correlate ACKs and detect stale state.
	ID string `json:"id"`

	// SourceSubnet is the LAN subnet this profile governs.
	SourceSubnet netip.Prefix `json:"sourceSubnet"`

	// ExitNodeID is the stable StableNodeID of the WireGuard peer
	// that carries internet traffic for this subnet.
	// Headscale resolves tag references to concrete IDs before sending.
	ExitNodeID string `json:"exitNodeID"`

	// SecurityLevel controls firewall enforcement.
	// "open"      — route only, no extra firewall rules
	// "encrypted" — require WireGuard tunnel
	// "full"      — tunnel + DNS override + block WAN bypass
	SecurityLevel string `json:"securityLevel"`

	// FailMode controls agent behaviour on control server disconnect.
	// "open"   — keep last-applied routes (availability-first)
	// "closed" — tear down routes (security-first)
	FailMode string `json:"failMode"`

	// DNSOverride, if set, forces DNS for this subnet to this address.
	DNSOverride *netip.Addr `json:"dnsOverride,omitempty"`
}

// GatewayProfiles is a slice of GatewayProfile that implements
// GORM's serializer interface for JSON column storage.
type GatewayProfiles []GatewayProfile

func (g GatewayProfiles) Value() (driver.Value, error) {
	if len(g) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(g)
	if err != nil {
		return nil, fmt.Errorf("gateway_profiles marshal: %w", err)
	}
	return string(b), nil
}

func (g *GatewayProfiles) Scan(value any) error {
	var b []byte
	switch v := value.(type) {
	case string:
		b = []byte(v)
	case []byte:
		b = v
	case nil:
		*g = GatewayProfiles{}
		return nil
	default:
		return fmt.Errorf("gateway_profiles: unsupported type %T", value)
	}
	return json.Unmarshal(b, g)
}

// CapGatewayPolicy is the NodeCapability key for gateway policy.
// Value in CapMap is JSON-encoded GatewayPolicyCap.
const CapGatewayPolicy = "vpngw:gateway-policy"

// GatewayPolicyCap is the JSON payload in CapMap[CapGatewayPolicy].
type GatewayPolicyCap struct {
	Version  uint64           `json:"version"`
	Profiles []GatewayProfile `json:"profiles"`
	FailMode string           `json:"failMode"`
}
