// Copyright (c) vpngw contributors
// SPDX-License-Identifier: BSD-3-Clause

package hscontrol

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
	"tailscale.com/util/zlog/zf"

	"github.com/juanfont/headscale/hscontrol/types"
)

// UpdateGatewayPolicyRequest is the JSON body for PUT /api/v1/vpngw/node/{nodeId}/gateway-policy.
type UpdateGatewayPolicyRequest struct {
	// Profiles is the list of LAN subnet → exit node → security level mappings.
	// An empty slice removes all gateway profiles from the node.
	Profiles []types.GatewayProfile `json:"profiles"`

	// FailMode controls agent behaviour on control server disconnect.
	// "open"   — keep last-applied routes running (default, availability-first)
	// "closed" — tear down routes (security-first)
	FailMode string `json:"failMode"`
}

// UpdateGatewayPolicyResponse is the JSON response.
type UpdateGatewayPolicyResponse struct {
	NodeID               uint64 `json:"nodeId"`
	GatewayPolicyVersion uint64 `json:"gatewayPolicyVersion"`
	ProfileCount         int    `json:"profileCount"`
}

// UpdateGatewayPolicyHandler handles:
//
//	PUT /api/v1/vpngw/node/{nodeId}/gateway-policy
//
// Sets the gateway profiles for a node. The node must be tagged tag:gateway.
// On success, Headscale immediately pushes a MapResponse to the node so the
// agent applies the new routing policy without waiting for the next poll.
func (h *Headscale) UpdateGatewayPolicyHandler(w http.ResponseWriter, r *http.Request) {
	nodeIDStr := chi.URLParam(r, "nodeId")
	nodeID, err := strconv.ParseUint(nodeIDStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid nodeId: must be a uint64", http.StatusBadRequest)
		return
	}

	var req UpdateGatewayPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Default failMode to "open" if not specified.
	if req.FailMode == "" {
		req.FailMode = "open"
	}
	if req.FailMode != "open" && req.FailMode != "closed" {
		http.Error(w, `failMode must be "open" or "closed"`, http.StatusBadRequest)
		return
	}

	// Validate profiles.
	for i, p := range req.Profiles {
		if p.ID == "" {
			http.Error(w, "profile["+strconv.Itoa(i)+"].id must not be empty", http.StatusBadRequest)
			return
		}
		if !p.SourceSubnet.IsValid() {
			http.Error(w, "profile["+strconv.Itoa(i)+"].sourceSubnet is invalid", http.StatusBadRequest)
			return
		}
		if p.ExitNodeID == "" {
			http.Error(w, "profile["+strconv.Itoa(i)+"].exitNodeID must not be empty", http.StatusBadRequest)
			return
		}
	}

	node, nodeChange, err := h.state.UpdateGatewayPolicy(
		types.NodeID(nodeID),
		types.GatewayProfiles(req.Profiles),
		req.FailMode,
	)
	if err != nil {
		log.Error().
			Err(err).
			Uint64("nodeId", nodeID).
			Msg("vpngw: UpdateGatewayPolicy failed")
		http.Error(w, "updating gateway policy: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Push MapResponse to the node immediately.
	// The agent receives the new CapGatewayPolicy and applies it without waiting.
	h.Change(nodeChange)

	log.Info().
		Str(zf.Node, node.Hostname()).
		Uint64("nodeId", nodeID).
		Uint64("version", node.GatewayPolicyVersion()).
		Int("profiles", len(req.Profiles)).
		Str("failMode", req.FailMode).
		Msg("vpngw: gateway policy updated")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(UpdateGatewayPolicyResponse{
		NodeID:               nodeID,
		GatewayPolicyVersion: node.GatewayPolicyVersion(),
		ProfileCount:         len(req.Profiles),
	})
}
