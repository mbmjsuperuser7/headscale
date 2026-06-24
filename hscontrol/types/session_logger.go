// Copyright (c) Prvis contributors
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"net/netip"
	"time"
)

// SessionEvent is a loggable event in the Horizon audit trail.
// Glue's implementation discards all events at write time —
// nothing is stored, nothing can be subpoenaed.
type SessionEvent struct {
	// Timestamp is when the event occurred.
	Timestamp time.Time

	// Namespace is the Headscale namespace (tenant).
	Namespace string

	// NodeID is the stable node identifier.
	NodeID string

	// NodeName is whatever name is stored for this node.
	// In Horizon: IdP-sourced. In Glue: user-supplied or blank.
	NodeName string

	// EventType identifies what happened.
	EventType SessionEventType

	// SrcIP is the source IP of the connection.
	// Horizon: stored. Glue: never populated, never written.
	SrcIP *netip.Addr

	// ExitNodeID is which exit node handled traffic, if any.
	// Horizon: stored. Glue: never populated.
	ExitNodeID string

	// BytesIn / BytesOut session totals.
	// Horizon: stored. Glue: never populated.
	BytesIn  uint64
	BytesOut uint64
}

// SessionEventType classifies audit log entries.
type SessionEventType string

const (
	EventNodeRegistered   SessionEventType = "node.registered"
	EventNodeConnected    SessionEventType = "node.connected"
	EventNodeDisconnected SessionEventType = "node.disconnected"
	EventNodeExpired      SessionEventType = "node.expired"
	EventPolicyChanged    SessionEventType = "policy.changed"
	EventRouteApplied     SessionEventType = "route.applied"
	EventDriftCorrected   SessionEventType = "drift.corrected"
)

// SessionLogger is the audit log interface.
// Horizon: writes to DB + exports to SIEM.
// Glue:    discards everything — the no-op implementation
//          is the privacy guarantee, not a config flag.
type SessionLogger interface {
	// Log records a session event.
	// Glue's implementation is a documented no-op.
	Log(event SessionEvent)

	// Export sends events to the configured SIEM webhook.
	// Horizon only. Glue's implementation returns immediately.
	Export(events []SessionEvent) error

	// Flush persists any buffered events.
	// Glue's implementation returns immediately.
	Flush() error
}

// GlueLogger discards all events.
// This is the privacy guarantee — not a config flag that could be
// accidentally enabled. The Glue binary contains only this implementation.
// There is no code path that writes session data in Glue.
type GlueLogger struct{}

// NewGlueLogger returns the no-op logger for Glue deployments.
func NewGlueLogger() SessionLogger { return &GlueLogger{} }

// Log discards the event. By design. No data written anywhere.
func (l *GlueLogger) Log(_ SessionEvent) {}

// Export is a no-op. Nothing was logged, nothing to export.
func (l *GlueLogger) Export(_ []SessionEvent) error { return nil }

// Flush is a no-op.
func (l *GlueLogger) Flush() error { return nil }
