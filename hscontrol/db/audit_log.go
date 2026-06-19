// Copyright (c) Prvis contributors
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"gorm.io/gorm"

	"github.com/juanfont/headscale/hscontrol/types"
)

// AuditLogEntry is the DB model for Horizon session events.
// Retention: 30 days (enforced by PruneAuditLogs).
type AuditLogEntry struct {
	ID         uint64    `gorm:"primarykey;autoIncrement"`
	CreatedAt  time.Time `gorm:"index"`
	Namespace  string    `gorm:"index;not null"`
	NodeID     string    `gorm:"index"`
	NodeName   string
	EventType  string `gorm:"index;not null"`
	SrcIP      string
	ExitNodeID string
	BytesIn    uint64
	BytesOut   uint64
}

type horizonLoggerDB struct {
	db         *gorm.DB
	webhookURL string
	namespace  string
	buf        chan types.SessionEvent
	done       chan struct{}
}

func NewHorizonLoggerDB(db *gorm.DB, webhookURL, namespace string) types.SessionLogger {
	l := &horizonLoggerDB{
		db: db, webhookURL: webhookURL, namespace: namespace,
		buf: make(chan types.SessionEvent, 512), done: make(chan struct{}),
	}
	go l.flushLoop()
	return l
}

func (l *horizonLoggerDB) Log(event types.SessionEvent) {
	event.Namespace = l.namespace
	if event.Timestamp.IsZero() { event.Timestamp = time.Now() }
	select { case l.buf <- event: default: }
}

func (l *horizonLoggerDB) Export(events []types.SessionEvent) error {
	if l.webhookURL == "" || len(events) == 0 { return nil }
	payload, err := json.Marshal(struct{ Events []types.SessionEvent `json:"events"` }{Events: events})
	if err != nil { return fmt.Errorf("audit export marshal: %w", err) }
	resp, err := http.Post(l.webhookURL, "application/json", bytes.NewReader(payload))
	if err != nil { return fmt.Errorf("audit export POST: %w", err) }
	defer resp.Body.Close()
	if resp.StatusCode >= 400 { return fmt.Errorf("audit export: SIEM returned %d", resp.StatusCode) }
	return nil
}

func (l *horizonLoggerDB) Flush() error { close(l.buf); <-l.done; return nil }

func (l *horizonLoggerDB) flushLoop() {
	defer close(l.done)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var pending []types.SessionEvent
	flush := func() {
		if len(pending) == 0 { return }
		entries := make([]AuditLogEntry, 0, len(pending))
		for _, e := range pending {
			entry := AuditLogEntry{
				CreatedAt: e.Timestamp, Namespace: e.Namespace,
				NodeID: e.NodeID, NodeName: e.NodeName,
				EventType: string(e.EventType), ExitNodeID: e.ExitNodeID,
				BytesIn: e.BytesIn, BytesOut: e.BytesOut,
			}
			if e.SrcIP != nil { entry.SrcIP = e.SrcIP.String() }
			entries = append(entries, entry)
		}
		l.db.CreateInBatches(entries, 100)
		_ = l.Export(pending)
		pending = pending[:0]
	}
	for {
		select {
		case event, ok := <-l.buf:
			if !ok { flush(); return }
			pending = append(pending, event)
			if len(pending) >= 100 { flush() }
		case <-ticker.C:
			flush()
		}
	}
}

func PruneAuditLogs(db *gorm.DB) error {
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	return db.Where("created_at < ?", cutoff).Delete(&AuditLogEntry{}).Error
}
