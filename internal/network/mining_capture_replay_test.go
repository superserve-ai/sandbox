package network

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/abuse"
)

func TestMiningHistoricalAppliedReceiptCannotContainReplacement(t *testing.T) {
	c, source, gate, delivery := miningFixture()
	original := source.p
	if !c.Observe(original.SandboxID, original.HostIP, abuse.MiningEvidence{Kind: "domain", Indicator: "pool.invalid"}) {
		t.Fatal("original observation not captured")
	}
	captured := delivery.items[0]
	source.change(func(p *abuse.SandboxPolicy) {
		p.SandboxID, p.TeamID, p.Assignment = uuid.New(), uuid.New(), "replacement-session"
	})
	if err := c.Reconcile(); err != nil {
		t.Fatal(err)
	}
	// A retired observation may first acquire its durable team restriction
	// after the host has already replaced the pooled network assignment.
	if err := c.Receipt(context.Background(), captured, abuse.IncidentReceipt{IncidentID: captured.ID, Disposition: abuse.IncidentApplied}); err != nil {
		t.Fatal(err)
	}
	if gate.on[original.HostIP] || c.Blocked(source.p.SandboxID, source.p.HostIP) {
		t.Fatal("historical quarantine transferred to replacement network session")
	}
}
