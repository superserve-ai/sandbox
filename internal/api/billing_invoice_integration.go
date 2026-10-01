//go:build integration

package api

import (
	"context"
	"github.com/superserve-ai/sandbox/internal/billing"
	"time"
)

func (h *Handlers) ReconcileInvoiceForTest(ctx context.Context, p billing.ExportPeriod) error {
	return h.reconcileInvoicePeriod(ctx, p)
}

func (h *Handlers) InvoiceEnrollmentTickForTest(ctx context.Context) (bool, error) {
	return h.invoiceEnrollmentTick(ctx)
}

func (h *Handlers) VerifyInvoiceExportHoldForTest(ctx context.Context, p billing.ExportPeriod) error {
	return h.verifyInvoiceExportHold(ctx, p)
}

func (h *Handlers) ExportInvoicePeriodForTest(ctx context.Context, p billing.ExportPeriod) error {
	_, err := h.exportIncrementalPeriod(ctx, p)
	return err
}

func (h *Handlers) InvoiceReconciliationTickForTest(ctx context.Context) (bool, error) {
	return h.invoiceReconciliationTick(ctx)
}
func (h *Handlers) IncrementalBillingTickForTest(ctx context.Context) (bool, int, error) {
	return h.incrementalBillingTick(ctx, time.Hour)
}
func (h *Handlers) DiscoverIncrementalBillingWorkForTest(ctx context.Context) error {
	return h.discoverIncrementalBillingWork(ctx)
}
