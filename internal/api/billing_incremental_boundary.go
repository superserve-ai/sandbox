package api

import "github.com/superserve-ai/sandbox/internal/billing"

// Interior hours use persisted rollups; only anniversary boundaries need raw usage.
const billingBoundaryUsageSQL = billing.ExportRemeasurementSQL
