package api

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/superserve-ai/sandbox/internal/billing/provisioning"
)

// ProvisionAcceptedOffer is an internal durable-consumer boundary. The configured
// adapter resolves exact acceptance and assignment authority from server storage.
func (h *Handlers) ProvisionAcceptedOffer(ctx context.Context, team, assignment uuid.UUID) (uuid.UUID, error) {
	return h.OfferProvisioning.Enqueue(ctx, team, assignment)
}
func (h *Handlers) AcceptedOfferProvisioningStatus(ctx context.Context, team, assignment uuid.UUID) (provisioning.Status, error) {
	return h.OfferProvisioning.Status(ctx, team, assignment)
}

func (h *Handlers) startOfferProvisioning(ctx context.Context) {
	if h.YCOfferAcceptance.available() {
		client, configured := h.Stripe.(*stripeHTTPClient)
		authority := &offerProvisioningAuthority{h: h, admission: &YCAcceptedProvisioningAdmission{Service: h.YCOfferAcceptance, Handlers: h}, client: client, successorRequester: RenewalSuccessorRequester, dispatchesResolved: CheckProviderPairDispatchesResolved}
		if h.ProviderPairEntitlementAuthority == nil {
			h.ProviderPairEntitlementAuthority = authority
		}
		// Revocation delivery must keep running if provider configuration or new
		// admission flags are disabled. It performs no provider mutations.
		go authority.runFinancialInvalidations(ctx)
		if h.OfferProvisioning == nil && configured {
			h.OfferProvisioning = &provisioning.Service{Pool: h.Pool, Authority: authority, Provider: &offerProvisioningProvider{client: client}}
		}
		if h.OfferProvisioning.Available() && h.YCOfferAcceptance.Provisioning == nil {
			// The earlier acceptance startup initialized its service but could not
			// start its consumer until the complete provisioning adapter existed.
			h.StartYCOfferAcceptance(ctx)
		}
	}
	service := h.OfferProvisioning
	if !service.Available() {
		return
	}
	go func() {
		var observedAt time.Time
		for ctx.Err() == nil {
			started := time.Now()
			count, err := service.RunBatch(ctx)
			currentBillingRecorder().RecordBillingWork(ctx, "offer_provisioning", err != nil, time.Since(started), int64(count))
			if err != nil {
				log.Warn().Msg("offer provisioning reconciliation requires recovery")
			}
			if time.Since(observedAt) >= time.Minute {
				observe, cancel := context.WithTimeout(ctx, 2*time.Second)
				pending, oldest, observeErr := service.PendingDispatches(observe)
				cancel()
				observedAt = time.Now()
				if observeErr != nil {
					log.Warn().Msg("offer provisioning pending dispatch observation failed")
				} else if oldest >= 15*time.Minute {
					log.Warn().Int64("pending_dispatch_count", pending).Dur("oldest_pending_age", oldest).Msg("offer provisioning dispatch requires operator recovery")
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
}
