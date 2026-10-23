package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// The verifier checks the immutable fee/usage pair and complete writable phase
// settings. Unknown fields, foreign schedules and incomplete inventories fail
// closed. Ownership comes from durable creation history, not an ID or metadata.
type renewalScheduleSnapshot struct {
	BindingHash  string
	Schedule     string
	Owned        bool
	Anchor       time.Time
	Boundary     time.Time
	CurrentPhase url.Values
}
type renewalScheduleVerifier interface {
	Inspect(context.Context, renewalChoiceKey, renewalChoiceOperation) (renewalScheduleSnapshot, error)
	ObserveStep(context.Context, renewalChoiceKey, renewalChoiceOperation, renewalChoiceStepRequest) (renewalChoiceStepProof, error)
	ObserveChoice(context.Context, renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error)
}

type renewalScheduleProvider struct {
	Client   *stripeHTTPClient
	Merchant string
	Verifier renewalScheduleVerifier
	// Registration requires reviewed exact-boundary write safety. Local clocks
	// and a preflight GET do not close the provider's in-flight boundary race.
	BoundaryWritesVerified bool
}

func (p *renewalScheduleProvider) ready(op renewalChoiceOperation) bool {
	return p != nil && p.Client != nil && p.Client.httpClient != nil && p.Client.apiVersion == renewalStripeVersion && p.Merchant == op.Binding.Merchant && p.Verifier != nil && p.BoundaryWritesVerified
}
func (p *renewalScheduleProvider) Dispatch(context.Context, renewalChoiceKey, renewalChoiceOperation) (renewalChoiceProof, error) {
	return renewalChoiceProof{}, errRenewalDisabled
}
func (p *renewalScheduleProvider) Observe(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceProof, error) {
	if p == nil || p.Verifier == nil {
		return renewalChoiceProof{}, errRenewalDisabled
	}
	return p.Verifier.ObserveChoice(ctx, k, op)
}
func (p *renewalScheduleProvider) PrepareStep(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation) (renewalChoiceStepRequest, error) {
	if !p.ready(op) {
		return renewalChoiceStepRequest{}, errRenewalDisabled
	}
	snapshot, err := p.Verifier.Inspect(ctx, k, op)
	if err != nil {
		return renewalChoiceStepRequest{}, err
	}
	return buildRenewalScheduleStep(k, op, snapshot)
}

func buildRenewalScheduleStep(k renewalChoiceKey, op renewalChoiceOperation, snapshot renewalScheduleSnapshot) (renewalChoiceStepRequest, error) {
	var r renewalChoiceStepRequest
	if !validRenewalKey(k) || !validRenewalBinding(op.Binding, k) || snapshot.BindingHash != renewalHash(op.Binding) || !snapshot.Anchor.Equal(op.Binding.Anchor) || !snapshot.Boundary.Equal(k.Boundary) {
		return r, errRenewalConflict
	}
	form := url.Values{}
	if snapshot.Schedule == "" {
		if len(op.Steps) != 0 {
			return r, errRenewalPending
		}
		r.Kind = "create_schedule"
		r.Path = "/v1/subscription_schedules"
		form.Set("from_subscription", op.Binding.Fee)
	} else {
		if !snapshot.Owned {
			return r, errRenewalConflict
		}
		r.Kind = "update_schedule"
		r.Schedule = snapshot.Schedule
		r.Path = "/v1/subscription_schedules/" + snapshot.Schedule
		// The normalized current phase includes every setting that would otherwise
		// be cleared by a schedule update, including the current one-time discount.
		for name, values := range snapshot.CurrentPhase {
			if !strings.HasPrefix(name, "phases[0][") || len(values) != 1 {
				return r, errRenewalConflict
			}
			form[name] = append([]string(nil), values...)
		}
		if form.Get("phases[0][start_date]") != strconv.FormatInt(op.Binding.Anchor.Unix(), 10) || form.Get("phases[0][end_date]") != strconv.FormatInt(k.Boundary.Unix(), 10) || form.Get("phases[0][items][0][price]") == "" || form.Get("phases[0][items][0][quantity]") != "1" || form.Get("phases[0][collection_method]") != "charge_automatically" {
			return r, errRenewalConflict
		}
		form.Set("proration_behavior", "none")
		form.Set("phases[0][proration_behavior]", "none")
		form.Set("end_behavior", "release")
		switch op.Request.Choice {
		case "free":
			form.Set("end_behavior", "cancel")
		case "annual":
			if validateRenewalTerms("annual", op.Terms) != nil || op.Terms.Price != form.Get("phases[0][items][0][price]") {
				return r, errRenewalConflict
			}
		case "monthly":
			if validateRenewalTerms("monthly", op.Terms) != nil {
				return r, errRenewalConflict
			}
			form.Set("phases[1][start_date]", strconv.FormatInt(k.Boundary.Unix(), 10))
			form.Set("phases[1][duration][interval]", "month")
			form.Set("phases[1][duration][interval_count]", "1")
			form.Set("phases[1][items][0][price]", op.Terms.Price)
			form.Set("phases[1][items][0][quantity]", "1")
			form.Set("phases[1][proration_behavior]", "none")
			form.Set("phases[1][collection_method]", "charge_automatically")
			form.Set("phases[1][discounts]", "")
		default:
			return r, errRenewalConflict
		}
	}
	r.ID = uuid.NewSHA1(op.ID, []byte(r.Kind))
	r.Method = http.MethodPost
	r.Form = form.Encode()
	r.Version = renewalStripeVersion
	r.Merchant = op.Binding.Merchant
	r.Live = op.Binding.Live
	r.Idempotency = "renewal/" + r.ID.String()
	r.BindingHash = renewalHash(op.Binding)
	if !validRenewalStep(op, r) {
		return renewalChoiceStepRequest{}, errRenewalConflict
	}
	return r, nil
}

func (p *renewalScheduleProvider) DispatchStep(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation, r renewalChoiceStepRequest) (renewalChoiceStepProof, error) {
	if !p.ready(op) || r.BindingHash != renewalHash(op.Binding) || r.Merchant != p.Merchant || r.Version != p.Client.apiVersion {
		return renewalChoiceStepProof{}, errRenewalDisabled
	}
	// GetBody=nil disables net/http's transparent retry of an idempotent POST.
	req, err := http.NewRequestWithContext(ctx, r.Method, p.Client.baseURL+r.Path, strings.NewReader(r.Form))
	if err != nil {
		return renewalChoiceStepProof{}, err
	}
	req.GetBody = nil
	req.Header.Set("Authorization", "Bearer "+p.Client.secretKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Stripe-Version", r.Version)
	req.Header.Set("Idempotency-Key", r.Idempotency)
	client := *p.Client.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		return renewalChoiceStepProof{}, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil {
		return renewalChoiceStepProof{}, err
	}
	if len(raw) > 1<<20 {
		return renewalChoiceStepProof{}, fmt.Errorf("schedule response exceeds limit")
	}
	// An HTTP failure alone never proves no effect, including a 4xx that might
	// follow another accepted request. Recovery is read-only verification.
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return renewalChoiceStepProof{}, fmt.Errorf("schedule request returned %d", response.StatusCode)
	}
	return verifyRenewalScheduleReceipt(k, op, r, raw, time.Now().UTC())
}
func (p *renewalScheduleProvider) ObserveStep(ctx context.Context, k renewalChoiceKey, op renewalChoiceOperation, r renewalChoiceStepRequest) (renewalChoiceStepProof, error) {
	if p == nil || p.Verifier == nil {
		return renewalChoiceStepProof{}, errRenewalDisabled
	}
	return p.Verifier.ObserveStep(ctx, k, op, r)
}
