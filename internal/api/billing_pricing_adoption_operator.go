package api

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
)

type PricingAdoptionState struct {
	Epoch                uuid.UUID `json:"epoch"`
	State                string    `json:"state"`
	Region               *string   `json:"region"`
	PublicPricingVersion string    `json:"public_pricing_version"`
	EntryOpen            bool      `json:"entry_open"`
}

type PricingAdoptionResidual struct {
	TeamID uuid.UUID `json:"team_id"`
	Bucket string    `json:"bucket"`
	Reason string    `json:"reason"`
}

type PricingAdoptionSnapshot struct {
	Epoch      uuid.UUID `json:"epoch"`
	State      string    `json:"state"`
	Total      int       `json:"total"`
	Assigned   int       `json:"assigned"`
	Unassigned int       `json:"unassigned"`
	Deferred   int       `json:"deferred"`
	Released   bool      `json:"released"`
	Blocker    string    `json:"blocker,omitempty"`
}

func (a *PricingV2Activation) PrepareAdoption(ctx context.Context, actor, reason string) (uuid.UUID, error) {
	var epoch uuid.UUID
	system, configErr := a.adoptionSystemTeam()
	if configErr != nil {
		return uuid.Nil, configErr
	}
	err := a.h.Pool.QueryRow(ctx, `SELECT billing_prepare_pricing_adoption($1,$2,$3,$4)`, a.h.Config.TeamCreationRegion, system, actor, reason).Scan(&epoch)
	return epoch, err
}

func (a *PricingV2Activation) CaptureAdoption(ctx context.Context, actor, reason string) (PricingAdoptionSnapshot, error) {
	var raw []byte
	system, configErr := a.adoptionSystemTeam()
	if configErr != nil {
		return PricingAdoptionSnapshot{}, configErr
	}
	err := a.h.Pool.QueryRow(ctx, `SELECT billing_capture_pricing_adoption($1,$2,$3,$4)`, a.h.Config.TeamCreationRegion, system, actor, reason).Scan(&raw)
	var result PricingAdoptionSnapshot
	if err == nil {
		err = json.Unmarshal(raw, &result)
	}
	return result, err
}

func (a *PricingV2Activation) ReleaseAdoption(ctx context.Context, epoch uuid.UUID, actor, reason string, evidence json.RawMessage) (PricingAdoptionSnapshot, error) {
	var raw []byte
	system, configErr := a.adoptionSystemTeam()
	if configErr != nil {
		return PricingAdoptionSnapshot{}, configErr
	}
	err := a.h.Pool.QueryRow(ctx, `SELECT billing_release_pricing_adoption($1,$2,$3,$4,$5,$6::jsonb)`, a.h.Config.TeamCreationRegion, system, epoch, actor, reason, evidence).Scan(&raw)
	var result PricingAdoptionSnapshot
	if err == nil {
		err = json.Unmarshal(raw, &result)
	}
	if err == nil && !result.Released {
		err = errors.New("adoption release blocked: " + result.Blocker)
	}
	return result, err
}

func (a *PricingV2Activation) adoptionReport(ctx context.Context, r *ActivationReport) error {
	state := &PricingAdoptionState{}
	system, configErr := a.adoptionSystemTeam()
	if configErr != nil {
		return configErr
	}
	var boundSystem *uuid.UUID
	if err := a.h.Pool.QueryRow(ctx, `SELECT a.epoch,a.state,a.region,p.pricing_version,p.entry_open,a.system_team_id FROM billing_pricing_adoption a CROSS JOIN billing_pricing_public_state() p WHERE a.singleton`).Scan(&state.Epoch, &state.State, &state.Region, &state.PublicPricingVersion, &state.EntryOpen, &boundSystem); err != nil {
		return err
	}
	if (state.Region != nil && *state.Region != a.h.Config.TeamCreationRegion) || (boundSystem != nil && *boundSystem != system) {
		return errors.New("adoption is bound to another region")
	}
	r.Adoption = state
	rows, err := a.h.Pool.Query(ctx, `SELECT t.id,b.bucket,COALESCE(NULLIF(b.reason,''),b.bucket) FROM team t CROSS JOIN LATERAL pricing_v2_activation_bucket(t.id) b WHERE t.id<>$1 AND NOT EXISTS(SELECT 1 FROM team_plan_assignment pa WHERE pa.team_id=t.id AND pa.effective_to IS NULL) ORDER BY t.id`, system)
	if err != nil {
		return err
	}
	defer rows.Close()
	r.ResidualUnassigned = []PricingAdoptionResidual{}
	for rows.Next() {
		var item PricingAdoptionResidual
		if err := rows.Scan(&item.TeamID, &item.Bucket, &item.Reason); err != nil {
			return err
		}
		r.ResidualUnassigned = append(r.ResidualUnassigned, item)
	}
	r.ResidualCount = len(r.ResidualUnassigned)
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	deferred, err := a.h.Pool.Query(ctx, `SELECT t.id,b.reason FROM team t CROSS JOIN LATERAL (SELECT billing_pricing_adoption_blocker(t.id) AS reason) b WHERE t.id<>$1 AND b.reason IS NOT NULL ORDER BY t.id`, system)
	if err != nil {
		return err
	}
	defer deferred.Close()
	r.DeferredObligations = []PricingAdoptionResidual{}
	for deferred.Next() {
		item := PricingAdoptionResidual{Bucket: "skipped"}
		if err := deferred.Scan(&item.TeamID, &item.Reason); err != nil {
			return err
		}
		r.DeferredObligations = append(r.DeferredObligations, item)
	}
	return deferred.Err()
}

func (a *PricingV2Activation) adoptionSystemTeam() (uuid.UUID, error) {
	id, err := uuid.Parse(a.h.Config.SystemTeamID)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, errors.New("valid nonzero SYSTEM_TEAM_ID required for adoption")
	}
	return id, nil
}
