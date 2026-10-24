package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/superserve-ai/sandbox/internal/api"
	"github.com/superserve-ai/sandbox/internal/config"
)

const usage = `usage:
  pricing-v2-migrate [report] [--format text|json|csv]
  pricing-v2-migrate apply --confirm --actor <who> --reason <why> [--batch 500]
  pricing-v2-migrate prepare|capture --confirm --actor <who> --reason <why>
  pricing-v2-migrate release --confirm --actor <who> --reason <why> --epoch <uuid> --evidence-file <json>

Environment: DATABASE_URL (the region's database), TEAM_CREATION_REGION (the
region, or --region), SYSTEM_TEAM_ID, and STRIPE_SECRET_KEY with
STRIPE_API_VERSION to read lapsed teams' Stripe credit.`

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type options struct {
	command, format, region, actor, reason string
	epoch, evidenceFile                    string
	confirm                                bool
	batch                                  int
}

func parse(args []string, getenv func(string) string) (options, error) {
	o := options{command: "report"}
	if len(args) > 0 && (args[0] == "report" || args[0] == "apply" || args[0] == "prepare" || args[0] == "capture" || args[0] == "release") {
		o.command, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("pricing-v2-migrate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.format, "format", "text", "")
	fs.StringVar(&o.region, "region", getenv("TEAM_CREATION_REGION"), "")
	fs.StringVar(&o.actor, "actor", "", "")
	fs.StringVar(&o.reason, "reason", "", "")
	fs.StringVar(&o.epoch, "epoch", "", "")
	fs.StringVar(&o.evidenceFile, "evidence-file", "", "")
	fs.BoolVar(&o.confirm, "confirm", false, "")
	fs.IntVar(&o.batch, "batch", 500, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return o, errors.New(usage)
	}
	o.actor, o.reason = strings.TrimSpace(o.actor), strings.TrimSpace(o.reason)
	switch {
	case o.region == "":
		return o, errors.New("set TEAM_CREATION_REGION or --region to the region whose database DATABASE_URL names")
	case o.command == "report" && o.format != "text" && o.format != "json" && o.format != "csv":
		return o, errors.New("--format must be text, json or csv")
	case o.command != "report" && (!o.confirm || o.actor == "" || o.reason == ""):
		return o, errors.New("writes require --confirm, --actor and --reason")
	case !validSystemTeam(getenv("SYSTEM_TEAM_ID")):
		return o, errors.New("a valid nonzero SYSTEM_TEAM_ID is required")
	case o.command == "release" && (!validSystemTeam(o.epoch) || o.evidenceFile == ""):
		return o, errors.New("release requires current --epoch and --evidence-file")
	case o.batch < 1 || o.batch > 5000:
		return o, errors.New("--batch must be between 1 and 5000")
	}
	return o, nil
}

func run(ctx context.Context, args []string, out io.Writer, getenv func(string) string) error {
	o, err := parse(args, getenv)
	if err != nil {
		return err
	}
	if getenv("DATABASE_URL") == "" {
		return errors.New("DATABASE_URL must name the region's database")
	}
	pool, err := pgxpool.New(ctx, getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()
	if o.command == "prepare" || o.command == "capture" || o.command == "release" {
		activation := api.NewPricingV2Activation(pool, nil, o.region, getenv("SYSTEM_TEAM_ID"))
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		if o.command == "prepare" {
			epoch, err := activation.PrepareAdoption(ctx, o.actor, o.reason)
			if err != nil {
				return err
			}
			return encoder.Encode(map[string]any{"epoch": epoch, "state": "preparing", "region": o.region})
		}
		if o.command == "capture" {
			snapshot, err := activation.CaptureAdoption(ctx, o.actor, o.reason)
			if err != nil {
				return err
			}
			return encoder.Encode(snapshot)
		}
		evidence, err := os.ReadFile(o.evidenceFile)
		if err != nil {
			return err
		}
		if !json.Valid(evidence) {
			return errors.New("evidence file must be valid JSON")
		}
		snapshot, releaseErr := activation.ReleaseAdoption(ctx, uuid.MustParse(o.epoch), o.actor, o.reason, evidence)
		if releaseErr != nil && snapshot.Epoch == uuid.Nil {
			return releaseErr
		}
		if err := encoder.Encode(snapshot); err != nil {
			return err
		}
		return releaseErr
	}
	stripe := api.NewStripeBillingClient(&config.Config{
		StripeSecretKey: getenv("STRIPE_SECRET_KEY"), StripeAPIVersion: getenv("STRIPE_API_VERSION"),
		StripeAPIBaseURL: envOr(getenv, "STRIPE_API_BASE_URL", "https://api.stripe.com"),
	})
	if stripe == nil {
		fmt.Fprintln(os.Stderr, "warning: no Stripe credentials; lapsed teams are reported as credit_unknown and left unassigned")
	}
	activation := api.NewPricingV2Activation(pool, stripe, o.region, getenv("SYSTEM_TEAM_ID"))
	if o.command == "apply" {
		return apply(ctx, activation, o, out)
	}
	report, err := activation.Report(ctx)
	if err != nil {
		return err
	}
	return writeReport(out, o.format, report)
}

func apply(ctx context.Context, activation *api.PricingV2Activation, o options, out io.Writer) error {
	total := api.ActivationBatch{}
	var cursor *api.ActivationCursor
	passAssigned := 0
	for {
		batch, err := activation.ApplyBatchAfter(ctx, o.actor, o.reason, int32(o.batch), cursor)
		if errors.Is(err, api.ErrPricingV2Off) {
			return errors.New("refusing to apply: flip this region's pricing switch to v2 first")
		}
		if err != nil {
			return fmt.Errorf("apply stopped after %d Free and %d legacy PAYG assignments: %w", total.AssignedFree, total.AssignedLegacyPAYG, err)
		}
		total.AssignedContract += batch.AssignedContract
		total.AssignedFree += batch.AssignedFree
		total.AssignedLegacyPAYG += batch.AssignedLegacyPAYG
		total.Remaining = batch.Remaining
		fmt.Fprintf(out, "%s batch: %d to Free, %d to legacy PAYG, %d contract-backed, %d deferred, %d remaining\n",
			time.Now().UTC().Format(time.RFC3339), batch.AssignedFree, batch.AssignedLegacyPAYG, batch.AssignedContract, batch.Deferred, batch.Remaining)
		if batch.Remaining == 0 {
			snapshot, err := activation.CaptureAdoption(ctx, o.actor, o.reason)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "adoption epoch %s: %d total, %d assigned, %d residual unassigned; state %s (not auto-released)\n", snapshot.Epoch, snapshot.Total, snapshot.Assigned, snapshot.Unassigned, snapshot.State)
			fmt.Fprintf(out, "done: %d to Free, %d to legacy PAYG, %d contract-backed\n", total.AssignedFree, total.AssignedLegacyPAYG, total.AssignedContract)
			return nil
		}
		passAssigned += batch.AssignedFree + batch.AssignedLegacyPAYG + batch.AssignedContract
		if batch.Next != nil {
			cursor = batch.Next
			continue
		}
		if passAssigned == 0 {
			return fmt.Errorf("%d teams remain that this run could not assign; run report to see why, then apply again", batch.Remaining)
		}
		cursor, passAssigned = nil, 0
	}
}

func writeReport(out io.Writer, format string, r api.ActivationReport) error {
	switch format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "csv":
		w := csv.NewWriter(out)
		_ = w.Write([]string{"group", "team_id", "reason", "credit_cents"})
		for _, g := range []struct {
			name  string
			teams []api.ActivationTeam
		}{{"blocked_to_free", r.BlockedToFree}, {"lapsed_with_credit", r.LapsedWithCredit}, {"lapsed_no_credit", r.LapsedNoCredit},
			{"lapsed_unchecked", r.LapsedUnchecked}, {"skipped", r.Skipped}} {
			for _, t := range g.teams {
				credit := ""
				if t.CreditCents != nil {
					credit = strconv.FormatInt(*t.CreditCents, 10)
				}
				_ = w.Write([]string{g.name, t.TeamID.String(), t.Reason, credit})
			}
		}
		for _, item := range r.ResidualUnassigned {
			_ = w.Write([]string{"residual_unassigned", item.TeamID.String(), item.Reason, ""})
		}
		for _, item := range r.DeferredObligations {
			_ = w.Write([]string{"deferred_obligation", item.TeamID.String(), item.Reason, ""})
		}
		w.Flush()
		return w.Error()
	}
	fmt.Fprintf(out, "region %s, pricing %s, as of %s\n", r.Region, r.PricingVersion, r.AsOf.Format(time.RFC3339))
	fmt.Fprintf(out, "  to Free:              %d (of which abuse-blocked, staying blocked: %d; lapsed without credit: %d)\n", r.ToFree, len(r.BlockedToFree), len(r.LapsedNoCredit))
	fmt.Fprintf(out, "  to legacy PAYG:       %d (of which lapsed with credit: %d)\n", r.ToLegacyPAYG, len(r.LapsedWithCredit))
	fmt.Fprintf(out, "  contract-backed:      %d\n", r.ToContract)
	fmt.Fprintf(out, "  already assigned:     %d\n", r.AlreadyAssigned)
	fmt.Fprintf(out, "  credit not yet read:  %d\n", len(r.LapsedUnchecked))
	fmt.Fprintf(out, "  skipped:              %d %v\n", len(r.Skipped), r.SkippedReasons)
	fmt.Fprintf(out, "  residual unassigned (all cell teams): %d\n", r.ResidualCount)
	if r.Adoption != nil {
		fmt.Fprintf(out, "  adoption: %s epoch %s public %s entry_open=%t\n", r.Adoption.State, r.Adoption.Epoch, r.Adoption.PublicPricingVersion, r.Adoption.EntryOpen)
	}
	fmt.Fprintf(out, "  deferred obligations: %d\n", len(r.DeferredObligations))
	for _, item := range r.DeferredObligations {
		fmt.Fprintf(out, "    %s %s\n", item.TeamID, item.Reason)
	}
	fmt.Fprintf(out, "  pending:              %d\n", r.Pending)
	fmt.Fprintf(out, "  Stripe reads:         %d in %dms\n", r.CreditReads, r.ElapsedMS)
	fmt.Fprintln(out, "Use --format csv for the team lists.")
	return nil
}

func envOr(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

func validSystemTeam(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil
}
