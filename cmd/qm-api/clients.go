package main

import (
	"context"
	"fmt"

	"github.com/superserve-ai/sandbox/internal/qm"
	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
	"github.com/superserve-ai/sandbox/internal/qm/provisioner/gcp"
	"github.com/superserve-ai/sandbox/internal/qm/provisioner/steps"
	"github.com/superserve-ai/sandbox/internal/qm/secrets"
)

// provisionerClients is the set of cloud clients a real run needs, plus the
// one thing that has to be closed: the pool the database client holds on
// the shared Cloud SQL instance.
type provisionerClients struct {
	clients steps.Clients
	dbs     *gcp.Databases
}

func (p provisionerClients) Steps() steps.Clients { return p.clients }

func (p provisionerClients) Close() {
	if p.dbs != nil {
		p.dbs.Close()
	}
}

// cloudClients builds every client outside stub mode. The shared-
// infrastructure values it reads are the ones the QM Terraform module
// exports; the plan's readiness check reports any that are missing, so this
// only fails on a client that could not be constructed at all.
//
// The instance admin password is read here rather than per run: it is the
// one secret the provisioner itself needs, and a run that discovered it was
// unreadable at the database step would already have built half a tenant.
func cloudClients(ctx context.Context, cfg qm.Config, env provisioner.Env, store secrets.Store) (provisionerClients, error) {
	var out provisionerClients
	// The values this function itself consumes, checked up front so an
	// environment missing one says which rather than failing inside a
	// client constructor.
	if err := env.Require(
		"GCP_PROJECT", cfg.GCPProject,
		"QM_PROVISIONER_REGION", cfg.ProvisionerRegion,
		"QM_LB_URL_MAP", cfg.LBURLMap,
	); err != nil {
		return out, err
	}

	accounts, err := gcp.NewAccounts(ctx, cfg.GCPProject)
	if err != nil {
		return out, err
	}
	buckets, err := gcp.NewBuckets(ctx, cfg.GCPProject)
	if err != nil {
		return out, err
	}
	services, err := gcp.NewServices(ctx, cfg.GCPProject, cfg.ProvisionerRegion)
	if err != nil {
		return out, err
	}
	lb, err := gcp.NewLoadBalancer(ctx, cfg.GCPProject, cfg.ProvisionerRegion, cfg.LBURLMap)
	if err != nil {
		return out, err
	}

	// Resolved on first use, not here: reading the instance's admin
	// password and dialing the instance are the provisioner's business, and
	// the qm-api service — which only queues the job that does the work —
	// should not fail to start because either is briefly unavailable.
	dbs := gcp.NewDatabases(func(ctx context.Context) (string, error) {
		password, err := store.Get(ctx, cfg.SQLAdminSecret)
		if err != nil {
			return "", fmt.Errorf("read the cloud sql admin password from %s: %w", cfg.SQLAdminSecret, err)
		}
		// The maintenance database, not a tenant's: this connection exists
		// only to create and drop the others.
		return steps.DatabaseURL(env, cfg.SQLAdminUser, string(password), "postgres"), nil
	})

	out.dbs = dbs
	out.clients = steps.Clients{
		Secrets:      store,
		Accounts:     accounts,
		Databases:    dbs,
		Buckets:      buckets,
		Services:     services,
		LoadBalancer: lb,
	}
	return out, nil
}
