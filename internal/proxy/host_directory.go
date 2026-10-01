package proxy

import (
	"context"
	"sync"
	"time"

	"github.com/superserve-ai/sandbox/internal/db"
)

const hostDirectoryTTL = 15 * time.Second
const hostDirectoryInterval = 5 * time.Second
const maxDirectoryHosts = 4096

type hostLister interface {
	ListPeerHosts(context.Context) ([]db.GetSandboxPeerEndpointRow, error)
}

// HostDirectory refreshes serving endpoints independently of sandbox requests.
// An absent or expired snapshot falls back to the bounded ownership resolver.
type HostDirectory struct {
	mu      sync.RWMutex
	routes  map[string]SandboxRoute
	expires time.Time
}

func (d *HostDirectory) Ready() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return time.Now().Before(d.expires)
}

func (d *HostDirectory) ResolveHost(id string) (SandboxRoute, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	route, ok := d.routes[id]
	return route, ok && time.Now().Before(d.expires)
}

func (d *HostDirectory) refresh(ctx context.Context, source hostLister) error {
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, ownershipLookupTimeout)
	defer cancel()
	hosts, err := source.ListPeerHosts(ctx)
	if err != nil {
		return err
	}
	routes := make(map[string]SandboxRoute)
	if len(hosts) <= maxDirectoryHosts {
		for _, row := range hosts {
			endpoint, err := PeerEndpointFromDiscovery(row)
			if err != nil {
				continue
			}
			route, err := routeFromRecordedHost(row.HostID, *row.VmdAddr, endpoint.Generation)
			if err == nil {
				routes[row.HostID] = route
			}
		}
	}
	d.mu.Lock()
	d.routes, d.expires = routes, started.Add(hostDirectoryTTL)
	d.mu.Unlock()
	return nil
}

// DBHostDirectorySource uses only the existing proxy role's discovery grants.
type DBHostDirectorySource struct{ Pool routingQueryer }

func (s DBHostDirectorySource) ListPeerHosts(ctx context.Context) ([]db.GetSandboxPeerEndpointRow, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, vmd_addr, proxy_addr, incarnation_id, peer_generation FROM host WHERE last_heartbeat_at IS NOT NULL ORDER BY id LIMIT 4097`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hosts []db.GetSandboxPeerEndpointRow
	for rows.Next() {
		var row db.GetSandboxPeerEndpointRow
		if err := rows.Scan(&row.HostID, &row.VmdAddr, &row.ProxyAddr, &row.IncarnationID, &row.PeerGeneration); err != nil {
			return nil, err
		}
		hosts = append(hosts, row)
	}
	return hosts, rows.Err()
}
