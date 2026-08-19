package db

import "context"

// HostCapabilityDiagnostics is a read-only snapshot used only for failure-path
// logging. Timestamps are formatted by Postgres so logs preserve the exact DB
// values without introducing application-side timestamp conversion.
type HostCapabilityDiagnostics struct {
	HostStatus      string
	VmdAddr         string
	ProxyAddr       string
	LastHeartbeatAt string
	CapabilityRows  string
}

const getHostCapabilityDiagnostics = `
SELECT
    h.status,
    h.vmd_addr,
    h.proxy_addr,
    COALESCE(to_char(h.last_heartbeat_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), ''),
    COALESCE(
        jsonb_agg(
            jsonb_build_object(
                'capability', hc.capability,
                'heartbeat_at', to_char(hc.heartbeat_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                'matches_current_heartbeat', hc.heartbeat_at = h.last_heartbeat_at
            )
            ORDER BY hc.capability
        ) FILTER (WHERE hc.capability IS NOT NULL),
        '[]'::jsonb
    )::text
FROM host h
LEFT JOIN host_capability hc ON hc.host_id = h.id
WHERE h.id = $1
GROUP BY h.id, h.status, h.vmd_addr, h.proxy_addr, h.last_heartbeat_at
`

func (q *Queries) GetHostCapabilityDiagnostics(ctx context.Context, hostID string) (HostCapabilityDiagnostics, error) {
	row := q.db.QueryRow(ctx, getHostCapabilityDiagnostics, hostID)
	var d HostCapabilityDiagnostics
	err := row.Scan(
		&d.HostStatus,
		&d.VmdAddr,
		&d.ProxyAddr,
		&d.LastHeartbeatAt,
		&d.CapabilityRows,
	)
	return d, err
}
