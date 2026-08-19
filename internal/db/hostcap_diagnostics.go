package db

import "context"

// HostCapabilityCheckDiagnostics is a read-only snapshot of the exact DB
// statement that made a standalone capability decision. Timestamps are
// formatted by Postgres so logs preserve the committed values observed by the
// decision without application-side conversion.
type HostCapabilityCheckDiagnostics struct {
	HasCapabilities bool
	HostStatus       string
	VmdAddr          string
	ProxyAddr        string
	LastHeartbeatAt  string
	CapabilityRows   string
}

const checkHostCapabilitiesWithDiagnostics = `
WITH target_host AS MATERIALIZED (
    SELECT id, status, vmd_addr, proxy_addr, last_heartbeat_at
    FROM host
    WHERE id = $1
), capability_rows AS MATERIALIZED (
    SELECT
        hc.capability,
        hc.heartbeat_at,
        COALESCE(hc.heartbeat_at = h.last_heartbeat_at, false) AS matches_current_heartbeat
    FROM host_capability hc
    JOIN target_host h ON h.id = hc.host_id
), check_result AS (
    SELECT EXISTS (
        SELECT 1
        FROM target_host h
        WHERE h.status = 'active'
          AND h.last_heartbeat_at IS NOT NULL
          AND NOT EXISTS (
              SELECT 1
              FROM unnest($2::text[]) AS required(capability)
              WHERE NOT EXISTS (
                  SELECT 1
                  FROM capability_rows hc
                  WHERE hc.capability = required.capability
                    AND hc.matches_current_heartbeat
              )
          )
    ) AS has_capabilities
)
SELECT
    r.has_capabilities,
    COALESCE(h.status, ''),
    COALESCE(h.vmd_addr, ''),
    COALESCE(h.proxy_addr, ''),
    COALESCE(to_char(h.last_heartbeat_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), ''),
    COALESCE(
        jsonb_agg(
            jsonb_build_object(
                'capability', hc.capability,
                'heartbeat_at', to_char(hc.heartbeat_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                'matches_current_heartbeat', hc.matches_current_heartbeat
            )
            ORDER BY hc.capability
        ) FILTER (WHERE hc.capability IS NOT NULL),
        '[]'::jsonb
    )::text
FROM check_result r
LEFT JOIN target_host h ON true
LEFT JOIN capability_rows hc ON true
GROUP BY r.has_capabilities, h.status, h.vmd_addr, h.proxy_addr, h.last_heartbeat_at
`

func (q *Queries) CheckHostCapabilitiesWithDiagnostics(ctx context.Context, hostID string, requiredCapabilities []string) (HostCapabilityCheckDiagnostics, error) {
	row := q.db.QueryRow(ctx, checkHostCapabilitiesWithDiagnostics, hostID, requiredCapabilities)
	var d HostCapabilityCheckDiagnostics
	err := row.Scan(
		&d.HasCapabilities,
		&d.HostStatus,
		&d.VmdAddr,
		&d.ProxyAddr,
		&d.LastHeartbeatAt,
		&d.CapabilityRows,
	)
	return d, err
}
