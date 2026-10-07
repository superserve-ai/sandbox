package db

import "github.com/jackc/pgx/v5/pgtype"

// RegisterEnumArrays lets pgx encode status arrays in text format when a
// connection has not loaded the database-specific enum OID. The parameter is
// still sandbox_status[] on the server, preserving enum selectivity estimates.
func RegisterEnumArrays(m *pgtype.Map) {
	m.RegisterDefaultPgType([]SandboxStatus{}, "_text")
}
