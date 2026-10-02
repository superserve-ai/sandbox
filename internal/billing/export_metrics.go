package billing

import "context"

// ExportBacklog caps each state at 1000 active events; age still refers to the
// oldest event. The status/created_at partial index bounds sampling work.
type ExportBacklog struct {
	State            string
	Count            int64
	OldestAgeSeconds float64
}

func (s ExportStore) Backlog(ctx context.Context) ([]ExportBacklog, error) {
	var samples []ExportBacklog
	for _, state := range []string{"pending", "uncertain", "recovery_required", "rejected", "submitted", "adopted"} {
		sample := ExportBacklog{State: state}
		err := s.Pool.QueryRow(ctx, `SELECT count(*),COALESCE(extract(epoch FROM now()-min(created_at)),0)::float8
   FROM (SELECT created_at FROM billing_export_event WHERE active AND status=$1
         ORDER BY created_at,id LIMIT 1000) events`, state).Scan(&sample.Count, &sample.OldestAgeSeconds)
		if err != nil {
			return nil, err
		}
		samples = append(samples, sample)
	}
	return samples, nil
}

// Only a successful previous provider observation establishes freshness.
func (s ExportStore) PreviousObservationAge(ctx context.Context, p ExportPeriod, resource string) (*float64, error) {
	var age *float64
	err := s.Pool.QueryRow(ctx, `SELECT (SELECT extract(epoch FROM now()-observed_at)::float8
  FROM billing_export_observation WHERE team_id=$1 AND period_start=$2 AND period_end=$3
   AND resource_type=$4 AND last_error IS NULL AND counted_quantity IS NOT NULL)`,
		p.TeamID, p.Start, p.End, resource).Scan(&age)
	return age, err
}
