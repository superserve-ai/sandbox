CREATE OR REPLACE FUNCTION billing_request_now()
RETURNS timestamptz
LANGUAGE sql
STABLE
AS $$
	SELECT COALESCE(
		NULLIF(current_setting('superserve.billing_now', true), '')::timestamptz,
		now()
	)
$$;
