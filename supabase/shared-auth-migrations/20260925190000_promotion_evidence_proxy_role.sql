-- The regional control planes connect to shared Auth as this RPC-only role.
CREATE ROLE promotion_evidence_proxy LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;

GRANT USAGE ON SCHEMA public TO promotion_evidence_proxy;
REVOKE ALL ON public.signup_device_attempt, public.signup_device_account_evidence
    FROM promotion_evidence_proxy;
GRANT EXECUTE ON FUNCTION public.create_signup_device_attempt(),
    public.verify_signup_device_attempt(uuid,uuid,text,text,timestamptz),
    public.bind_signup_device_account(uuid,uuid),
    public.get_signup_device_account_evidence(uuid) TO promotion_evidence_proxy;
