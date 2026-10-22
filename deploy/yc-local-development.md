# Local YC confirmation email

YC mail is opt-in. The standard devbox installer configures the API and Mailpit,
but does not provision the optional YC shared Auth schema, claim credentials, or
`YC_CONSOLE_URL` / `YC_EMAIL_FROM`. A standard devbox alone is not ready for YC
claim capture. Keep capture and mail disabled until those prerequisites have
been installed and verified for the isolated database.

For an already provisioned local YC environment, set `YC_CONSOLE_URL` to the
browser's Console origin, for example `http://127.0.0.1:46300`, and
`YC_EMAIL_FROM` to its configured test sender. The API must load a numeric
loopback `API_HOST`, and its selected email transport must be SMTP at a loopback
address, such as `EMAIL_TRANSPORT=smtp`, `SMTP_HOST=127.0.0.1`, `SMTP_PORT=1025`.
The Console hostname must be exactly `localhost`, `127.0.0.1`, or `[::1]`; a port
must be between 1 and 65535. Other HTTP origins remain invalid. These settings
are local configuration prerequisites, not an attestation of devbox identity.

Supply YC settings through the environment mechanism owned by that isolated
deployment. The standard generated `api.env` omits them: adding mail settings
without the optional schema would start polling unavailable YC queues.
Reinstalling the standard API does not preserve a custom YC setup; verify its
effective settings before resuming capture.

Use the same Console browser origin for confirmation, signup and Auth callback
configuration. This does not change the Console's HTTPS server-to-server API
requirement. Keep provider credentials and claim proofs out of browser config
and logs.

Validate with a newly generated confirmation email in Mailpit, then follow that
exact link through confirmation and signup. Changing the origin in an old email
can diagnose the handler but does not test new link generation. Preserve any
existing claim until its fixture owner agrees the next transition; do not
resend or create duplicates to work around configuration errors.
