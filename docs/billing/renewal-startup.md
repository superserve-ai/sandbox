# Renewal service startup

Renewal choices are disabled by default. The control plane configures the service
once in the background, after `StartUsageEntitlementService` initializes the
existing financial and entitlement authority. HTTP serving does not wait for
renewal preflight. Until it finishes, renewal routes return an uncached 503
without reading the service pointer. A completion channel synchronizes publication
before those handlers can access it. Only successful configuration starts the
renewal worker. The existing authenticated status and submit routes use that
same handler instance.

Set `BILLING_RENEWAL_CHOICES_ENABLED=true` and
`BILLING_RENEWAL_CHOICES_CONFIG` to an absolute path to reviewed deployment
configuration. Missing or invalid enabled configuration emits an error identifying
the failing stage and leaves renewal unavailable; unrelated API services continue.
`/health` is API process health, not confirmation that renewal is available.
Disabled startup does not read renewal configuration or evidence files.

The configuration JSON contains:

- `scope`: exact `merchant`, explicit `live` boolean, and `api_version`.
- `monthly`: the complete `ProviderPairTerms` JSON, including the fee price,
  product, amount, currency, one-month period, three resource mappings and rounding
  mapping. Resource fields use the existing `StripeCheckoutResourceTerms` field
  names: `ResourceKey`, `PriceID`, `UnitAmountDecimal`, `MeterID`, and `EventName`.
- `monthly_version`: the exact prepared catalog version.
- `evidence_manifest`: absolute local `path` and lowercase `sha256` of the reviewed
  evidence manifest.
- `evidence_directory`: absolute local directory containing unchanged receipt and
  disposition files, using the basenames referenced by that manifest.

The configuration and manifest digest are trusted deployment inputs. Restrict
write access to the deployment owner; they must never come from customer input.
Changing the digest is a new evidence selection requiring review. Hashes detect
changed bytes; they do not independently authenticate the person selecting them.
Keep private receipts, account identifiers, review records and fixture details
outside public source and pull requests.

The loader verifies the manifest's pinned bytes, bounded-contract acceptance,
exact provider scope, reviewed source and six request/recovery source hashes. It
then verifies the pinned original receipt and disposition bytes, checks that the
disposition accepts that exact receipt/source, and passes the resulting assertion
to `ConfigureRenewalChoices`. Original artifact path strings remain identities in
the receipt/disposition relationship; deployment relocation uses only basenames
inside `evidence_directory`. Each file is limited to 1 MiB. The evidence bundle's
constituents and source coverage must be reviewed before pinning the manifest;
they are not all reread on every process startup. The composed-source test detects
changes to the six covered files that require evidence coverage review.

Configuration performs bounded catalog/storage/provider reads and starts no
worker itself. It requires the actual same-handler financial and removal guards,
matching shared/regional services, exact provider identity, and the prepared
Monthly catalog and mapping. Failed or repeated registration cannot replace an
existing registered service. There is no live reload.

Acceptance of bounded provider evidence does not authorize activation. The
release owner separately verifies exact-target shared and regional preparation,
reviewed dependency pins, worker capacity, retirement of untracked issuers,
authenticated Console access, and the allowed fixture/environment scope before
setting the enable flag. The existing evidence's activation status may remain
false: source/sample acceptance and deployment authority are separate decisions.
No production authority follows from this implementation or its local tests.
