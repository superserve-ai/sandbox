CREATE INDEX stripe_webhook_retained_expiration_idx
    ON stripe_webhook_event (
        (payload #>> '{data,object,client_reference_id}'),
        (payload #>> '{data,object,customer}'),
        (payload #>> '{data,object,metadata,checkout_generation}')
    )
    WHERE event_type = 'checkout.session.expired' AND processed_at IS NOT NULL;
