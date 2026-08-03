INSERT INTO permissions (name, description)
VALUES ('platform:billing:read', 'Read billing state across platform teams')
ON CONFLICT (name) DO UPDATE
SET description = EXCLUDED.description,
    updated_at = now();

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.name = 'platform:billing:read'
WHERE r.name = 'platform_admin'
ON CONFLICT (role_id, permission_id) DO NOTHING;
