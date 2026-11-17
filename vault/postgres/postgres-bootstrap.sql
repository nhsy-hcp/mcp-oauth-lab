-- PostgreSQL bootstrap for the MCP identity-broker lab. Runs once, on an empty data directory, via
-- 00-bootstrap.sh, which supplies the vault_admin_preview bootstrap password from a Kubernetes Secret.
-- Vault rotates that password with database/rotate-root straight after configuration.
\set ON_ERROR_STOP on

CREATE DATABASE preview;
REVOKE CONNECT ON DATABASE preview, postgres FROM PUBLIC;

-- Vault's own login: not a superuser. CREATEROLE to mint users; pg_signal_backend to end their sessions.
CREATE ROLE vault_admin_preview WITH LOGIN CREATEROLE PASSWORD :'vault_admin_preview_password';
GRANT pg_signal_backend TO vault_admin_preview;

-- Group role for the MCP server (NOLOGIN, owns nothing): read-only, one table.
-- PostgreSQL 16 needs ADMIN OPTION before a CREATEROLE user can grant it.
CREATE ROLE preview_orders_ro NOLOGIN;
GRANT preview_orders_ro TO vault_admin_preview WITH ADMIN OPTION;
GRANT CONNECT ON DATABASE preview TO preview_orders_ro, vault_admin_preview;

\connect preview

CREATE SCHEMA orders;
CREATE TABLE orders.items (
  id serial PRIMARY KEY,
  customer text NOT NULL,
  status text NOT NULL,
  total_pence integer NOT NULL
);
INSERT INTO orders.items (customer, status, total_pence) VALUES
  ('acme-ltd', 'pending', 4200),
  ('globex', 'shipped', 1999),
  ('initech', 'pending', 750),
  ('umbrella', 'cancelled', 12000);

GRANT USAGE ON SCHEMA orders TO preview_orders_ro;
GRANT SELECT ON orders.items TO preview_orders_ro;

-- Another team's data in the same database. No MCP role has any grant here (scenario M8).
CREATE SCHEMA payments;
CREATE TABLE payments.card_tokens (
  id serial PRIMARY KEY,
  token text NOT NULL
);
INSERT INTO payments.card_tokens (token) VALUES ('CANARY_NEVER_LEAK');
