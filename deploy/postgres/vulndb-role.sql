-- Least-privileged PostgreSQL role for the vulnerability database updater
-- (services/vulndb).
--
-- vulndb is the only SLeep service with internet access and it parses data
-- downloaded from outside, so it must not connect as the database owner. This
-- script is run by the database owner before vulndb starts (the one-shot
-- `vulndb-init` service in compose.yaml) and:
--
--   * creates the login role VULNDB_DB_USER, or resets its attributes and
--     password to the current values;
--   * makes it the owner of the schema "vulndb" and of every table and
--     sequence in it, including those that earlier deployments created under
--     the owner's role;
--   * grants it nothing else. On PostgreSQL 15+ the role cannot create
--     objects in "public", and it has no privileges on the API's tables.
--
-- The script is idempotent and runs on every start of the stack.
--
--   VULNDB_DB_USER=sleep_vulndb VULNDB_DB_PASSWORD=... \
--     psql --no-psqlrc -v ON_ERROR_STOP=1 -f deploy/postgres/vulndb-role.sql

\getenv vulndb_user VULNDB_DB_USER
\getenv vulndb_password VULNDB_DB_PASSWORD

\if :{?vulndb_user}
\else
  DO $$ BEGIN RAISE EXCEPTION 'VULNDB_DB_USER is not set'; END $$;
\endif
\if :{?vulndb_password}
\else
  DO $$ BEGIN RAISE EXCEPTION 'VULNDB_DB_PASSWORD is not set'; END $$;
\endif

-- Reusing the owner's role here would strip the owner of its own rights.
SELECT :'vulndb_user' = current_user AS same_role \gset
\if :same_role
  DO $$ BEGIN RAISE EXCEPTION 'VULNDB_DB_USER must differ from the database owner role'; END $$;
\endif

BEGIN;

SELECT format('CREATE ROLE %I', :'vulndb_user')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'vulndb_user') \gexec

SELECT format(
    'ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'vulndb_user', :'vulndb_password'
) \gexec

SELECT format('CREATE SCHEMA vulndb AUTHORIZATION %I', :'vulndb_user')
WHERE NOT EXISTS (SELECT FROM pg_namespace WHERE nspname = 'vulndb') \gexec
SELECT format('ALTER SCHEMA vulndb OWNER TO %I', :'vulndb_user') \gexec

-- Tables (with their indexes and serial sequences) owned by someone else,
-- typically by the owner's role on installations older than this script.
SELECT format('ALTER TABLE vulndb.%I OWNER TO %I', c.relname, :'vulndb_user')
FROM pg_class AS c
JOIN pg_namespace AS n ON n.oid = c.relnamespace
WHERE n.nspname = 'vulndb'
  AND c.relkind IN ('r', 'p', 'v', 'm')
  AND c.relowner <> (SELECT oid FROM pg_roles WHERE rolname = :'vulndb_user') \gexec

-- Standalone sequences; those of serial columns moved with their tables above.
SELECT format('ALTER SEQUENCE vulndb.%I OWNER TO %I', c.relname, :'vulndb_user')
FROM pg_class AS c
JOIN pg_namespace AS n ON n.oid = c.relnamespace
WHERE n.nspname = 'vulndb'
  AND c.relkind = 'S'
  AND c.relowner <> (SELECT oid FROM pg_roles WHERE rolname = :'vulndb_user') \gexec

COMMIT;
