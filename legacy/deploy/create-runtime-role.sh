#!/bin/sh
set -eu
# Executed only during initialization of a new PostgreSQL volume.
app_password=$(cat /run/secrets/app_password)
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set=app_password="$app_password" <<'SQL'
CREATE ROLE kig_app LOGIN PASSWORD :'app_password';
GRANT CONNECT ON DATABASE keyguard TO kig_app;
GRANT USAGE ON SCHEMA public TO kig_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO kig_app;
SQL
