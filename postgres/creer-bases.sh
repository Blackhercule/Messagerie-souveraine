#!/bin/sh
# Exécuté une seule fois, à la création du volume PostgreSQL :
# une base pour Synapse (encodage imposé par Synapse) et une base pour Keycloak.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-SQL
	CREATE USER synapse WITH PASSWORD '$MOT_DE_PASSE_POSTGRES';
	CREATE DATABASE synapse OWNER synapse ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0;
	CREATE USER keycloak WITH PASSWORD '$MOT_DE_PASSE_POSTGRES';
	CREATE DATABASE keycloak OWNER keycloak;
SQL
