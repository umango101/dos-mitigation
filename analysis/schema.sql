CREATE TABLE "revisions" (
  "id" serial PRIMARY KEY,
  "hash" varchar,
  "metal" boolean,
  "nickname" varchar,
  "model_file" bytea
);

CREATE TABLE "materializations" (
  "id" serial PRIMARY KEY,
  "nickname" varchar,
  "revision" serial,
  "inventory_file" bytea
);

CREATE TABLE "hosts" (
  "id" serial PRIMARY KEY,
  "materialization" serial,
  "hostname" varchar,
  "hostgroup" varchar,
  "hostnum" int
);

CREATE TABLE "sessions" (
  "id" serial PRIMARY KEY,
  "nickname" varchar,
  "materialization" serial,
  "parameters" jsonb
);

CREATE TABLE "experiments" (
  "id" serial PRIMARY KEY,
  "timestamp" timestamp,
  "session" serial,
  "settings" jsonb
);

CREATE TABLE "data" (
  "metric" varchar,
  "host" serial,
  "experiment" serial,
  "attack_enabled" bool,
  "mitigation_enabled" bool,
  "timestamp" float,
  "value" float
);

CREATE TABLE "results" (
  "experiment" serial,
  "metric" varchar,
  "host" serial,
  "ub" float,
  "mb" float,
  "ua" float,
  "ma" float,
  "threat" float,
  "damage" float,
  "efficacy" float,
  "overhead" float,
  "threat_pct" float,
  "damage_pct" float,
  "efficacy_pct" float,
  "efficacy_pct_threat" float,
  "efficacy_relative" float,
  "overhead_pct" float
);

ALTER TABLE "materializations" ADD FOREIGN KEY ("revision") REFERENCES "revisions" ("id");

ALTER TABLE "hosts" ADD FOREIGN KEY ("materialization") REFERENCES "materializations" ("id");

ALTER TABLE "sessions" ADD FOREIGN KEY ("materialization") REFERENCES "materializations" ("id");

ALTER TABLE "experiments" ADD FOREIGN KEY ("session") REFERENCES "sessions" ("id");

ALTER TABLE "data" ADD FOREIGN KEY ("host") REFERENCES "hosts" ("id");

ALTER TABLE "data" ADD FOREIGN KEY ("experiment") REFERENCES "experiments" ("id");

ALTER TABLE "results" ADD FOREIGN KEY ("experiment") REFERENCES "experiments" ("id");

ALTER TABLE "results" ADD FOREIGN KEY ("host") REFERENCES "hosts" ("id")