import { getMigrations } from "better-auth/db/migration";
import { createAuth } from "./auth.js";
import { loadConfig } from "./config.js";
import { logEvent } from "./log.js";

const auth = createAuth(loadConfig());
const { runMigrations } = await getMigrations(auth.options);
await runMigrations();
logEvent("migrated");
process.exit(0);
