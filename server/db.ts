import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
import * as schema from "@shared/schema";

neonConfig.webSocketConstructor = ws;

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?"
  );
}

// Create pool with error handling
export const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Add error event listeners to catch connection errors
pool.on("error", (err) => {
  console.error("[Database] Unexpected error on idle client:", err);
});

// Test connection on startup
pool
  .query("SELECT 1")
  .then(() => {
    console.log("[Database] Connection established successfully");
  })
  .catch((err) => {
    console.error("[Database] Failed to connect to database:", err);
    console.error(
      "[Database] DATABASE_URL format:",
      process.env.DATABASE_URL?.replace(/:[^:@]+@/, ":****@")
    );
  });

export const db = drizzle({ client: pool, schema });
