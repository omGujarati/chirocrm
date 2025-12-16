import session from "express-session";
import connectPg from "connect-pg-simple";
import type { Express } from "express";

/**
 * Simple session configuration for OAuth compatibility
 */
export function configureSession(app: Express) {
  const sessionTtl = 7 * 24 * 60 * 60 * 1000; // 1 week

  // Use PostgreSQL session store
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: true,
    ttl: sessionTtl,
    tableName: "sessions",
  });

  console.log('[Session] Configuring session store');

  const isProduction = process.env.NODE_ENV === 'production';
  
  // In development, use insecure cookies so they work on http://localhost
  // In production, require HTTPS and use sameSite=none for cross-site compatibility
  const cookieSecure = isProduction;
  const cookieSameSite = isProduction ? ('none' as const) : ('lax' as const);

  // Only set trust proxy in production (behind reverse proxy)
  if (isProduction) {
    app.set("trust proxy", 1);
  }

  // Simple session configuration
  app.use(session({
    secret: process.env.SESSION_SECRET!,
    store: sessionStore,
    resave: false,
    saveUninitialized: true,
    rolling: true,
    proxy: isProduction,
    name: 'connect.sid',
    cookie: {
      httpOnly: true,
      secure: cookieSecure,
      sameSite: cookieSameSite,
      maxAge: sessionTtl,
    },
  }));

  console.log('[Session] Session configured with secure=true, sameSite=none');
}