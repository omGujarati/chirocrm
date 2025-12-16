import 'dotenv/config';

// CRITICAL: Set env vars BEFORE any imports to ensure they're available during module initialization
if (process.env.NODE_ENV === 'development') {
  process.env.DEV_ALLOW_ADMIN_BOOTSTRAP = 'true';
  // process.env.BYPASS_AUTH = 'true'; // DISABLED - Real authentication enabled
  console.log('[Auth] DEV_ALLOW_ADMIN_BOOTSTRAP enabled for development');
  console.log('[Auth] Real authentication ENABLED');
}

import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { docusignWebhookHandler } from './docusignWebhookHandler';

const app = express();

// Enforce canonical domain - redirect dev domains to published domain (production only)
app.use((req, res, next) => {
  // Skip redirect in development mode or when auth bypass is enabled
  if (process.env.NODE_ENV === 'development' || process.env.BYPASS_AUTH === 'true') {
    return next();
  }
  
  const publishedHost = 'robust-todo-kingsransom.replit.app';
  const currentHost = req.get('host');
  
  // Redirect development domains to published domain (production only)
  if (currentHost && currentHost.includes('.riker.replit.dev') && !currentHost.includes(publishedHost)) {
    const redirectUrl = `https://${publishedHost}${req.originalUrl}`;
    console.log(`[Domain] Redirecting ${currentHost} to ${publishedHost}`);
    return res.redirect(307, redirectUrl); // 307 preserves method and body
  }
  
  next();
});

app.post(
  '/api/docusign/webhook',
  express.raw({ type: '*/*' }),
  docusignWebhookHandler
);


app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  // Log all API requests for debugging
  app.use('/api', (req, res, next) => {
    console.log(`[API Route] ${req.method} ${req.path}`);
    next();
  });

  const server = await registerRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    res.status(status).json({ message });
    throw err;
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = parseInt(process.env.PORT || '5000', 10);
  const listenOptions: any = process.platform === 'win32'
    ? { port, host: '0.0.0.0' }
    : { port, host: '0.0.0.0', reusePort: true };

  server.listen(listenOptions, () => {
    log(`serving on port ${port}`);
  });
})();
