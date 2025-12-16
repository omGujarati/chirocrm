import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import type { Express, RequestHandler } from "express";
import { storage } from "./storage";
import { randomBytes } from "crypto";

// Extend session data type for OAuth state
declare module "express-session" {
  interface SessionData {
    oauthState?: string;
  }
}

// Check Google OAuth credentials at module load (skip if bypass mode will be used)
if (process.env.BYPASS_AUTH !== 'true') {
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    throw new Error("Google OAuth credentials not provided");
  }
}

// Dev admin user for bypass mode
const DEV_ADMIN_USER = {
  id: 'dev_admin',
  email: 'dev@local',
  firstName: 'Dev',
  lastName: 'Admin',
  role: 'admin' as const,
  isActive: true,
};

async function authenticateExistingUser(profile: any) {
  const email = profile.emails?.[0]?.value || '';
  
  if (!email) {
    console.warn('[Auth] No email provided in Google profile');
    return null;
  }
  
  // SECURITY: Only authenticate existing pre-approved users
  const existingUser = await storage.getUserByEmail(email);
  
  if (!existingUser) {
    // DEV ONLY: Allow admin account creation (must be disabled in production)
    // Set ADMIN_BOOTSTRAP_EMAIL env var to your email to bootstrap first admin
    const bootstrapEmail = process.env.ADMIN_BOOTSTRAP_EMAIL;
    if (process.env.DEV_ALLOW_ADMIN_BOOTSTRAP === 'true' && bootstrapEmail && email === bootstrapEmail) {
      console.log(`[Auth] DEV: Creating admin account for: ${email}`);
      const adminUser = await storage.upsertUser({
        id: profile.id,
        email: email,
        firstName: profile.name?.givenName || 'Admin',
        lastName: profile.name?.familyName || 'User',
        profileImageUrl: profile.photos?.[0]?.value,
        role: 'admin',
        isActive: true,
      });
      return adminUser;
    }
    
    console.warn(`[Auth] Access denied - user not found in system: ${email}`);
    return null;
  }
  
  // SECURITY: Only authenticate active users
  if (!existingUser.isActive) {
    console.warn(`[Auth] Access denied - user is deactivated: ${email}`);
    return null;
  }
  
  // Update user profile data from Google (but preserve role and status)
  const updatedUser = await storage.upsertUser({
    id: existingUser.id, // Preserve existing ID
    email: existingUser.email,
    firstName: profile.name?.givenName || existingUser.firstName,
    lastName: profile.name?.familyName || existingUser.lastName,
    profileImageUrl: profile.photos?.[0]?.value || existingUser.profileImageUrl,
    role: existingUser.role, // Preserve existing role - DO NOT change from OIDC
    isActive: existingUser.isActive, // Preserve existing status
  });
  
  console.log(`[Auth] Successful login: ${email} (${updatedUser.role})`);
  return updatedUser;
}

export async function setupAuth(app: Express) {
  // Check if auth bypass mode is enabled (runtime check)
  const bypassAuth = process.env.BYPASS_AUTH === 'true';
  
  if (bypassAuth) {
    // Auth bypass mode - inject dev admin user and skip all OAuth setup
    console.log('⚠️  [Auth] BYPASS_AUTH enabled - authentication disabled for development');
    console.log('⚠️  [Auth] All users will be logged in as dev admin automatically');
    
    // Ensure dev admin user exists in storage
    const existingDevAdmin = await storage.getUser(DEV_ADMIN_USER.id);
    if (!existingDevAdmin) {
      await storage.upsertUser(DEV_ADMIN_USER);
      console.log('[Auth] Created dev admin user in database');
    }
    
    // Middleware to inject dev admin user into all requests
    app.use((req, res, next) => {
      // Inject user object for all requests
      (req as any).user = DEV_ADMIN_USER;
      // Mock isAuthenticated function
      (req as any).isAuthenticated = () => true;
      console.log(`[Auth Bypass] Injected dev admin user for ${req.method} ${req.path}`);
      next();
    });
    
    console.log('[Auth] Auth bypass configured - all requests will use dev admin user');
    return;
  }
  
  // Normal OAuth mode
  app.use(passport.initialize());
  app.use(passport.session());

  // Configure Google OAuth Strategy - use relative callback to match any domain
  const callbackURL = "/api/auth/google/callback"; // Always relative to current host
  console.log(`[Auth] Using relative OAuth callback URL: ${callbackURL}`);
  
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    callbackURL: callbackURL,
    state: true // Enable CSRF protection via state parameter
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const user = await authenticateExistingUser(profile);
      
      if (!user) {
        // SECURITY: Return false for unauthorized users (not found or inactive)
        return done(null, false);
      }
      
      return done(null, user);
    } catch (error) {
      console.error('[Auth] Error during Google OAuth authentication:', error);
      return done(error, undefined);
    }
  }));

  passport.serializeUser((user: any, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id: string, done) => {
    try {
      const user = await storage.getUser(id);
      
      if (!user) {
        // User not found - session is invalid
        return done(null, false);
      }
      
      // SECURITY: Check isActive status during session deserialization
      if (!user.isActive) {
        console.warn(`[Auth] Session deserialization blocked - user is deactivated: ${user.email} (${user.id})`);
        // Return false to indicate unauthorized - this will clear the session
        return done(null, false);
      }
      
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  });

  // Google OAuth routes with CSRF protection
  // Debug endpoint to check session state
  app.get("/api/debug/session", (req, res) => {
    res.json({
      sessionExists: !!req.session,
      sessionId: req.session?.id,
      isAuthenticated: req.isAuthenticated(),
      user: req.user ? { id: (req.user as any)?.id, email: (req.user as any)?.email } : null,
      cookies: req.headers.cookie
    });
  });

  app.get("/api/auth/google", (req, res, next) => {
    console.log('🔐 [OAuth Debug] === OAUTH INITIATION ===');
    console.log('🔐 [OAuth Debug] IP:', req.ip);
    console.log('🔐 [OAuth Debug] User-Agent:', req.get('User-Agent'));
    console.log('🔐 [OAuth Debug] Referer:', req.get('Referer'));
    console.log('🔐 [OAuth Debug] Hostname:', req.hostname);
    console.log('🔐 [OAuth Debug] Protocol:', req.protocol);
    console.log('🔐 [OAuth Debug] Session exists:', !!req.session);
    console.log('🔐 [OAuth Debug] Session ID:', req.session?.id);
    
    console.log('🔐 [OAuth Debug] Starting Google OAuth...');
    console.log('🔐 [OAuth Debug] Session ID before OAuth:', req.session?.id);
    
    passport.authenticate("google", { 
      scope: ["profile", "email"],
      // Let Passport handle state automatically with state: true in Strategy
      // SECURITY: Force fresh authentication - prevent Google from auto-approving
      prompt: "select_account consent", // Always show account picker and require consent
      accessType: "offline"   // Request offline access
    })(req, res, next);
  });

  app.get("/api/auth/google/callback", 
    (req, res, next) => {
      console.log('🔄 [OAuth Debug] === CALLBACK RECEIVED ===');
      console.log('🔄 [OAuth Debug] Method:', req.method);
      console.log('🔄 [OAuth Debug] URL:', req.url);
      console.log('🔄 [OAuth Debug] Original URL:', req.originalUrl);
      console.log('🔄 [OAuth Debug] Query params:', req.query);
      console.log('🔄 [OAuth Debug] Session exists:', !!req.session);
      console.log('🔄 [OAuth Debug] Session ID:', req.session?.id);
      console.log('🔄 [OAuth Debug] Session state managed by Passport');
      console.log('🔄 [OAuth Debug] User before auth:', req.user || 'none');
      console.log('🔄 [OAuth Debug] IP:', req.ip);
      console.log('🔄 [OAuth Debug] Hostname:', req.hostname);
      console.log('🔄 [OAuth Debug] User-Agent:', req.get('User-Agent'));
      next();
    },
    passport.authenticate("google", { 
      failureRedirect: "/?error=oauth_failed",
      failureFlash: false
    }),
    (req, res, next) => {
      // Custom error handler to log authentication failures
      if (!req.user) {
        console.log('❌ [OAuth Debug] === AUTHENTICATION FAILED ===');
        console.log('❌ [OAuth Debug] No user object after passport auth');
        console.log('❌ [OAuth Debug] Session ID:', req.session?.id);
        console.log('❌ [OAuth Debug] Redirecting to failure URL...');
        return res.redirect("/?error=oauth_failed");
      }
      next();
    },
    (req, res) => {
      // Success handler - user is authenticated and approved
      console.log('✅ [OAuth Debug] === AUTHENTICATION SUCCESS ===');
      console.log('✅ [OAuth Debug] User authenticated:', (req.user as any)?.email);
      console.log('✅ [OAuth Debug] User ID:', (req.user as any)?.id);
      console.log('✅ [OAuth Debug] Session ID after auth:', req.session?.id);
      console.log('✅ [OAuth Debug] Redirecting to dashboard...');
      res.redirect("/");
    }
  );

  app.get("/api/logout", (req, res) => {
    // SECURITY: Force immediate session cleanup with cache prevention
    req.logout((err) => {
      if (err) {
        console.error('[Auth] Logout error:', err);
        return res.status(500).json({ message: "Error during logout" });
      }
      
      // Complete session cleanup for security
      req.session.destroy((sessionErr) => {
        if (sessionErr) {
          console.error('[Auth] Session destroy error:', sessionErr);
        }
        
        console.log('[Auth] User logged out and session destroyed');
        
        // Clear all authentication cookies
        res.clearCookie('connect.sid', { 
          path: '/',
          httpOnly: true,
          secure: true,
          sameSite: 'none'
        });
        
        // Prevent browser caching of logout response
        res.header('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.header('Pragma', 'no-cache');
        res.header('Expires', '0');
        
        // Redirect to home page
        res.redirect("/");
      });
    });
  });
}

export const isAuthenticated: RequestHandler = (req, res, next) => {
  // In bypass mode, always allow through (runtime check)
  if (process.env.BYPASS_AUTH === 'true') {
    console.log(`[Auth Bypass] isAuthenticated middleware - bypassing for ${req.path}`);
    return next();
  }
  
  // Normal OAuth mode - check authentication
  if (req.isAuthenticated() && req.user) {
    return next();
  }
  
  console.log(`[Auth] isAuthenticated failed for ${req.path}`);
  return res.status(401).json({ message: "Unauthorized" });
};
