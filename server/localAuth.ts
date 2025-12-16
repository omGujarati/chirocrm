import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import bcrypt from "bcrypt";
import type { Express, RequestHandler } from "express";
import { storage } from "./storage";

// Type for authenticated user
export interface AuthenticatedUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  profileImageUrl?: string;
  role: string;
  isActive: boolean;
  mustChangePassword?: boolean;
}

// Dev admin user for bypass mode
const DEV_ADMIN_USER: AuthenticatedUser = {
  id: 'dev_admin',
  email: 'dev@local',
  firstName: 'Dev',
  lastName: 'Admin',
  role: 'admin',
  isActive: true,
};

// Configure passport serialization
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await storage.getUser(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// Local authentication strategy
passport.use(new LocalStrategy(
  {
    usernameField: 'email',
    passwordField: 'password',
  },
  async (email, password, done) => {
    try {
      console.log(`[Auth Debug] Login attempt for email: ${email}`);
      
      // Find user by email
      const user = await storage.getUserByEmail(email);
      
      if (!user) {
        console.log(`[Auth Debug] User not found for email: ${email}`);
        return done(null, false, { message: 'Invalid email or password' });
      }

      console.log(`[Auth Debug] User found: ${user.email}, active: ${user.isActive}, hasPassword: ${!!user.passwordHash}, verificationStatus: ${user.verificationStatus}`);

      // Check if account is rejected (for attorney accounts)
      if (user.role === 'attorney' && user.verificationStatus === 'rejected') {
        console.log(`[Auth Debug] User ${email} account has been rejected`);
        const errorInfo: any = { message: 'Account has been rejected. Please contact an administrator.' };
        errorInfo.code = 'ACCOUNT_REJECTED';
        return done(null, false, errorInfo);
      }

      // Check if user is active
      if (!user.isActive) {
        console.log(`[Auth Debug] User ${email} is not active`);
        return done(null, false, { message: 'Account has been deactivated' });
      }

      // Check if user has a password set
      if (!user.passwordHash) {
        console.log(`[Auth Debug] User ${email} has no password set`);
        return done(null, false, { message: 'Password not set for this account' });
      }

      // Verify password
      console.log(`[Auth Debug] Verifying password for ${email}`);
      const isValidPassword = await bcrypt.compare(password, user.passwordHash);
      console.log(`[Auth Debug] Password verification result: ${isValidPassword}`);
      
      if (!isValidPassword) {
        console.log(`[Auth Debug] Invalid password for ${email}`);
        return done(null, false, { message: 'Invalid email or password' });
      }

      // Authentication successful
      console.log(`[Auth] Successful login: ${email} (${user.role})`);
      return done(null, user);
    } catch (error) {
      console.error(`[Auth Debug] Error during login:`, error);
      return done(error);
    }
  }
));

export async function setupAuth(app: Express) {
  // Check if auth bypass mode is enabled
  const bypassAuth = process.env.BYPASS_AUTH === 'true';
  
  if (bypassAuth) {
    console.log('⚠️  [Auth] BYPASS_AUTH enabled - authentication disabled for development');
    console.log('⚠️  [Auth] All users will be logged in as dev admin automatically');
    
    // Ensure dev admin user exists in storage
    const existingDevAdmin = await storage.getUser(DEV_ADMIN_USER.id);
    if (!existingDevAdmin) {
      await storage.upsertUser({
        id: DEV_ADMIN_USER.id,
        email: DEV_ADMIN_USER.email,
        passwordHash: null,
        firstName: DEV_ADMIN_USER.firstName,
        lastName: DEV_ADMIN_USER.lastName,
        role: 'admin' as const,
        isActive: true,
      });
      console.log('[Auth] Created dev admin user in database');
    }
    
    // Middleware to inject dev admin user into all requests
    app.use((req, res, next) => {
      (req as any).user = DEV_ADMIN_USER;
      (req as any).isAuthenticated = () => true;
      next();
    });
    
    console.log('[Auth] Auth bypass configured - all requests will use dev admin user');
    return;
  }

  // Normal authentication mode
  app.use(passport.initialize());
  app.use(passport.session());

  // Login route
  app.post('/api/auth/login', (req, res, next) => {
    passport.authenticate('local', (err: any, user: any, info: any) => {
      if (err) {
        return res.status(500).json({ message: 'Authentication error' });
      }
      
      if (!user) {
        return res.status(401).json({ 
          message: info?.message || 'Invalid credentials',
          code: info?.code || 'LOGIN_FAILED'
        });
      }

      req.logIn(user, (err) => {
        if (err) {
          return res.status(500).json({ message: 'Login error' });
        }
        
        return res.json({ 
          message: 'Login successful',
          user: {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            role: user.role,
          }
        });
      });
    })(req, res, next);
  });

  // Logout route
  app.post('/api/auth/logout', (req, res) => {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ message: 'Logout error' });
      }
      req.session.destroy((sessionErr) => {
        if (sessionErr) {
          console.error('[Auth] Error destroying session:', sessionErr);
        }
        res.json({ message: 'Logout successful' });
      });
    });
  });

  // Get current user route
  app.get('/api/auth/user', (req, res) => {
    if (req.isAuthenticated()) {
      const user = req.user as AuthenticatedUser;
      res.json({
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      });
    } else {
      res.status(401).json({ message: 'Not authenticated' });
    }
  });

  console.log('[Auth] Username/password authentication configured');
}

// Auth middleware
export const isAuthenticated: RequestHandler = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: 'Not authenticated' });
};
