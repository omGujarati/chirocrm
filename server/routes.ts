import type { Express, Request, RequestHandler } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupAuth, isAuthenticated } from "./localAuth";
import { configureSession } from "./session";
import {
  insertPatientSchema,
  insertTaskSchema,
  insertAppointmentSchema,
  insertPatientNoteSchema,
} from "@shared/schema";
import { notificationService } from "./services/emailService";
import { docusignService } from "./services/docusignService";
import { alertService } from "./services/alertService";
import { insertUserSchema, attorneyRegistrationSchema } from "@shared/schema";
import { z } from "zod";
import multer from "multer";
import path from "path";
import fs from "fs/promises";
import crypto from "crypto";
import { sendOtpEmail, sendAppointmentEmail } from "./services/sendgridMailer";
import {
  uploadToS3,
  downloadFromS3,
  deleteFromS3,
  isS3Configured,
} from "./services/s3Service";

// Type definition for authenticated user (Google OAuth)
interface AuthenticatedUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  profileImageUrl?: string;
  role: string;
}

// Type assertion helper for authenticated requests
type AuthenticatedRequest = Request & { user: AuthenticatedUser };

// Typed helper to get user ID from authenticated requests - prevents auth system regressions
const getUserId = (req: AuthenticatedRequest): string => {
  const user = req.user as AuthenticatedUser;
  if (!user || !user.id) {
    throw new Error("User not authenticated or missing user ID");
  }
  return user.id;
};

// Middleware to attach fresh user data from database and enforce active status
const withCurrentUser = async (req: any, res: any, next: any) => {
  try {
    const user = req.user as AuthenticatedUser;

    if (!user || !user.id) {
      return res.status(401).json({ message: "User not authenticated" });
    }

    // Get fresh user data from database
    const currentUser = await storage.getUser(user.id);

    if (!currentUser) {
      return res.status(401).json({ message: "User not found" });
    }

    // SECURITY: Enforce isActive status on every request
    if (!currentUser.isActive) {
      console.warn(
        `[Auth] Access denied - deactivated user attempted access: ${currentUser.email} (${currentUser.id})`
      );

      // Force session cleanup for security - deactivated users should be immediately logged out
      req.logout((err: any) => {
        if (err) {
          console.error(
            "[Auth] Error during forced logout of deactivated user:",
            err
          );
        }
      });

      req.session.destroy((sessionErr: any) => {
        if (sessionErr) {
          console.error(
            "[Auth] Error destroying session for deactivated user:",
            sessionErr
          );
        }
      });

      return res.status(401).json({
        message: "Access denied - account has been deactivated",
        code: "ACCOUNT_DEACTIVATED",
      });
    }

    req.currentUser = currentUser;
    next();
  } catch (error) {
    console.error("Error fetching current user:", error);
    res.status(500).json({ message: "Failed to fetch user data" });
  }
};

export async function registerRoutes(app: Express): Promise<Server> {
  // Configure centralized session with OAuth compatibility
  configureSession(app);

  // Auth middleware
  await setupAuth(app);

  // Auth bypass mode - create local authGuard that respects BYPASS_AUTH at route definition time
  const isBypass = process.env.BYPASS_AUTH === "true";
  const authGuard: RequestHandler = isBypass
    ? (_req, _res, next) => {
        next();
      }
    : isAuthenticated;

  // Session diagnostics endpoint (debug only)
  app.get("/api/debug/session", async (req: any, res) => {
    try {
      console.log("🔬 [Session Debug] === SESSION DIAGNOSTICS ===");
      const diagnostics = {
        timestamp: new Date().toISOString(),
        sessionExists: !!req.session,
        sessionId: req.session?.id || null,
        isAuthenticated: req.isAuthenticated?.() || false,
        userExists: !!req.user,
        userId: req.user?.id || null,
        userEmail: req.user?.email || null,
        cookies: req.headers.cookie || null,
        userAgent: req.get("User-Agent") || null,
        ip: req.ip,
        hostname: req.hostname,
        protocol: req.protocol,
        path: req.path,
        originalUrl: req.originalUrl,
        sessionData: req.session
          ? {
              id: req.session.id,
              cookie: req.session.cookie
                ? {
                    maxAge: req.session.cookie.maxAge,
                    secure: req.session.cookie.secure,
                    httpOnly: req.session.cookie.httpOnly,
                    sameSite: req.session.cookie.sameSite,
                  }
                : null,
            }
          : null,
      };

      console.log("🔬 [Session Debug] Diagnostics:", diagnostics);
      res.json(diagnostics);
    } catch (error) {
      console.error("🔬 [Session Debug] Error:", error);
      res.status(500).json({
        error: "Session diagnostics failed",
        message: (error as Error).message,
      });
    }
  });

  // Auth routes - returns current user (dev admin in bypass mode)
  app.get("/api/auth/user", authGuard, async (req: any, res) => {
    if (isBypass) {
      // In bypass mode, return dev admin user directly
      const devAdmin = await storage.getUser("dev_admin");
      if (!devAdmin) {
        return res.status(500).json({ message: "Dev admin user not found" });
      }
      return res.json(devAdmin);
    }

    // Normal mode - use withCurrentUser middleware
    await withCurrentUser(req, res, () => {
      res.json(req.currentUser);
    });
  });

  // Attorney registration route (public, no auth required)
  app.post("/api/auth/register", async (req: any, res) => {
    try {
      // Validate request body
      const parseResult = attorneyRegistrationSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({
          message: "Validation failed",
          errors: parseResult.error.issues,
        });
      }

      const registrationData = parseResult.data;

      // Check if email already exists
      const existingUser = await storage.getUserByEmail(registrationData.email);
      if (existingUser) {
        return res
          .status(400)
          .json({ message: "User with this email already exists" });
      }

      // Hash password
      const bcrypt = await import("bcrypt");
      const passwordHash = await bcrypt.hash(registrationData.password, 10);

      // Create the attorney user with pending_verification status
      const userToCreate = {
        id: `user_${Math.random().toString(36).substr(2, 9)}`,
        email: registrationData.email,
        passwordHash,
        firstName: registrationData.firstName,
        lastName: registrationData.lastName,
        role: "attorney" as const,
        isActive: true,
        mustChangePassword: false,
        verificationStatus: "pending_verification" as const,
      };

      const newUser = await storage.upsertUser(userToCreate);

      // Create audit log for registration
      await storage.createAuditLog({
        userId: newUser.id,
        action: "registered",
        resourceType: "user",
        resourceId: newUser.id,
        details: {
          email: newUser.email,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          role: "attorney",
          verificationStatus: "pending_verification",
        },
        ipAddress: req.ip,
        userAgent: req.get("User-Agent"),
      });

      res.status(201).json({
        message:
          "Registration successful. Your account is pending verification by an administrator.",
        user: {
          id: newUser.id,
          email: newUser.email,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          verificationStatus: newUser.verificationStatus,
        },
      });
    } catch (error) {
      console.error("Error during registration:", error);
      res.status(500).json({ message: "Failed to register account" });
    }
  });

  // Forgot password - request OTP (public, no auth required)
  app.post("/api/auth/forgot-password/request", async (req: any, res) => {
    const requestSchema = z.object({
      email: z.string().email("Invalid email address"),
    });

    try {
      // Best-effort cleanup on every request
      await storage.cleanupExpiredTempOtps();

      const parsed = requestSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          message: "Validation failed",
          errors: parsed.error.issues,
        });
      }

      const email = parsed.data.email.trim().toLowerCase();

      const user = await storage.getUserByEmail(email);
      if (!user) {
        return res.status(404).json({
          message: "Account not found. Please register.",
          code: "ACCOUNT_NOT_FOUND",
        });
      }

      // Rate limit: max 5 OTPs in 5 minutes per email
      const windowMs = 5 * 60 * 1000;
      const now = new Date();
      const since = new Date(now.getTime() - windowMs);
      const recentCount = await storage.countRecentTempOtpsByEmail(
        email,
        since
      );
      if (recentCount >= 5) {
        return res.status(429).json({
          message: "Too many OTP requests. Please try again in a few minutes.",
          code: "OTP_RATE_LIMIT",
          retryAfterSeconds: 5 * 60,
        });
      }

      const otp = crypto.randomInt(100000, 1000000).toString(); // 6 digits
      const otpSecret =
        process.env.OTP_SECRET ||
        process.env.SESSION_SECRET ||
        "dev_otp_secret";
      const otpHash = crypto
        .createHash("sha256")
        .update(`${email}:${otp}:${otpSecret}`)
        .digest("hex");

      const expiresInMinutes = 2;
      const expiresAt = new Date(now.getTime() + expiresInMinutes * 60 * 1000);
      await storage.createTempOtp({ email, otpHash, expiresAt });

      await sendOtpEmail({ to: email, otp, expiresInMinutes });

      return res.json({
        message: "OTP sent to your email address.",
        expiresInMinutes,
        cooldownSeconds: 30,
      });
    } catch (error) {
      console.error("Error requesting forgot-password OTP:", error);
      return res.status(500).json({
        message: "Failed to send OTP. Please try again.",
        code: "OTP_SEND_FAILED",
      });
    }
  });

  function base64UrlEncode(input: string): string {
    return Buffer.from(input, "utf8")
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
  }

  function base64UrlDecode(input: string): string {
    const padLength = (4 - (input.length % 4)) % 4;
    const padded =
      input.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padLength);
    return Buffer.from(padded, "base64").toString("utf8");
  }

  function signResetToken(payload: { email: string; exp: number }): string {
    const secret =
      process.env.OTP_SECRET || process.env.SESSION_SECRET || "dev_otp_secret";
    const json = JSON.stringify(payload);
    const body = base64UrlEncode(json);
    const sig = crypto
      .createHmac("sha256", secret)
      .update(body)
      .digest("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
    return `${body}.${sig}`;
  }

  function verifyResetToken(token: string): { email: string } | null {
    try {
      const secret =
        process.env.OTP_SECRET ||
        process.env.SESSION_SECRET ||
        "dev_otp_secret";
      const [body, sig] = token.split(".");
      if (!body || !sig) return null;
      const expectedSig = crypto
        .createHmac("sha256", secret)
        .update(body)
        .digest("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
      if (expectedSig !== sig) return null;
      const payload = JSON.parse(base64UrlDecode(body)) as {
        email?: string;
        exp?: number;
      };
      if (!payload?.email || !payload?.exp) return null;
      if (Date.now() > payload.exp) return null;
      return { email: String(payload.email).trim().toLowerCase() };
    } catch {
      return null;
    }
  }

  // Forgot password - verify OTP (public, no auth required)
  app.post("/api/auth/forgot-password/verify", async (req: any, res) => {
    const verifySchema = z.object({
      email: z.string().email("Invalid email address"),
      otp: z
        .string()
        .min(6, "OTP must be 6 digits")
        .max(6, "OTP must be 6 digits")
        .regex(/^\d{6}$/, "OTP must be 6 digits"),
    });

    try {
      await storage.cleanupExpiredTempOtps();

      const parsed = verifySchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          message: "Validation failed",
          errors: parsed.error.issues,
        });
      }

      const email = parsed.data.email.trim().toLowerCase();
      const otp = parsed.data.otp;

      const user = await storage.getUserByEmail(email);
      if (!user) {
        return res.status(404).json({
          message: "Account not found. Please register.",
          code: "ACCOUNT_NOT_FOUND",
        });
      }

      const latestOtp = await storage.getLatestValidTempOtpByEmail(email);
      if (!latestOtp) {
        return res.status(400).json({
          message: "OTP expired or not found. Please request a new OTP.",
          code: "OTP_NOT_FOUND",
        });
      }

      const otpSecret =
        process.env.OTP_SECRET ||
        process.env.SESSION_SECRET ||
        "dev_otp_secret";
      const providedHash = crypto
        .createHash("sha256")
        .update(`${email}:${otp}:${otpSecret}`)
        .digest("hex");

      if (providedHash !== latestOtp.otpHash) {
        return res.status(400).json({
          message: "Invalid OTP. Please try again.",
          code: "OTP_INVALID",
        });
      }

      // Consume OTP to prevent replay; reset flow continues with resetToken
      await storage.consumeTempOtp(latestOtp.id);
      await storage.deleteTempOtpsByEmail(email);

      const tokenTtlMs = 15 * 60 * 1000; // 15 minutes
      const resetToken = signResetToken({
        email,
        exp: Date.now() + tokenTtlMs,
      });

      return res.json({
        message: "OTP verified.",
        resetToken,
        expiresInMinutes: 15,
      });
    } catch (error) {
      console.error("Error verifying forgot-password OTP:", error);
      return res.status(500).json({
        message: "Failed to verify OTP. Please try again.",
        code: "OTP_VERIFY_FAILED",
      });
    }
  });

  // Forgot password - reset password with OTP (public, no auth required)
  app.post("/api/auth/forgot-password/reset", async (req: any, res) => {
    const resetSchema = z
      .object({
        email: z.string().email("Invalid email address"),
        // New flow: resetToken returned by /verify. Keep otp optional for backward compatibility.
        resetToken: z.string().min(10).optional().nullable(),
        otp: z
          .string()
          .min(6, "OTP must be 6 digits")
          .max(6, "OTP must be 6 digits")
          .regex(/^\d{6}$/, "OTP must be 6 digits")
          .optional(),
        newPassword: z
          .string()
          .min(8, "Password must be at least 8 characters"),
        confirmPassword: z
          .string()
          .min(8, "Password must be at least 8 characters"),
      })
      .refine((data) => data.newPassword === data.confirmPassword, {
        message: "Passwords do not match",
        path: ["confirmPassword"],
      });

    try {
      await storage.cleanupExpiredTempOtps();

      const parsed = resetSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          message: "Validation failed",
          errors: parsed.error.issues,
        });
      }

      const email = parsed.data.email.trim().toLowerCase();
      const otp = parsed.data.otp;
      const resetToken = parsed.data.resetToken
        ? String(parsed.data.resetToken)
        : null;
      const newPassword = parsed.data.newPassword;

      const user = await storage.getUserByEmail(email);
      if (!user) {
        return res.status(404).json({
          message: "Account not found. Please register.",
          code: "ACCOUNT_NOT_FOUND",
        });
      }

      // Preferred: verify resetToken (OTP already verified on /verify)
      if (resetToken) {
        const verified = verifyResetToken(resetToken);
        if (!verified || verified.email !== email) {
          return res.status(400).json({
            message:
              "Verification expired or invalid. Please request a new OTP.",
            code: "RESET_TOKEN_INVALID",
          });
        }
      } else {
        // Backward-compatible flow: verify OTP inline (old UI)
        if (!otp) {
          return res.status(400).json({
            message: "OTP is required.",
            code: "OTP_REQUIRED",
          });
        }

        const latestOtp = await storage.getLatestValidTempOtpByEmail(email);
        if (!latestOtp) {
          return res.status(400).json({
            message: "OTP expired or not found. Please request a new OTP.",
            code: "OTP_NOT_FOUND",
          });
        }

        const otpSecret =
          process.env.OTP_SECRET ||
          process.env.SESSION_SECRET ||
          "dev_otp_secret";
        const providedHash = crypto
          .createHash("sha256")
          .update(`${email}:${otp}:${otpSecret}`)
          .digest("hex");

        if (providedHash !== latestOtp.otpHash) {
          return res.status(400).json({
            message: "Invalid OTP. Please try again.",
            code: "OTP_INVALID",
          });
        }

        // Consume OTP first to prevent race / replay
        await storage.consumeTempOtp(latestOtp.id);
      }

      // Update password hash
      const bcrypt = await import("bcrypt");
      const passwordHash = await bcrypt.hash(newPassword, 10);
      await storage.updateUser(user.id, {
        passwordHash,
        mustChangePassword: false,
      });

      // Cleanup all OTPs for that email
      await storage.deleteTempOtpsByEmail(email);

      return res.json({ message: "Password updated successfully." });
    } catch (error) {
      console.error("Error resetting password with OTP:", error);
      return res.status(500).json({
        message: "Failed to reset password. Please try again.",
        code: "PASSWORD_RESET_FAILED",
      });
    }
  });

  // Change password route
  app.put("/api/auth/change-password", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const { currentPassword, newPassword } = req.body;

      if (!currentPassword || !newPassword) {
        return res
          .status(400)
          .json({ message: "Current and new password are required" });
      }

      if (newPassword.length < 8) {
        return res
          .status(400)
          .json({ message: "New password must be at least 8 characters" });
      }

      // Get user from storage
      const user = await storage.getUser(userId);
      if (!user || !user.passwordHash) {
        return res
          .status(400)
          .json({ message: "User not found or password not set" });
      }

      // Verify current password
      const bcrypt = await import("bcrypt");
      const isValidPassword = await bcrypt.compare(
        currentPassword,
        user.passwordHash
      );
      if (!isValidPassword) {
        await auditLog(req, "password_change_failed", "user", userId, {
          reason: "invalid_current_password",
        });
        return res
          .status(401)
          .json({ message: "Current password is incorrect" });
      }

      // Hash new password
      const newPasswordHash = await bcrypt.hash(newPassword, 10);

      // Update password and clear mustChangePassword flag
      await storage.updateUser(userId, {
        passwordHash: newPasswordHash,
        mustChangePassword: false,
      });

      await auditLog(req, "password_changed", "user", userId, {
        changedBy: userId,
      });

      res.json({ message: "Password changed successfully" });
    } catch (error) {
      console.error("Error changing password:", error);
      res.status(500).json({ message: "Failed to change password" });
    }
  });

  // Update user profile route - allows users to update their own profile
  app.put("/api/auth/profile", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const { firstName, lastName, email, currentPassword, newPassword } =
        req.body;

      // Get current user from storage
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      const updateData: any = {};

      // Update firstName if provided
      if (firstName !== undefined) {
        if (firstName.trim().length === 0) {
          return res
            .status(400)
            .json({ message: "First name cannot be empty" });
        }
        updateData.firstName = firstName.trim();
      }

      // Update lastName if provided
      if (lastName !== undefined) {
        if (lastName.trim().length === 0) {
          return res.status(400).json({ message: "Last name cannot be empty" });
        }
        updateData.lastName = lastName.trim();
      }

      // Update email if provided
      if (email !== undefined) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email.trim())) {
          return res.status(400).json({ message: "Invalid email format" });
        }

        // Check if email is already taken by another user
        const existingUser = await storage.getUserByEmail(email.trim());
        if (existingUser && existingUser.id !== userId) {
          return res.status(400).json({ message: "Email is already in use" });
        }
        updateData.email = email.trim();
      }

      // Update password if provided
      if (newPassword !== undefined) {
        if (newPassword.length < 8) {
          return res
            .status(400)
            .json({ message: "New password must be at least 8 characters" });
        }

        // If user has a password, require current password verification
        const bcrypt = await import("bcrypt");
        if (user.passwordHash) {
          if (!currentPassword) {
            return res.status(400).json({
              message: "Current password is required to change password",
            });
          }

          const isValidPassword = await bcrypt.compare(
            currentPassword,
            user.passwordHash
          );
          if (!isValidPassword) {
            await auditLog(
              req,
              "profile_password_change_failed",
              "user",
              userId,
              {
                reason: "invalid_current_password",
              }
            );
            return res
              .status(401)
              .json({ message: "Current password is incorrect" });
          }
        }

        // Hash new password
        updateData.passwordHash = await bcrypt.hash(newPassword, 10);
        updateData.mustChangePassword = false;
      }

      // If no updates provided, return error
      if (Object.keys(updateData).length === 0) {
        return res.status(400).json({ message: "No updates provided" });
      }

      // Update user
      const updatedUser = await storage.updateUser(userId, updateData);

      await auditLog(req, "profile_updated", "user", userId, {
        updatedFields: Object.keys(updateData).filter(
          (key) => key !== "passwordHash"
        ),
        passwordChanged: !!updateData.passwordHash,
      });

      res.json({
        message: "Profile updated successfully",
        user: {
          id: updatedUser.id,
          email: updatedUser.email,
          firstName: updatedUser.firstName,
          lastName: updatedUser.lastName,
          role: updatedUser.role,
          profileImageUrl: updatedUser.profileImageUrl,
        },
      });
    } catch (error) {
      console.error("Error updating profile:", error);
      res.status(500).json({ message: "Failed to update profile" });
    }
  });

  // Users routes - for fetching attorneys for assignment
  app.get("/api/users", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(403).json({ message: "User not found" });
      }

      // Only admin and staff can fetch user lists (for attorney assignment)
      if (user.role !== "admin" && user.role !== "staff") {
        await auditLog(req, "users_list_denied", "users", "", {
          role: user.role,
          reason: "insufficient_role",
        });
        return res
          .status(403)
          .json({ message: "Insufficient permissions to view user list" });
      }

      // Parse pagination parameters
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 5;

      // Validate pagination parameters
      const validLimit = [5, 10, 50, 100].includes(limit) ? limit : 5;
      const validPage = page > 0 ? page : 1;

      // Get paginated users
      const {
        users: allUsers,
        total,
        totalPages,
      } = await storage.getUsersPaginated(validPage, validLimit);

      // Filter to only return relevant info and no PHI
      const safeUsers = allUsers.map((u) => ({
        id: u.id,
        firstName: u.firstName,
        lastName: u.lastName,
        email: u.email,
        role: u.role,
        isActive: u.isActive,
        verificationStatus: u.verificationStatus,
        rejectionReason: u.rejectionReason,
      }));

      await auditLog(req, "users_list_accessed", "users", "", {
        role: user.role,
        count: safeUsers.length,
        page: validPage,
        limit: validLimit,
      });

      res.json({
        users: safeUsers,
        pagination: {
          page: validPage,
          limit: validLimit,
          total,
          totalPages,
        },
      });
    } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ message: "Failed to fetch users" });
    }
  });

  // Create new user - Admin only
  app.post("/api/users/create", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);

      if (!user || user.role !== "admin") {
        await auditLog(req, "user_create_denied", "users", "", {
          role: user?.role || "unknown",
          reason: "insufficient_role",
        });
        return res
          .status(403)
          .json({ message: "Only administrators can create users" });
      }

      // Validate request body with password
      const { insertUserWithPasswordSchema } = await import("@shared/schema");
      const parseResult = insertUserWithPasswordSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({
          message: "Validation failed",
          errors: parseResult.error.issues,
        });
      }

      const { password, ...userData } = parseResult.data;

      // Check if email already exists
      const existingUsers = await storage.getUsers();
      const existingUser = existingUsers.find(
        (u) => u.email === userData.email
      );
      if (existingUser) {
        return res
          .status(400)
          .json({ message: "User with this email already exists" });
      }

      // Hash password
      const bcrypt = await import("bcrypt");
      const passwordHash = await bcrypt.hash(password, 10);

      // Create the user with password
      const userToCreate = {
        id: `user_${Math.random().toString(36).substr(2, 9)}`,
        ...userData,
        passwordHash,
        mustChangePassword: true, // Force password change on first login
      };
      const newUser = await storage.upsertUser(userToCreate);

      await auditLog(req, "user_created", "users", newUser.id, {
        adminUserId: userId,
        newUser: {
          email: newUser.email,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          role: newUser.role,
        },
      });

      res.status(201).json({
        message: `User ${newUser.firstName} ${newUser.lastName} created successfully`,
        user: {
          id: newUser.id,
          email: newUser.email,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          role: newUser.role,
          isActive: newUser.isActive,
        },
      });
    } catch (error) {
      console.error("Error creating user:", error);
      res.status(500).json({ message: "Failed to create user" });
    }
  });

  // User management endpoints (admin only)
  app.patch("/api/users/:id/status", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);
      const targetUserId = req.params.id;

      if (!user || user.role !== "admin") {
        await auditLog(
          req,
          "user_status_change_denied",
          "users",
          targetUserId,
          {
            role: user?.role || "unknown",
            reason: "insufficient_permissions",
            targetUserId,
          }
        );
        return res.status(403).json({ message: "Admin access required" });
      }

      const { isActive } = req.body;

      if (typeof isActive !== "boolean") {
        return res.status(400).json({ message: "isActive must be a boolean" });
      }

      // Prevent admin from deactivating themselves
      if (targetUserId === userId && !isActive) {
        return res
          .status(400)
          .json({ message: "Cannot deactivate your own account" });
      }

      const updatedUser = await storage.updateUserStatus(
        targetUserId,
        isActive
      );

      await auditLog(req, "user_status_changed", "users", targetUserId, {
        adminUserId: userId,
        oldStatus: !isActive ? "active" : "inactive",
        newStatus: isActive ? "active" : "inactive",
        targetUser: {
          id: updatedUser.id,
          email: updatedUser.email,
          role: updatedUser.role,
        },
      });

      res.json({
        message: `User ${isActive ? "activated" : "deactivated"} successfully`,
        user: {
          id: updatedUser.id,
          firstName: updatedUser.firstName,
          lastName: updatedUser.lastName,
          email: updatedUser.email,
          role: updatedUser.role,
          isActive: updatedUser.isActive,
        },
      });
    } catch (error) {
      console.error("Error updating user status:", error);
      res.status(500).json({ message: "Failed to update user status" });
    }
  });

  // Verify attorney account (admin only)
  app.patch("/api/users/:id/verify", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);
      const targetUserId = req.params.id;

      if (!user || user.role !== "admin") {
        await auditLog(req, "user_verification_denied", "users", targetUserId, {
          role: user?.role || "unknown",
          reason: "insufficient_permissions",
          targetUserId,
        });
        return res.status(403).json({ message: "Admin access required" });
      }

      const targetUser = await storage.getUser(targetUserId);
      if (!targetUser) {
        return res.status(404).json({ message: "User not found" });
      }

      if (targetUser.role !== "attorney") {
        return res
          .status(400)
          .json({ message: "Only attorney accounts can be verified" });
      }

      const updatedUser = await storage.updateUser(targetUserId, {
        verificationStatus: "verified" as const,
      });

      await auditLog(req, "user_verified", "users", targetUserId, {
        adminUserId: userId,
        targetUser: {
          id: updatedUser.id,
          email: updatedUser.email,
          firstName: updatedUser.firstName,
          lastName: updatedUser.lastName,
          role: updatedUser.role,
        },
      });

      res.json({
        message: `Attorney ${updatedUser.firstName} ${updatedUser.lastName} verified successfully`,
        user: {
          id: updatedUser.id,
          firstName: updatedUser.firstName,
          lastName: updatedUser.lastName,
          email: updatedUser.email,
          role: updatedUser.role,
          verificationStatus: updatedUser.verificationStatus,
        },
      });
    } catch (error) {
      console.error("Error verifying user:", error);
      res.status(500).json({ message: "Failed to verify user" });
    }
  });

  // Reject attorney account (admin only)
  app.patch("/api/users/:id/reject", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);
      const targetUserId = req.params.id;

      if (!user || user.role !== "admin") {
        await auditLog(req, "user_rejection_denied", "users", targetUserId, {
          role: user?.role || "unknown",
          reason: "insufficient_permissions",
          targetUserId,
        });
        return res.status(403).json({ message: "Admin access required" });
      }

      const targetUser = await storage.getUser(targetUserId);
      if (!targetUser) {
        return res.status(404).json({ message: "User not found" });
      }

      if (targetUser.role !== "attorney") {
        return res
          .status(400)
          .json({ message: "Only attorney accounts can be rejected" });
      }

      // Get rejection reason from request body (optional)
      const { rejectionReason } = req.body;

      const updatedUser = await storage.updateUser(targetUserId, {
        verificationStatus: "rejected" as const,
        isActive: false, // Also deactivate rejected accounts
        rejectionReason: rejectionReason || null,
      });

      await auditLog(req, "user_rejected", "users", targetUserId, {
        adminUserId: userId,
        targetUser: {
          id: updatedUser.id,
          email: updatedUser.email,
          firstName: updatedUser.firstName,
          lastName: updatedUser.lastName,
          role: updatedUser.role,
        },
      });

      res.json({
        message: `Attorney ${updatedUser.firstName} ${updatedUser.lastName} rejected`,
        user: {
          id: updatedUser.id,
          firstName: updatedUser.firstName,
          lastName: updatedUser.lastName,
          email: updatedUser.email,
          role: updatedUser.role,
          verificationStatus: updatedUser.verificationStatus,
          isActive: updatedUser.isActive,
        },
      });
    } catch (error) {
      console.error("Error rejecting user:", error);
      res.status(500).json({ message: "Failed to reject user" });
    }
  });

  // Update verification status and rejection reason (admin only)
  app.patch(
    "/api/users/:id/verification-status",
    authGuard,
    async (req: any, res) => {
      try {
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);
        const targetUserId = req.params.id;

        if (!user || user.role !== "admin") {
          await auditLog(
            req,
            "user_verification_status_update_denied",
            "users",
            targetUserId,
            {
              role: user?.role || "unknown",
              reason: "insufficient_permissions",
              targetUserId,
            }
          );
          return res.status(403).json({ message: "Admin access required" });
        }

        const targetUser = await storage.getUser(targetUserId);
        if (!targetUser) {
          return res.status(404).json({ message: "User not found" });
        }

        if (targetUser.role !== "attorney") {
          return res.status(400).json({
            message:
              "Only attorney accounts can have verification status updated",
          });
        }

        const { verificationStatus, rejectionReason } = req.body;

        if (
          !verificationStatus ||
          !["pending_verification", "verified", "rejected"].includes(
            verificationStatus
          )
        ) {
          return res
            .status(400)
            .json({ message: "Invalid verification status" });
        }

        const updateData: any = {
          verificationStatus: verificationStatus,
        };

        // If rejecting, also deactivate and set rejection reason
        if (verificationStatus === "rejected") {
          updateData.isActive = false;
          updateData.rejectionReason = rejectionReason || null;
        } else if (verificationStatus === "verified") {
          // If verifying, ensure account is active
          updateData.isActive = true;
          updateData.rejectionReason = null;
        } else {
          // If pending, keep current active status but clear rejection reason
          updateData.rejectionReason = null;
        }

        const updatedUser = await storage.updateUser(targetUserId, updateData);

        await auditLog(
          req,
          "user_verification_status_updated",
          "users",
          targetUserId,
          {
            adminUserId: userId,
            previousStatus: targetUser.verificationStatus,
            newStatus: verificationStatus,
            rejectionReason: rejectionReason || null,
            targetUser: {
              id: updatedUser.id,
              email: updatedUser.email,
              firstName: updatedUser.firstName,
              lastName: updatedUser.lastName,
              role: updatedUser.role,
            },
          }
        );

        res.json({
          message: `Attorney verification status updated successfully`,
          user: {
            id: updatedUser.id,
            firstName: updatedUser.firstName,
            lastName: updatedUser.lastName,
            email: updatedUser.email,
            role: updatedUser.role,
            verificationStatus: updatedUser.verificationStatus,
            rejectionReason: updatedUser.rejectionReason,
            isActive: updatedUser.isActive,
          },
        });
      } catch (error) {
        console.error("Error updating verification status:", error);
        res
          .status(500)
          .json({ message: "Failed to update verification status" });
      }
    }
  );

  app.delete("/api/users/:id", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);
      const targetUserId = req.params.id;

      if (!user || user.role !== "admin") {
        await auditLog(req, "user_delete_denied", "users", targetUserId, {
          role: user?.role || "unknown",
          reason: "insufficient_permissions",
          targetUserId,
        });
        return res.status(403).json({ message: "Admin access required" });
      }

      // Prevent admin from deleting themselves
      if (targetUserId === userId) {
        return res
          .status(400)
          .json({ message: "Cannot delete your own account" });
      }

      // Get target user details for audit log before deletion
      const targetUser = await storage.getUser(targetUserId);

      if (!targetUser) {
        return res.status(404).json({ message: "User not found" });
      }

      // Check if user has audit logs (HIPAA compliance - preserve audit trail)
      const userAuditLogs = await storage.getAuditLogs();
      const hasAuditLogs = userAuditLogs.some(
        (log) => log.userId === targetUserId
      );

      if (hasAuditLogs) {
        return res.status(400).json({
          message:
            "Cannot delete user with audit log history. For HIPAA compliance, deactivate the user instead.",
        });
      }

      await storage.deleteUser(targetUserId);

      await auditLog(req, "user_deleted", "users", targetUserId, {
        adminUserId: userId,
        deletedUser: {
          id: targetUser.id,
          email: targetUser.email,
          role: targetUser.role,
        },
      });

      res.json({ message: "User deleted successfully" });
    } catch (error) {
      console.error("Error deleting user:", error);
      res.status(500).json({ message: "Failed to delete user" });
    }
  });

  // Update user password - Admin or self
  app.patch("/api/users/:id/password", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);
      const targetUserId = req.params.id;

      if (!user) {
        return res.status(403).json({ message: "User not found" });
      }

      // Only admin or the user themselves can update password
      if (user.role !== "admin" && userId !== targetUserId) {
        await auditLog(req, "password_update_denied", "users", targetUserId, {
          role: user.role,
          reason: "insufficient_permissions",
        });
        return res
          .status(403)
          .json({ message: "Cannot update another user's password" });
      }

      const { password, currentPassword } = req.body;

      if (!password || password.length < 8) {
        return res
          .status(400)
          .json({ message: "Password must be at least 8 characters" });
      }

      // If user is updating their own password, verify current password
      if (userId === targetUserId && !isBypass) {
        if (!currentPassword) {
          return res
            .status(400)
            .json({ message: "Current password is required" });
        }

        const targetUser = await storage.getUser(targetUserId);
        if (!targetUser || !targetUser.passwordHash) {
          return res
            .status(400)
            .json({ message: "User not found or no password set" });
        }

        const bcrypt = await import("bcrypt");
        const isValid = await bcrypt.compare(
          currentPassword,
          targetUser.passwordHash
        );
        if (!isValid) {
          return res
            .status(401)
            .json({ message: "Current password is incorrect" });
        }
      }

      // Hash new password
      const bcrypt = await import("bcrypt");
      const passwordHash = await bcrypt.hash(password, 10);

      // Update password
      const targetUser = await storage.getUser(targetUserId);
      if (!targetUser) {
        return res.status(404).json({ message: "User not found" });
      }

      await storage.upsertUser({
        id: targetUser.id,
        email: targetUser.email,
        passwordHash,
        firstName: targetUser.firstName,
        lastName: targetUser.lastName,
        role: targetUser.role,
        isActive: targetUser.isActive,
      });

      await auditLog(req, "password_updated", "users", targetUserId, {
        updatedBy: userId,
        isSelfUpdate: userId === targetUserId,
      });

      res.json({ message: "Password updated successfully" });
    } catch (error) {
      console.error("Error updating password:", error);
      res.status(500).json({ message: "Failed to update password" });
    }
  });

  // Audit logging middleware
  const auditLog = async (
    req: any,
    action: string,
    resourceType: string,
    resourceId: string,
    details?: any
  ) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      await storage.createAuditLog({
        userId: authenticatedUser.id,
        action,
        resourceType,
        resourceId,
        details,
        ipAddress: req.ip,
        userAgent: req.get("User-Agent"),
      });
    } catch (error) {
      console.error("Failed to create audit log:", error);
    }
  };

  // Centralized audit log helper for system-initiated actions (no req available)
  // NOTE: userId is required due to FK constraint; prefer a real actor when possible.
  const systemAuditLog = async (
    userId: string,
    action: string,
    resourceType: string,
    resourceId: string,
    details?: any,
    patientId?: string
  ) => {
    try {
      await storage.createAuditLog({
        userId,
        action,
        resourceType,
        resourceId,
        patientId,
        details,
      });
    } catch (error) {
      console.error("Failed to create system audit log:", error);
    }
  };

  // Patient history helper (product-facing timeline inside Patient Details)
  const patientHistoryLog = async (
    req: any,
    patientId: string,
    eventType: string,
    title: string,
    message?: string,
    metadata?: any
  ) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      await storage.createPatientHistoryLog({
        patientId,
        actorUserId: authenticatedUser?.id ?? null,
        eventType,
        title,
        message,
        metadata,
      });
    } catch (error) {
      console.error("Failed to create patient history log:", error);
    }
  };

  // For system/webhook events where we don't have req/session
  const systemPatientHistoryLog = async (
    patientId: string,
    actorUserId: string | null,
    eventType: string,
    title: string,
    message?: string,
    metadata?: any
  ) => {
    try {
      await storage.createPatientHistoryLog({
        patientId,
        actorUserId,
        eventType,
        title,
        message,
        metadata,
      });
    } catch (error) {
      console.error("Failed to create system patient history log:", error);
    }
  };

  // Update user details - Admin only
  app.put("/api/users/:id", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);
      const targetUserId = req.params.id;

      if (!user || user.role !== "admin") {
        await auditLog(req, "user_update_denied", "users", targetUserId, {
          role: user?.role || "unknown",
          reason: "insufficient_permissions",
          targetUserId,
        });
        return res.status(403).json({ message: "Admin access required" });
      }

      const { firstName, lastName, email, role } = req.body;

      // Get target user
      const targetUser = await storage.getUser(targetUserId);
      if (!targetUser) {
        return res.status(404).json({ message: "User not found" });
      }

      const updateData: any = {};

      // Update firstName if provided
      if (firstName !== undefined) {
        if (firstName.trim().length === 0) {
          return res
            .status(400)
            .json({ message: "First name cannot be empty" });
        }
        updateData.firstName = firstName.trim();
      }

      // Update lastName if provided
      if (lastName !== undefined) {
        if (lastName.trim().length === 0) {
          return res.status(400).json({ message: "Last name cannot be empty" });
        }
        updateData.lastName = lastName.trim();
      }

      // Update email if provided
      if (email !== undefined) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email.trim())) {
          return res.status(400).json({ message: "Invalid email format" });
        }

        // Check if email is already taken by another user
        const existingUser = await storage.getUserByEmail(email.trim());
        if (existingUser && existingUser.id !== targetUserId) {
          return res.status(400).json({ message: "Email is already in use" });
        }
        updateData.email = email.trim();
      }

      // Update role if provided (with validation)
      if (role !== undefined) {
        if (!["admin", "staff", "attorney"].includes(role)) {
          return res.status(400).json({ message: "Invalid role" });
        }

        // Prevent admin from changing their own role
        if (targetUserId === userId && role !== "admin") {
          return res
            .status(400)
            .json({ message: "Cannot change your own role" });
        }

        // Prevent changing role of the last admin
        if (targetUser.role === "admin" && role !== "admin") {
          const allUsers = await storage.getUsers();
          const adminCount = allUsers.filter(
            (u) => u.role === "admin" && u.isActive
          ).length;
          if (adminCount <= 1) {
            return res
              .status(400)
              .json({ message: "Cannot change role of the last active admin" });
          }
        }

        updateData.role = role;
      }

      // If no updates provided, return error
      if (Object.keys(updateData).length === 0) {
        return res.status(400).json({ message: "No updates provided" });
      }

      // Update user
      const updatedUser = await storage.updateUser(targetUserId, updateData);

      await auditLog(req, "user_updated", "users", targetUserId, {
        adminUserId: userId,
        updatedFields: Object.keys(updateData),
        previousData: {
          firstName: targetUser.firstName,
          lastName: targetUser.lastName,
          email: targetUser.email,
          role: targetUser.role,
        },
        newData: {
          firstName: updatedUser.firstName,
          lastName: updatedUser.lastName,
          email: updatedUser.email,
          role: updatedUser.role,
        },
      });

      res.json({
        message: "User updated successfully",
        user: {
          id: updatedUser.id,
          email: updatedUser.email,
          firstName: updatedUser.firstName,
          lastName: updatedUser.lastName,
          role: updatedUser.role,
          isActive: updatedUser.isActive,
          verificationStatus: updatedUser.verificationStatus,
        },
      });
    } catch (error) {
      console.error("Error updating user:", error);
      res.status(500).json({ message: "Failed to update user" });
    }
  });

  // Helper function to check if user can access a patient
  const canAccessPatient = (user: any, patient: any): boolean => {
    if (user.role === "admin") return true;
    if (
      user.role === "staff" &&
      (patient.createdBy.id === user.id ||
        patient.assignedAttorney?.id === user.id)
    )
      return true;
    if (user.role === "attorney" && patient.assignedAttorney?.id === user.id)
      return true;
    return false;
  };

  // Dashboard stats
  app.get("/api/dashboard/stats", authGuard, async (req: any, res) => {
    try {
      const stats = await storage.getDashboardStats();
      res.json(stats);
    } catch (error) {
      console.error("Error fetching dashboard stats:", error);
      res.status(500).json({ message: "Failed to fetch dashboard stats" });
    }
  });

  // Dashboard activity chart
  app.get("/api/dashboard/activity", authGuard, async (req: any, res) => {
    try {
      const rangeParam = req.query.range;
      const range =
        rangeParam === "weekly" || rangeParam === "monthly"
          ? rangeParam
          : "monthly";
      const compare = String(req.query.compare || "").toLowerCase();
      const includeCompare =
        compare === "1" || compare === "true" || compare === "yes";

      if (includeCompare) {
        const activity = await storage.getDashboardActivityWithCompare(range);
        return res.json({
          range,
          data: activity.current,
          previousData: activity.previous,
        });
      }

      const activity = await storage.getDashboardActivity(range);
      res.json({ range, data: activity });
    } catch (error) {
      console.error("Error fetching dashboard activity:", error);
      res.status(500).json({ message: "Failed to fetch dashboard activity" });
    }
  });

  // Patient routes
  app.get("/api/patients", authGuard, async (req: any, res) => {
    try {
      const { status, page, limit } = req.query;
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(403).json({ message: "User not found" });
      }

      // Parse pagination parameters with defaults
      const pageNum = parseInt(page as string) || 1;
      const limitNum = parseInt(limit as string) || 5;

      // Validate pagination parameters
      const validLimit = [5, 10, 50, 100].includes(limitNum) ? limitNum : 5;
      const validPage = pageNum > 0 ? pageNum : 1;

      // Parse status filter
      const statusFilter =
        status && typeof status === "string" && status !== "all"
          ? status
          : undefined;

      // Use paginated method which handles role-based access control internally
      const result = await storage.getPatientsPaginated(
        validPage,
        validLimit,
        statusFilter,
        userId,
        user.role
      );

      // Audit log the access with count
      await auditLog(req, "list_accessed", "patients", "", {
        count: result.total,
        role: user.role,
        status: statusFilter || "all",
        page: validPage,
        limit: validLimit,
      });

      // Return response in the format expected by frontend
      res.json({
        patients: result.patients,
        pagination: {
          page: validPage,
          limit: validLimit,
          total: result.total,
          totalPages: result.totalPages,
        },
      });
    } catch (error) {
      console.error("Error fetching patients:", error);
      res.status(500).json({ message: "Failed to fetch patients" });
    }
  });

  app.get("/api/patients/:id", authGuard, async (req: any, res) => {
    try {
      const patient = await storage.getPatient(req.params.id);
      if (!patient) {
        return res.status(404).json({ message: "Patient not found" });
      }

      const userId = req.user.id;
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(403).json({ message: "User not found" });
      }

      // HIPAA compliance: Enforce least privilege access
      if (!canAccessPatient(user, patient)) {
        await auditLog(req, "view_denied", "patient", patient.id, {
          role: user.role,
          reason: "insufficient_permissions",
        });
        return res
          .status(403)
          .json({ message: "Access denied - insufficient permissions" });
      }

      await auditLog(req, "viewed", "patient", patient.id, { role: user.role });
      res.json(patient);
    } catch (error) {
      console.error("Error fetching patient:", error);
      res.status(500).json({ message: "Failed to fetch patient" });
    }
  });

  app.post("/api/patients", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(403).json({ message: "User not found" });
      }

      const patientData = insertPatientSchema.parse({
        ...req.body,
        createdBy: userId,
        assignedAttorney: userId, // Auto-assign creator to the patient
        status: "pending_consent", // Server enforces initial status - ignore client value
      });

      const patient = await storage.createPatient(patientData);
      // HIPAA-safe audit log - no PHI in details
      await auditLog(req, "created", "patient", patient.id, {
        role: user.role,
        hasFirstName: !!patientData.firstName,
        hasLastName: !!patientData.lastName,
        hasEmail: !!patientData.email,
        status: patientData.status,
      });

      await patientHistoryLog(
        req,
        patient.id,
        "patient_created",
        "Patient created",
        `Patient created by ${user.firstName ?? ""} ${
          user.lastName ?? ""
        }`.trim(),
        { createdBy: userId, initialStatus: patientData.status }
      );

      // Create initial task to send consent form
      if (patient.status === "pending_consent") {
        await storage.createTask({
          title: "Send consent form",
          description: `Initial consent form needs to be sent to the patient.`,
          patientId: patient.id,
          assignedTo: req.user.id,
          createdBy: req.user.id,
          priority: "normal",
          dueDate: new Date(Date.now() + 24 * 60 * 60 * 1000), // Due in 24 hours
        });
      }

      res.status(201).json(patient);
    } catch (error) {
      console.error("Error creating patient:", error);
      res.status(400).json({
        message: "Failed to create patient",
        error: (error as Error).message,
      });
    }
  });

  // Schema for patient updates - only allow demographic fields, block all workflow/server-managed fields
  const updatePatientSchema = insertPatientSchema
    .pick({
      firstName: true,
      lastName: true,
      email: true,
      phone: true,
      dateOfBirth: true,
      dateOfInjury: true,
      address: true,
    })
    .partial();

  app.put("/api/patients/:id", authGuard, async (req: any, res) => {
    try {
      const patientId = req.params.id;
      const userId = req.user.id;
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(403).json({ message: "User not found" });
      }

      // Get patient to check ownership
      const existingPatient = await storage.getPatient(patientId);
      if (!existingPatient) {
        return res.status(404).json({ message: "Patient not found" });
      }

      // Only admin and staff can update patient information
      if (user.role !== "admin" && user.role !== "staff") {
        await auditLog(req, "update_denied", "patient", patientId, {
          role: user.role,
          reason: "insufficient_role",
        });
        return res.status(403).json({
          message: "Only admin and staff can update patient information",
        });
      }

      // Only allow demographic field updates - NO status or workflow fields
      const patientData = updatePatientSchema.parse(req.body);

      const patient = await storage.updatePatient(patientId, patientData);
      // HIPAA-safe audit log - no PHI in details
      await auditLog(req, "updated", "patient", patient.id, {
        role: user.role,
        fieldsUpdated: Object.keys(patientData),
        fieldCount: Object.keys(patientData).length,
      });

      res.json(patient);
    } catch (error) {
      console.error("Error updating patient:", error);
      res.status(400).json({
        message: "Failed to update patient",
        error: (error as Error).message,
      });
    }
  });

  // PATCH endpoint for admin-only updates (like envelope ID)
  app.patch("/api/patients/:id", authGuard, async (req: any, res) => {
    try {
      const patientId = req.params.id;
      const userId = req.user.id;
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(403).json({ message: "User not found" });
      }

      // Get patient to check ownership
      const existingPatient = await storage.getPatient(patientId);
      if (!existingPatient) {
        return res.status(404).json({ message: "Patient not found" });
      }

      // Only admins can use PATCH to update envelope ID
      if (user.role !== "admin") {
        await auditLog(req, "update_denied", "patient", patientId, {
          role: user.role,
          reason: "insufficient_permissions",
        });
        return res
          .status(403)
          .json({ message: "Only administrators can update envelope ID" });
      }

      // Admin-only schema for updating envelope ID
      const updatePatientAdminSchema = updatePatientSchema.extend({
        docusignEnvelopeId: z.string().nullable().optional(),
      });

      // Parse with admin schema
      const patientData = updatePatientAdminSchema.parse(req.body);

      const patient = await storage.updatePatient(patientId, patientData);

      // Audit log for envelope ID update
      await auditLog(req, "updated", "patient", patient.id, {
        role: user.role,
        fieldsUpdated: Object.keys(patientData),
        envelopeIdUpdated: "docusignEnvelopeId" in patientData,
      });

      res.json(patient);
    } catch (error) {
      console.error("Error updating patient:", error);
      res.status(400).json({
        message: "Failed to update patient",
        error: (error as Error).message,
      });
    }
  });

  // Admin override patient consent status
  app.patch("/api/patients/:id/status", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);
      const patientId = req.params.id;

      if (!user || user.role !== "admin") {
        await auditLog(
          req,
          "patient_status_override_denied",
          "patient",
          patientId,
          {
            role: user?.role || "unknown",
            reason: "insufficient_permissions",
          }
        );
        return res
          .status(403)
          .json({ message: "Only administrators can override patient status" });
      }

      const { status } = req.body;
      const validStatuses = [
        "pending_consent",
        "consent_sent",
        "consent_signed",
        "schedulable",
        "treatment_completed",
        "pending_records",
        "records_forwarded",
        "records_verified",
        "case_closed",
        "dropped",
      ];

      if (!validStatuses.includes(status)) {
        return res.status(400).json({
          message: `Invalid status. Must be one of: ${validStatuses.join(
            ", "
          )}`,
        });
      }

      const patient = await storage.getPatient(patientId);
      if (!patient) {
        return res.status(404).json({ message: "Patient not found" });
      }

      const oldStatus = patient.status;

      // Prepare update data
      const updateData: any = {
        status: status as any,
      };

      // Set consentSignedAt if manually marking as signed
      if (status === "consent_signed" && !patient.consentSignedAt) {
        updateData.consentSignedAt = new Date();
      }

      // Set dropped fields if manually marking as dropped
      if (status === "dropped" && oldStatus !== "dropped") {
        updateData.droppedBy = userId;
        updateData.droppedAt = new Date();
        // If no drop reason provided, use a default
        if (!patient.dropReason) {
          updateData.dropReason = "Dropped via admin status override";
        }
      }

      // Update patient status
      const updatedPatient = await storage.updatePatient(patientId, updateData);

      await auditLog(req, "patient_status_override", "patient", patientId, {
        adminUserId: userId,
        oldStatus,
        newStatus: status,
        reason: "admin_manual_override",
        patientName: `${patient.firstName} ${patient.lastName}`,
      });

      await patientHistoryLog(
        req,
        patientId,
        "patient_status_changed",
        "Status updated",
        `Status changed from ${oldStatus} to ${status}`,
        { oldStatus, newStatus: status, source: "admin_override" }
      );

      res.json({
        message: `Patient status updated from ${oldStatus} to ${status}`,
        patient: {
          id: updatedPatient.id,
          status: updatedPatient.status,
          consentSignedAt: updatedPatient.consentSignedAt,
        },
      });
    } catch (error) {
      console.error("Error updating patient status:", error);
      res.status(500).json({ message: "Failed to update patient status" });
    }
  });

  // Update patient assignment (admin only)
  app.patch(
    "/api/patients/:id/assignment",
    authGuard,
    async (req: any, res) => {
      try {
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);
        const patientId = req.params.id;

        if (!user || user.role !== "admin") {
          await auditLog(
            req,
            "patient_assignment_update_denied",
            "patient",
            patientId,
            {
              role: user?.role || "unknown",
              reason: "insufficient_permissions",
            }
          );
          return res.status(403).json({
            message: "Only administrators can update patient assignments",
          });
        }

        const { assignedAttorney } = req.body;

        const patient = await storage.getPatient(patientId);
        if (!patient) {
          return res.status(404).json({ message: "Patient not found" });
        }

        // Validate that the assigned user exists and is active
        if (assignedAttorney && assignedAttorney !== "none") {
          const assignedUser = await storage.getUser(assignedAttorney);
          if (!assignedUser) {
            return res.status(400).json({ message: "Assigned user not found" });
          }
          if (!assignedUser.isActive) {
            return res
              .status(400)
              .json({ message: "Cannot assign to inactive user" });
          }
          if (
            assignedUser.role !== "attorney" &&
            assignedUser.role !== "staff"
          ) {
            return res
              .status(400)
              .json({ message: "Can only assign to staff or attorney users" });
          }
        }

        const oldAssignment = patient.assignedAttorney;
        const newAssignment =
          assignedAttorney === "none" ? null : assignedAttorney;

        // Update patient assignment
        const updatedPatient = await storage.updatePatient(patientId, {
          assignedAttorney: newAssignment,
        });

        await auditLog(
          req,
          "patient_assignment_updated",
          "patient",
          patientId,
          {
            adminUserId: userId,
            oldAssignment: oldAssignment || "unassigned",
            newAssignment: newAssignment || "unassigned",
            patientName: `${patient.firstName} ${patient.lastName}`,
          }
        );

        await patientHistoryLog(
          req,
          patientId,
          "patient_assignment_changed",
          "Assignment updated",
          undefined,
          {
            oldAssignedAttorneyId: oldAssignment,
            newAssignedAttorneyId: newAssignment,
          }
        );

        // Notify newly assigned user (in-app alert)
        // NOTE: Only notify the specific assignee (least privilege).
        if (newAssignment && newAssignment !== oldAssignment) {
          try {
            const assignedUser = await storage.getUser(newAssignment);
            if (assignedUser) {
              const message = `You have been assigned a patient: ${patient.firstName} ${patient.lastName}`;
              await storage.createAlert({
                type: "patient_assigned",
                patientId,
                userId: newAssignment,
                message,
                scheduledFor: new Date(), // immediate
              });
            }
          } catch (notificationError) {
            // Don't fail the request if notification fails
            console.error(
              "Failed to create patient assignment notification:",
              notificationError
            );
          }
        }

        res.json({
          message: "Patient assignment updated successfully",
          patient: {
            id: updatedPatient.id,
            assignedAttorney: updatedPatient.assignedAttorney,
          },
        });
      } catch (error) {
        console.error("Error updating patient assignment:", error);
        res
          .status(500)
          .json({ message: "Failed to update patient assignment" });
      }
    }
  );

  app.delete("/api/patients/:id", authGuard, async (req: any, res) => {
    try {
      const patientId = req.params.id;
      const userId = req.user.id;
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(403).json({ message: "User not found" });
      }

      // Get patient to check ownership
      const existingPatient = await storage.getPatient(patientId);
      if (!existingPatient) {
        return res.status(404).json({ message: "Patient not found" });
      }

      // HIPAA compliance: Only admin, creator, or assigned attorney can delete patient
      if (!canAccessPatient(user, existingPatient)) {
        await auditLog(req, "delete_denied", "patient", patientId, {
          role: user.role,
          reason: "insufficient_permissions",
        });
        return res
          .status(403)
          .json({ message: "Access denied - insufficient permissions" });
      }

      await storage.deletePatient(patientId);
      await auditLog(req, "deleted", "patient", patientId, { role: user.role });

      res.status(204).send();
    } catch (error) {
      console.error("Error deleting patient:", error);
      res.status(500).json({ message: "Failed to delete patient" });
    }
  });

  // Schema for consultation scheduling
  const scheduleConsultationSchema = insertPatientSchema
    .pick({
      consultationDate: true,
      consultationTime: true,
      consultationLocation: true,
    })
    .extend({
      consultationDate: z.coerce.date().refine((date) => date > new Date(), {
        message: "Consultation date must be in the future",
      }),
      consultationTime: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/, {
        message: "Time must be in HH:MM format",
      }),
      consultationLocation: z.string().min(1, "Location is required"),
    });

  // Schedule consultation
  app.put("/api/patients/:id/schedule", authGuard, async (req: any, res) => {
    try {
      const patientId = req.params.id;
      const userId = req.user.id;
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(403).json({ message: "User not found" });
      }

      // Get patient to check ownership and status
      const existingPatient = await storage.getPatient(patientId);
      if (!existingPatient) {
        return res.status(404).json({ message: "Patient not found" });
      }

      // Check if case is closed - only admin can schedule appointments for closed cases
      if (existingPatient.status === "case_closed" && user.role !== "admin") {
        await auditLog(req, "schedule_denied", "patient", patientId, {
          role: user.role,
          reason: "case_closed",
          status: existingPatient.status,
        });
        return res.status(403).json({
          message:
            "Cannot schedule appointment - case is closed. Only admin can perform this action.",
        });
      }

      // HIPAA compliance: Only admin, creator, or assigned attorney can schedule
      if (!canAccessPatient(user, existingPatient)) {
        await auditLog(req, "schedule_denied", "patient", patientId, {
          role: user.role,
          reason: "insufficient_permissions",
        });
        return res
          .status(403)
          .json({ message: "Access denied - insufficient permissions" });
      }

      // Role-based status validation: Staff can only schedule when status is 'consent_signed'
      if (
        user.role !== "admin" &&
        existingPatient.status !== "consent_signed"
      ) {
        await auditLog(req, "schedule_denied", "patient", patientId, {
          role: user.role,
          reason: "invalid_status",
          currentStatus: existingPatient.status,
        });
        return res.status(400).json({
          message: `Cannot schedule consultation - patient status is ${existingPatient.status}, must be consent_signed`,
        });
      }

      // Validate request body
      const parseResult = scheduleConsultationSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({
          message: "Validation failed",
          errors: parseResult.error.issues,
        });
      }

      const consultationData = parseResult.data;

      // Update patient with consultation details
      const patient = await storage.updatePatient(patientId, consultationData);

      // Create appointment in appointments table
      // Combine consultationDate and consultationTime into scheduledAt timestamp
      const consultationDate = new Date(consultationData.consultationDate);
      const [hours, minutes] = consultationData.consultationTime
        .split(":")
        .map(Number);
      consultationDate.setHours(hours, minutes, 0, 0);

      // Determine provider: use assignedAttorney if available, otherwise use current user
      const providerId = existingPatient.assignedAttorney?.id || userId;

      // Check if there's an existing appointment for this patient's consultation
      // (to handle updates/rescheduling - typically a patient has one consultation)
      const existingAppointments = await storage.getAppointmentsByPatient(
        patientId
      );
      const existingConsultationAppointment = existingAppointments.find(
        (apt) =>
          apt.status === "scheduled" &&
          // Match appointments on the same date (consultation rescheduling)
          new Date(apt.scheduledAt).toDateString() ===
            consultationDate.toDateString()
      );

      const isReschedule = !!existingConsultationAppointment;
      let appointment;
      if (existingConsultationAppointment) {
        // Update existing appointment
        appointment = await storage.updateAppointment(
          existingConsultationAppointment.id,
          {
            scheduledAt: consultationDate,
            providerId: providerId,
            notes: consultationData.consultationLocation,
            duration: 60, // Default 60 minutes
          }
        );
      } else {
        // Create new appointment
        appointment = await storage.createAppointment({
          patientId: patientId,
          providerId: providerId,
          scheduledAt: consultationDate,
          duration: 60, // Default 60 minutes
          status: "scheduled",
          notes: consultationData.consultationLocation,
          createdBy: userId,
        });
      }

      // Update patient status to schedulable when appointment is scheduled
      if (
        patient.status === "consent_signed" ||
        patient.status === "schedulable"
      ) {
        await storage.updatePatient(patient.id, { status: "schedulable" });
      }

      // HIPAA-safe audit log
      await auditLog(
        req,
        isReschedule ? "consultation_rescheduled" : "consultation_scheduled",
        "patient",
        patient.id,
        {
          role: user.role,
          hasDate: !!consultationData.consultationDate,
          hasTime: !!consultationData.consultationTime,
          hasLocation: !!consultationData.consultationLocation,
          scheduledBy: userId,
          appointmentId: appointment.id,
          type: isReschedule ? "reschedule" : "new",
        }
      );

      await patientHistoryLog(
        req,
        patient.id,
        isReschedule ? "consultation_rescheduled" : "consultation_scheduled",
        isReschedule ? "Consultation rescheduled" : "Consultation scheduled",
        undefined,
        {
          appointmentId: appointment.id,
          consultationDate: consultationData.consultationDate,
          consultationTime: consultationData.consultationTime,
          consultationLocation: consultationData.consultationLocation,
        }
      );

      // Send appointment email to patient
      if (patient.email) {
        try {
          const oldScheduledAt =
            isReschedule && existingConsultationAppointment
              ? new Date(existingConsultationAppointment.scheduledAt)
              : undefined;

          await sendAppointmentEmail({
            to: patient.email,
            patientName: `${patient.firstName} ${patient.lastName}`,
            scheduledAt: consultationDate,
            duration: appointment.duration || 60,
            location: consultationData.consultationLocation || null,
            isUpdate: isReschedule,
            oldScheduledAt: oldScheduledAt,
          });

          // Log email sent in patient history
          await patientHistoryLog(
            req,
            patient.id,
            "appointment_email_sent",
            isReschedule
              ? "Appointment update email sent"
              : "Appointment confirmation email sent",
            `${isReschedule ? "Update" : "Confirmation"} email sent to ${
              patient.email
            }`,
            {
              appointmentId: appointment.id,
              emailType: isReschedule ? "update" : "confirmation",
            }
          );
        } catch (emailError) {
          // Log error but don't fail the appointment scheduling
          console.error("Error sending appointment email:", emailError);
          // Still log that we attempted to send email
          await patientHistoryLog(
            req,
            patient.id,
            "appointment_email_failed",
            "Appointment email failed to send",
            `Failed to send ${
              isReschedule ? "update" : "confirmation"
            } email to ${patient.email}`,
            {
              appointmentId: appointment.id,
              emailType: isReschedule ? "update" : "confirmation",
              error: (emailError as Error).message,
            }
          );
        }
      }

      res.json({
        message: "Consultation scheduled successfully",
        patient: {
          id: patient.id,
          consultationDate: patient.consultationDate,
          consultationTime: patient.consultationTime,
          consultationLocation: patient.consultationLocation,
        },
        appointment: {
          id: appointment.id,
          scheduledAt: appointment.scheduledAt,
        },
      });
    } catch (error) {
      console.error("Error scheduling consultation:", error);
      res.status(400).json({
        message: "Failed to schedule consultation",
        error: (error as Error).message,
      });
    }
  });

  // Send consent form
  // Drop patient route - for attorneys and staff
  app.post("/api/patients/:id/drop", authGuard, async (req: any, res) => {
    try {
      const patientId = req.params.id;
      const userId = req.user.id;
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(403).json({ message: "User not found" });
      }

      // Only attorneys and staff can drop patients
      if (user.role !== "attorney" && user.role !== "staff") {
        await auditLog(req, "drop_denied", "patient", patientId, {
          role: user.role,
          reason: "insufficient_role",
        });
        return res
          .status(403)
          .json({ message: "Only attorneys and staff can drop patients" });
      }

      const patient = await storage.getPatient(patientId);
      if (!patient) {
        return res.status(404).json({ message: "Patient not found" });
      }

      // Check if user can access this patient
      if (!canAccessPatient(user, patient)) {
        await auditLog(req, "drop_denied", "patient", patientId, {
          role: user.role,
          reason: "no_access",
        });
        return res
          .status(403)
          .json({ message: "Access denied - you cannot drop this patient" });
      }

      // Validate drop reason
      const { dropReason } = req.body;
      if (
        !dropReason ||
        typeof dropReason !== "string" ||
        dropReason.trim().length === 0
      ) {
        return res.status(400).json({ message: "Drop reason is required" });
      }

      if (dropReason.trim().length > 1000) {
        return res
          .status(400)
          .json({ message: "Drop reason must be less than 1000 characters" });
      }

      // Drop the patient
      const droppedPatient = await storage.dropPatient(
        patientId,
        dropReason.trim(),
        userId
      );

      // HIPAA-compliant audit log
      await auditLog(req, "dropped", "patient", patientId, {
        role: user.role,
        droppedBy: userId,
        reasonLength: dropReason.trim().length,
        previousStatus: patient.status,
      });

      await patientHistoryLog(
        req,
        patientId,
        "case_dropped",
        "Case dropped",
        dropReason.trim(),
        { previousStatus: patient.status }
      );

      res.json({
        message: "Patient dropped successfully",
        patient: droppedPatient,
      });
    } catch (error) {
      console.error("Error dropping patient:", error);
      res.status(500).json({ message: "Failed to drop patient" });
    }
  });

  app.post(
    "/api/patients/:id/send-consent",
    authGuard,
    async (req: any, res) => {
      try {
        const patientId = req.params.id;
        const userId = req.user.id;

        // Role and ownership check for consent sending
        const user = await storage.getUser(userId);
        if (
          !user ||
          (user.role !== "admin" &&
            user.role !== "staff" &&
            user.role !== "attorney")
        ) {
          await auditLog(req, "consent_send_denied", "patient", patientId, {
            role: user?.role || "none",
            reason: "insufficient_role",
          });
          return res.status(403).json({
            message: "Insufficient permissions to send consent forms",
          });
        }

        const patient = await storage.getPatient(patientId);
        if (!patient) {
          return res.status(404).json({ message: "Patient not found" });
        }

        // Check if case is closed - only admin can send emails for closed cases
        if (patient.status === "case_closed" && user.role !== "admin") {
          await auditLog(req, "consent_send_denied", "patient", patientId, {
            role: user.role,
            reason: "case_closed",
            status: patient.status,
          });
          return res.status(403).json({
            message:
              "Cannot send consent - case is closed. Only admin can perform this action.",
          });
        }

        // HIPAA compliance: Staff can only send consent for patients they created, attorneys for assigned patients
        if (!canAccessPatient(user, patient)) {
          await auditLog(req, "consent_send_denied", "patient", patientId, {
            role: user.role,
            reason: "insufficient_permissions",
          });
          return res
            .status(403)
            .json({ message: "Access denied - insufficient permissions" });
        }

        // Get language from request body (default to 'en' if not provided)
        const language = (req.body?.language === "es" ? "es" : "en") as
          | "en"
          | "es";

        // Allow sending consent if status is pending_consent OR if changing language (consent_sent)
        // This allows users to resend with a different language
        const canSendConsent =
          patient.status === "pending_consent" ||
          (patient.status === "consent_sent" &&
            patient.consentLanguage !== language);

        if (!canSendConsent) {
          return res.status(400).json({
            message: `Cannot send consent - patient status is ${patient.status}. Only allowed for pending_consent or when changing language.`,
          });
        }

        // Convert PatientWithCreator to Patient format for DocuSign service
        const patientForDocuSign = {
          ...patient,
          createdBy: patient.createdBy.id,
          assignedAttorney: patient.assignedAttorney?.id || null,
        };
        const envelopeId = await docusignService.sendConsentForm(
          patientForDocuSign,
          language
        );

        await storage.updatePatient(patient.id, {
          status: "consent_sent",
          docusignEnvelopeId: envelopeId,
          consentLanguage: language,
        });

        await auditLog(req, "consent_sent", "patient", patient.id, {
          envelopeId,
          language,
        });

        await patientHistoryLog(
          req,
          patient.id,
          "consent_sent",
          "Consent sent",
          "DocuSign consent sent",
          { envelopeId, language }
        );

        // Schedule alerts
        await alertService.scheduleConsentAlerts(patient.id);

        // Auto-complete the "Send consent form" task for this patient
        try {
          const patientTasks = await storage.getTasksByPatient(patient.id);
          const sendConsentTask = patientTasks.find(
            (task) =>
              task.title === "Send consent form" && task.status === "pending"
          );

          if (sendConsentTask) {
            await storage.updateTask(sendConsentTask.id, {
              status: "completed",
              completedAt: new Date(),
            });

            await auditLog(req, "task_completed", "task", sendConsentTask.id, {
              role: user.role,
              patientId: patient.id,
              taskTitle: sendConsentTask.title,
              autoCompleted: true,
              reason: "consent_form_sent",
            });

            console.log(
              `✅ Auto-completed task "${sendConsentTask.title}" for patient ${patient.id}`
            );
          }
        } catch (taskError) {
          // Log error but don't fail the consent sending
          console.error("Error auto-completing consent task:", taskError);
        }

        res.json({ message: "Consent form sent successfully", envelopeId });
      } catch (error) {
        console.error("Error sending consent form:", error);
        res.status(500).json({
          message: "Failed to send consent form",
          error: (error as Error).message,
        });
      }
    }
  );

  // DocuSign webhook (basic security with shared secret)
  // app.post('/api/docusign/webhook', async (req, res) => {
  //   try {
  //     // Basic webhook security - check for a shared secret in headers
  //     const webhookSecret = req.headers['x-webhook-secret'];
  //     if (webhookSecret !== process.env.DOCUSIGN_WEBHOOK_SECRET) {
  //       console.warn('DocuSign webhook: Invalid or missing webhook secret');
  //       await auditLog(req, 'rejected', 'docusign_webhook', '', 'Invalid webhook secret');
  //       return res.status(401).json({ message: 'Unauthorized' });
  //     }

  //     const { envelopeId, status } = req.body;

  //     if (status === 'completed') {
  //       // Find patient by envelope ID
  //       const patients = await storage.getPatients();
  //       const patient = patients.find(p => p.docusignEnvelopeId === envelopeId);

  //       if (patient) {
  //         await storage.updatePatient(patient.id, {
  //           status: 'consent_signed',
  //           consentSignedAt: new Date(),
  //         });

  //         // Cancel any pending consent alerts for this patient
  //         await alertService.cancelPendingConsentAlerts(patient.id);

  //         await storage.createAuditLog({
  //           userId: 'system',
  //           patientId: patient.id,
  //           action: 'consent_signed',
  //           resourceType: 'patient',
  //           resourceId: patient.id,
  //           details: { envelopeId },
  //         });

  //         console.log(`Patient consent signed (ID: ${patient.id}) and pending alerts cancelled`);
  //       }
  //     }

  //     res.status(200).json({ message: "Webhook processed" });
  //   } catch (error) {
  //     console.error("Error processing DocuSign webhook:", error);
  //     res.status(500).json({ message: "Failed to process webhook" });
  //   }
  // });

  // Patient notes routes
  app.get(
    "/api/patients/:patientId/notes",
    authGuard,
    async (req: any, res) => {
      try {
        const { patientId } = req.params;
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);

        if (!user) {
          return res.status(403).json({ message: "User not found" });
        }

        // Verify patient exists and user has access
        const patient = await storage.getPatient(patientId);
        if (!patient) {
          return res.status(404).json({ message: "Patient not found" });
        }

        // HIPAA compliance: Enforce role-based access
        if (!canAccessPatient(user, patient)) {
          await auditLog(
            req,
            "notes_access_denied",
            "patient_notes",
            patientId,
            {
              role: user.role,
              reason: "insufficient_permissions",
            }
          );
          return res
            .status(403)
            .json({ message: "Access denied - insufficient permissions" });
        }

        const notes = await storage.getPatientNotes(patientId);

        await auditLog(req, "notes_viewed", "patient_notes", patientId, {
          role: user.role,
          count: notes.length,
        });

        res.json(notes);
      } catch (error) {
        console.error("Error fetching patient notes:", error);
        res.status(500).json({ message: "Failed to fetch patient notes" });
      }
    }
  );

  app.post(
    "/api/patients/:patientId/notes",
    authGuard,
    async (req: any, res) => {
      try {
        const { patientId } = req.params;
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);

        if (!user) {
          return res.status(403).json({ message: "User not found" });
        }

        // Verify patient exists and user has access
        const patient = await storage.getPatient(patientId);
        if (!patient) {
          return res.status(404).json({ message: "Patient not found" });
        }

        // Check if case is closed - only admin can create notes for closed cases
        if (patient.status === "case_closed" && user.role !== "admin") {
          await auditLog(
            req,
            "note_create_denied",
            "patient_notes",
            patientId,
            {
              role: user.role,
              reason: "case_closed",
              status: patient.status,
            }
          );
          return res.status(403).json({
            message:
              "Cannot create note - case is closed. Only admin can perform this action.",
          });
        }

        // HIPAA compliance: Enforce role-based access for creating notes
        if (!canAccessPatient(user, patient)) {
          await auditLog(
            req,
            "note_create_denied",
            "patient_notes",
            patientId,
            {
              role: user.role,
              reason: "insufficient_permissions",
            }
          );
          return res
            .status(403)
            .json({ message: "Access denied - insufficient permissions" });
        }

        const noteData = insertPatientNoteSchema.parse({
          ...req.body,
          patientId,
          createdBy: userId,
        });

        const newNote = await storage.createPatientNote(noteData);

        await auditLog(req, "note_created", "patient_notes", newNote.id, {
          patientId,
          role: user.role,
          noteLength: noteData.content.length,
        });

        await patientHistoryLog(
          req,
          patientId,
          "note_created",
          "Note added",
          undefined,
          { noteId: newNote.id, noteType: noteData.noteType }
        );

        res.status(201).json(newNote);
      } catch (error) {
        console.error("Error creating patient note:", error);
        res.status(500).json({ message: "Failed to create patient note" });
      }
    }
  );

  app.put(
    "/api/patients/:patientId/notes/:noteId",
    authGuard,
    async (req: any, res) => {
      try {
        const { patientId, noteId } = req.params;
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);

        if (!user) {
          return res.status(403).json({ message: "User not found" });
        }

        // Verify patient exists and user has access
        const patient = await storage.getPatient(patientId);
        if (!patient) {
          return res.status(404).json({ message: "Patient not found" });
        }

        // Check if case is closed - only admin can edit notes for closed cases
        if (patient.status === "case_closed" && user.role !== "admin") {
          await auditLog(req, "note_edit_denied", "patient_notes", noteId, {
            role: user.role,
            reason: "case_closed",
            status: patient.status,
          });
          return res.status(403).json({
            message:
              "Cannot edit note - case is closed. Only admin can perform this action.",
          });
        }

        if (!canAccessPatient(user, patient)) {
          await auditLog(req, "note_edit_denied", "patient_notes", noteId, {
            role: user.role,
            reason: "insufficient_permissions",
          });
          return res
            .status(403)
            .json({ message: "Access denied - insufficient permissions" });
        }

        // Get existing note to verify ownership (only creator can edit)
        const existingNotes = await storage.getPatientNotes(patientId);
        const existingNote = existingNotes.find((note) => note.id === noteId);

        if (!existingNote) {
          return res.status(404).json({ message: "Note not found" });
        }

        if (existingNote.createdBy !== userId && user.role !== "admin") {
          await auditLog(req, "note_edit_denied", "patient_notes", noteId, {
            role: user.role,
            reason: "not_creator",
          });
          return res
            .status(403)
            .json({ message: "Access denied - can only edit own notes" });
        }

        const updateData = insertPatientNoteSchema.partial().parse(req.body);
        const updatedNote = await storage.updatePatientNote(noteId, updateData);

        await auditLog(req, "note_updated", "patient_notes", noteId, {
          patientId,
          role: user.role,
        });

        await patientHistoryLog(
          req,
          patientId,
          "note_updated",
          "Note updated",
          undefined,
          { noteId, fieldsUpdated: Object.keys(updateData) }
        );

        res.json(updatedNote);
      } catch (error) {
        console.error("Error updating patient note:", error);
        res.status(500).json({ message: "Failed to update patient note" });
      }
    }
  );

  app.delete(
    "/api/patients/:patientId/notes/:noteId",
    authGuard,
    async (req: any, res) => {
      try {
        const { patientId, noteId } = req.params;
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);

        if (!user) {
          return res.status(403).json({ message: "User not found" });
        }

        // Only admins can delete notes for HIPAA compliance
        if (user.role !== "admin") {
          await auditLog(req, "note_delete_denied", "patient_notes", noteId, {
            role: user.role,
            reason: "insufficient_permissions",
          });
          return res
            .status(403)
            .json({ message: "Access denied - only admins can delete notes" });
        }

        // Verify note exists
        const existingNotes = await storage.getPatientNotes(patientId);
        const existingNote = existingNotes.find((note) => note.id === noteId);

        if (!existingNote) {
          return res.status(404).json({ message: "Note not found" });
        }

        await storage.deletePatientNote(noteId);

        await auditLog(req, "note_deleted", "patient_notes", noteId, {
          patientId,
          role: user.role,
          originalCreator: existingNote.createdBy,
        });

        await patientHistoryLog(
          req,
          patientId,
          "note_deleted",
          "Note deleted",
          undefined,
          { noteId, originalCreator: existingNote.createdBy }
        );

        res.json({ message: "Note deleted successfully" });
      } catch (error) {
        console.error("Error deleting patient note:", error);
        res.status(500).json({ message: "Failed to delete patient note" });
      }
    }
  );

  // Patient records routes
  app.get(
    "/api/patients/:patientId/records",
    authGuard,
    async (req: any, res) => {
      try {
        const { patientId } = req.params;
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);

        if (!user) {
          return res.status(403).json({ message: "User not found" });
        }

        // Verify patient exists and user has access
        const patient = await storage.getPatient(patientId);
        if (!patient) {
          return res.status(404).json({ message: "Patient not found" });
        }

        // HIPAA compliance: Enforce role-based access
        if (!canAccessPatient(user, patient)) {
          await auditLog(
            req,
            "records_access_denied",
            "patient_records",
            patientId,
            {
              role: user.role,
              reason: "insufficient_permissions",
            }
          );
          return res
            .status(403)
            .json({ message: "Access denied - insufficient permissions" });
        }

        let records = await storage.getPatientRecords(patientId);

        // For staff when case is closed: only show records they uploaded
        if (patient.status === "case_closed" && user.role === "staff") {
          records = records.filter((record) => record.uploadedBy === userId);
        }

        await auditLog(req, "records_viewed", "patient_records", patientId, {
          role: user.role,
          count: records.length,
        });

        res.json(records);
      } catch (error) {
        console.error("Error fetching patient records:", error);
        res.status(500).json({ message: "Failed to fetch patient records" });
      }
    }
  );

  // Secure file upload configuration with validation
  const fileFilter = (
    req: any,
    file: Express.Multer.File,
    cb: multer.FileFilterCallback
  ) => {
    // Allow only specific file types for medical records
    const allowedMimeTypes = [
      "application/pdf",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "image/jpeg",
      "image/png",
      "image/tiff",
    ];

    if (allowedMimeTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(
        new Error(
          "Invalid file type. Only PDF, DOC, DOCX, JPEG, PNG, and TIFF files are allowed."
        )
      );
    }
  };

  // Use memory storage for S3 uploads (or disk storage as fallback)
  // If S3 is configured, use memory storage; otherwise use disk storage for backward compatibility
  const useS3 = isS3Configured();

  const storage_config = useS3
    ? multer.memoryStorage() // Memory storage for S3 uploads
    : multer.diskStorage({
        destination: async (req, file, cb) => {
          try {
            const { patientId } = req.params;
            // Server-controlled secure path generation
            const uploadDir = path.join(
              process.cwd(),
              "uploads",
              "patients",
              patientId
            );

            // Ensure directory exists
            await fs.mkdir(uploadDir, { recursive: true });
            cb(null, uploadDir);
          } catch (error) {
            cb(error as Error, "");
          }
        },
        filename: (req, file, cb) => {
          // Server-controlled secure filename generation
          const timestamp = Date.now();
          const randomString = Math.random().toString(36).substring(2, 15);
          const sanitizedOriginalName = file.originalname.replace(
            /[^a-zA-Z0-9.-]/g,
            "_"
          );
          const secureFilename = `${timestamp}_${randomString}_${sanitizedOriginalName}`;
          cb(null, secureFilename);
        },
      });

  const upload = multer({
    storage: storage_config,
    fileFilter,
    limits: {
      fileSize: 50 * 1024 * 1024, // 50MB max file size
      files: 1, // Only one file per upload
    },
  });

  app.post(
    "/api/patients/:patientId/records",
    authGuard,
    upload.single("file"),
    async (req: any, res) => {
      try {
        const { patientId } = req.params;
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);

        if (!user) {
          return res.status(403).json({ message: "User not found" });
        }

        // Verify patient exists and user has access
        const patient = await storage.getPatient(patientId);
        if (!patient) {
          return res.status(404).json({ message: "Patient not found" });
        }

        // Check if case is closed - only admin can upload records for closed cases
        if (patient.status === "case_closed" && user.role !== "admin") {
          await auditLog(
            req,
            "record_upload_denied",
            "patient_records",
            patientId,
            {
              role: user.role,
              reason: "case_closed",
              status: patient.status,
            }
          );
          return res.status(403).json({
            message:
              "Cannot upload records - case is closed. Only admin can perform this action.",
          });
        }

        // Only staff can upload records (they will be forwarded to attorneys)
        if (user.role !== "staff" && user.role !== "admin") {
          await auditLog(
            req,
            "record_upload_denied",
            "patient_records",
            patientId,
            {
              role: user.role,
              reason: "insufficient_role",
            }
          );
          return res
            .status(403)
            .json({ message: "Only staff can upload patient records" });
        }

        // HIPAA compliance: Staff can only upload for patients they created
        if (user.role === "staff" && !canAccessPatient(user, patient)) {
          await auditLog(
            req,
            "record_upload_denied",
            "patient_records",
            patientId,
            {
              role: user.role,
              reason: "insufficient_permissions",
            }
          );
          return res
            .status(403)
            .json({ message: "Access denied - insufficient permissions" });
        }

        // Validate file upload
        if (!req.file) {
          return res.status(400).json({ message: "No file uploaded" });
        }

        const { description } = req.body;

        // Validate description
        if (description && description.length > 1000) {
          return res.status(400).json({ message: "Description too long" });
        }

        let recordData: any = {
          patientId,
          fileName: req.file.originalname,
          fileSize: req.file.size,
          mimeType: req.file.mimetype,
          description: description?.trim() || null,
          uploadedBy: userId,
          storageType: useS3 ? "s3" : "local",
        };

        // Upload to S3 if configured, otherwise use local storage
        if (useS3) {
          // Upload to S3 using memory buffer
          if (!req.file.buffer) {
            return res
              .status(400)
              .json({ message: "File buffer not available" });
          }

          const s3Result = await uploadToS3(
            req.file.buffer,
            req.file.originalname,
            req.file.mimetype,
            patientId
          );

          recordData.s3Key = s3Result.key;
          // filePath is null for S3 uploads
          recordData.filePath = null;
        } else {
          // Local storage fallback (backward compatibility)
          const secureFilePath = req.file.path;
          recordData.filePath = secureFilePath;
          recordData.s3Key = null;
        }

        const newRecord = await storage.createPatientRecord(recordData);

        await auditLog(
          req,
          "record_uploaded",
          "patient_records",
          newRecord.id,
          {
            role: user.role,
            patientId,
            fileName: req.file.originalname,
            fileSize: req.file.size,
            mimeType: req.file.mimetype,
            storageType: useS3 ? "s3" : "local",
          }
        );

        await patientHistoryLog(
          req,
          patientId,
          "record_uploaded",
          "Record uploaded",
          req.file.originalname,
          {
            recordId: newRecord.id,
            fileName: req.file.originalname,
            mimeType: req.file.mimetype,
          }
        );

        // Notify admins when staff uploads records
        // (Admins receive alerts; they can then verify/forward records)
        if (user.role === "staff") {
          try {
            const allUsers = await storage.getUsers();
            const activeAdmins = allUsers.filter(
              (u) => u.role === "admin" && u.isActive
            );
            const staffName =
              [user.firstName, user.lastName]
                .filter(Boolean)
                .join(" ")
                .trim() ||
              user.email ||
              "Staff";
            const patientName =
              `${patient.firstName} ${patient.lastName}`.trim();
            const message = `Records uploaded for ${patientName} by ${staffName}: ${req.file.originalname}`;

            await Promise.all(
              activeAdmins.map((admin) =>
                storage.createAlert({
                  type: "records_uploaded",
                  patientId,
                  userId: admin.id,
                  message,
                  scheduledFor: null,
                  sentAt: null,
                })
              )
            );
          } catch (notifyError) {
            // Don't fail upload if alert creation fails
            console.warn(
              "Failed to create admin alerts for record upload:",
              notifyError
            );
          }
        }

        res.status(201).json(newRecord);
      } catch (error) {
        console.error("Error uploading patient record:", error);

        // Handle multer errors specifically
        if (error instanceof multer.MulterError) {
          if (error.code === "LIMIT_FILE_SIZE") {
            return res
              .status(400)
              .json({ message: "File too large. Maximum size is 50MB." });
          }
          if (error.code === "LIMIT_UNEXPECTED_FILE") {
            return res
              .status(400)
              .json({ message: "Invalid file field. Use 'file' field name." });
          }
        }

        if ((error as Error).message.includes("Invalid file type")) {
          return res.status(400).json({ message: (error as Error).message });
        }

        res.status(500).json({ message: "Failed to upload patient record" });
      }
    }
  );

  // Generate time-limited preview token (15 minutes expiration)
  const generatePreviewToken = (
    patientId: string,
    recordId: string,
    userId: string
  ): string => {
    const secret = process.env.PREVIEW_TOKEN_SECRET || "change-this-secret-key";
    const expiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes from now
    const payload = `${patientId}:${recordId}:${userId}:${expiresAt}`;
    const signature = crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest("hex");
    const token = Buffer.from(`${payload}:${signature}`).toString("base64url");
    return token;
  };

  // Verify preview token
  const verifyPreviewToken = (
    token: string,
    patientId: string,
    recordId: string,
    userId: string
  ): boolean => {
    try {
      const secret =
        process.env.PREVIEW_TOKEN_SECRET || "change-this-secret-key";
      const decoded = Buffer.from(token, "base64url").toString("utf-8");
      const [tokenPatientId, tokenRecordId, tokenUserId, expiresAt, signature] =
        decoded.split(":");

      // Verify all parts match
      if (
        tokenPatientId !== patientId ||
        tokenRecordId !== recordId ||
        tokenUserId !== userId
      ) {
        return false;
      }

      // Check expiration
      if (Date.now() > parseInt(expiresAt, 10)) {
        return false;
      }

      // Verify signature
      const payload = `${tokenPatientId}:${tokenRecordId}:${tokenUserId}:${expiresAt}`;
      const expectedSignature = crypto
        .createHmac("sha256", secret)
        .update(payload)
        .digest("hex");

      return crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
      );
    } catch {
      return false;
    }
  };

  // Generate preview token endpoint
  app.get(
    "/api/patients/:patientId/records/:recordId/preview-token",
    authGuard,
    async (req: any, res) => {
      try {
        const { patientId, recordId } = req.params;
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);

        if (!user) {
          return res.status(403).json({ message: "User not found" });
        }

        // Verify patient exists and user has access
        const patient = await storage.getPatient(patientId);
        if (!patient) {
          return res.status(404).json({ message: "Patient not found" });
        }

        // HIPAA compliance: Enforce role-based access
        if (!canAccessPatient(user, patient)) {
          await auditLog(
            req,
            "record_preview_token_denied",
            "patient_records",
            recordId,
            {
              role: user.role,
              reason: "insufficient_permissions",
            }
          );
          return res
            .status(403)
            .json({ message: "Access denied - insufficient permissions" });
        }

        // Get record from database
        const records = await storage.getPatientRecords(patientId);
        const record = records.find((r) => r.id === recordId);

        if (!record) {
          return res.status(404).json({ message: "Record not found" });
        }

        // Generate time-limited token (15 minutes)
        const token = generatePreviewToken(patientId, recordId, userId);

        res.json({ token, expiresIn: 15 * 60 }); // expiresIn in seconds
      } catch (error) {
        console.error("Error generating preview token:", error);
        res.status(500).json({ message: "Failed to generate preview token" });
      }
    }
  );

  // Preview patient record file (secure endpoint with access control - inline display)
  app.get(
    "/api/patients/:patientId/records/:recordId/preview",
    authGuard,
    async (req: any, res) => {
      try {
        const { patientId, recordId } = req.params;
        const token = req.query.token as string | undefined;
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);

        // SECURITY: Require time-limited token for preview access
        if (!token || !verifyPreviewToken(token, patientId, recordId, userId)) {
          return res.status(403).json({
            message:
              "Invalid or expired preview token. Please request a new preview.",
          });
        }

        if (!user) {
          return res.status(403).json({ message: "User not found" });
        }

        // Verify patient exists and user has access
        const patient = await storage.getPatient(patientId);
        if (!patient) {
          return res.status(404).json({ message: "Patient not found" });
        }

        // HIPAA compliance: Enforce role-based access
        if (!canAccessPatient(user, patient)) {
          await auditLog(
            req,
            "record_preview_denied",
            "patient_records",
            recordId,
            {
              role: user.role,
              reason: "insufficient_permissions",
            }
          );
          return res
            .status(403)
            .json({ message: "Access denied - insufficient permissions" });
        }

        // Get record from database
        const records = await storage.getPatientRecords(patientId);
        const record = records.find((r) => r.id === recordId);

        if (!record) {
          return res.status(404).json({ message: "Record not found" });
        }

        // Only allow preview for PDFs and images
        const isPreviewable =
          record.mimeType?.includes("pdf") ||
          record.mimeType?.includes("image");
        if (!isPreviewable) {
          return res.status(400).json({
            message: "Preview is only available for PDF and image files",
          });
        }

        // Determine storage type and retrieve file
        if (record.storageType === "s3" && record.s3Key) {
          // Download from S3
          try {
            const fileStream = await downloadFromS3(record.s3Key);

            // Set appropriate headers for inline display (preview)
            const contentType = record.mimeType || "application/pdf";
            res.setHeader("Content-Type", contentType);
            res.setHeader(
              "Content-Disposition",
              `inline; filename="${encodeURIComponent(record.fileName)}"`
            );
            // Add security headers (but allow embedding for blob URLs)
            res.setHeader("X-Content-Type-Options", "nosniff");
            // Don't set X-Frame-Options for preview - blob URLs need to be embeddable

            // Handle stream errors
            fileStream.on("error", (streamError) => {
              console.error(
                "[Preview] Stream error during S3 preview:",
                streamError
              );
              if (!res.headersSent) {
                res.status(500).json({
                  message: "Error streaming file from S3",
                  error: (streamError as Error).message,
                });
              } else {
                // If headers already sent, we can't send JSON, just end the response
                res.end();
              }
            });

            // Handle response errors
            res.on("error", (resError) => {
              console.error("[Preview] Response error:", resError);
            });

            // Stream file to response
            fileStream.pipe(res);

            // Log after stream starts (don't await - let it stream)
            auditLog(req, "record_previewed", "patient_records", recordId, {
              role: user.role,
              storageType: "s3",
            }).catch((logError) => {
              console.error("Error logging preview:", logError);
            });
          } catch (s3Error) {
            console.error("Error previewing from S3:", s3Error);
            if (!res.headersSent) {
              return res.status(500).json({
                message: "Failed to preview file from S3",
                error: (s3Error as Error).message,
              });
            }
          }
        } else if (record.filePath) {
          // Preview from local storage (backward compatibility)
          try {
            const filePath = path.resolve(record.filePath);

            // Security: Verify file exists and is within allowed directory
            const uploadsDir = path.join(process.cwd(), "uploads");
            if (!filePath.startsWith(uploadsDir)) {
              return res.status(403).json({ message: "Invalid file path" });
            }

            const fileBuffer = await fs.readFile(filePath);

            res.setHeader("Content-Type", record.mimeType || "application/pdf");
            res.setHeader(
              "Content-Disposition",
              `inline; filename="${record.fileName}"`
            );
            res.setHeader("Content-Length", fileBuffer.length);
            // Add security headers
            res.setHeader("X-Content-Type-Options", "nosniff");
            res.setHeader("X-Frame-Options", "SAMEORIGIN");

            res.send(fileBuffer);

            await auditLog(
              req,
              "record_previewed",
              "patient_records",
              recordId,
              {
                role: user.role,
                storageType: "local",
              }
            );
          } catch (localError) {
            console.error("Error reading local file:", localError);
            return res.status(500).json({ message: "Failed to read file" });
          }
        } else {
          return res.status(404).json({ message: "File location not found" });
        }
      } catch (error) {
        console.error("Error previewing patient record:", error);
        res.status(500).json({ message: "Failed to preview patient record" });
      }
    }
  );

  // Download patient record file (secure endpoint with access control)
  app.get(
    "/api/patients/:patientId/records/:recordId/download",
    authGuard,
    async (req: any, res) => {
      try {
        const { patientId, recordId } = req.params;
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);

        if (!user) {
          return res.status(403).json({ message: "User not found" });
        }

        // Verify patient exists and user has access
        const patient = await storage.getPatient(patientId);
        if (!patient) {
          return res.status(404).json({ message: "Patient not found" });
        }

        // HIPAA compliance: Enforce role-based access
        if (!canAccessPatient(user, patient)) {
          await auditLog(
            req,
            "record_download_denied",
            "patient_records",
            recordId,
            {
              role: user.role,
              reason: "insufficient_permissions",
            }
          );
          return res
            .status(403)
            .json({ message: "Access denied - insufficient permissions" });
        }

        // Get record from database
        const records = await storage.getPatientRecords(patientId);
        const record = records.find((r) => r.id === recordId);

        if (!record) {
          return res.status(404).json({ message: "Record not found" });
        }

        // Determine storage type and retrieve file
        if (record.storageType === "s3" && record.s3Key) {
          // Download from S3
          try {
            const fileStream = await downloadFromS3(record.s3Key);

            // Set appropriate headers
            res.setHeader(
              "Content-Type",
              record.mimeType || "application/octet-stream"
            );
            res.setHeader(
              "Content-Disposition",
              `attachment; filename="${record.fileName}"`
            );

            // Stream file to response
            fileStream.pipe(res);

            await auditLog(
              req,
              "record_downloaded",
              "patient_records",
              recordId,
              {
                role: user.role,
                storageType: "s3",
              }
            );

            await patientHistoryLog(
              req,
              patientId,
              "record_downloaded",
              "Record downloaded",
              record.fileName,
              { recordId, storageType: "s3" }
            );
          } catch (s3Error) {
            console.error("Error downloading from S3:", s3Error);
            return res
              .status(500)
              .json({ message: "Failed to download file from S3" });
          }
        } else if (record.filePath) {
          // Download from local storage (backward compatibility)
          try {
            const filePath = path.resolve(record.filePath);

            // Security: Verify file exists and is within allowed directory
            const uploadsDir = path.join(process.cwd(), "uploads");
            if (!filePath.startsWith(uploadsDir)) {
              return res.status(403).json({ message: "Invalid file path" });
            }

            const fileBuffer = await fs.readFile(filePath);

            res.setHeader(
              "Content-Type",
              record.mimeType || "application/octet-stream"
            );
            res.setHeader(
              "Content-Disposition",
              `attachment; filename="${record.fileName}"`
            );
            res.setHeader("Content-Length", fileBuffer.length);

            res.send(fileBuffer);

            await auditLog(
              req,
              "record_downloaded",
              "patient_records",
              recordId,
              {
                role: user.role,
                storageType: "local",
              }
            );

            await patientHistoryLog(
              req,
              patientId,
              "record_downloaded",
              "Record downloaded",
              record.fileName,
              { recordId, storageType: "local" }
            );
          } catch (localError) {
            console.error("Error reading local file:", localError);
            return res.status(500).json({ message: "Failed to read file" });
          }
        } else {
          return res.status(404).json({ message: "File location not found" });
        }
      } catch (error) {
        console.error("Error downloading patient record:", error);
        res.status(500).json({ message: "Failed to download patient record" });
      }
    }
  );

  app.delete(
    "/api/patients/:patientId/records/:recordId",
    authGuard,
    async (req: any, res) => {
      try {
        const { patientId, recordId } = req.params;
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);

        if (!user) {
          return res.status(403).json({ message: "User not found" });
        }

        // Only admin can delete records
        if (user.role !== "admin") {
          await auditLog(
            req,
            "record_delete_denied",
            "patient_records",
            recordId,
            {
              role: user.role,
              reason: "insufficient_role",
            }
          );
          return res.status(403).json({
            message: "Only administrators can delete patient records",
          });
        }

        // Get record before deletion to check storage type
        const records = await storage.getPatientRecords(patientId);
        const record = records.find((r) => r.id === recordId);

        if (!record) {
          return res.status(404).json({ message: "Record not found" });
        }

        // Delete from S3 if stored there
        if (record.storageType === "s3" && record.s3Key) {
          try {
            await deleteFromS3(record.s3Key);
          } catch (s3Error) {
            console.error("Error deleting from S3:", s3Error);
            // Continue with database deletion even if S3 deletion fails
            // (orphaned S3 objects can be cleaned up later)
          }
        } else if (record.filePath) {
          // Delete from local storage (backward compatibility)
          try {
            const filePath = path.resolve(record.filePath);
            const uploadsDir = path.join(process.cwd(), "uploads");

            // Security: Only delete files within uploads directory
            if (filePath.startsWith(uploadsDir)) {
              await fs.unlink(filePath).catch((err) => {
                console.warn("Failed to delete local file:", err);
                // Continue with database deletion even if file deletion fails
              });
            }
          } catch (localError) {
            console.error("Error deleting local file:", localError);
            // Continue with database deletion
          }
        }

        // Delete record from database
        await storage.deletePatientRecord(recordId);

        await auditLog(req, "record_deleted", "patient_records", recordId, {
          role: user.role,
          patientId,
          storageType: record.storageType || "unknown",
        });

        await patientHistoryLog(
          req,
          patientId,
          "record_deleted",
          "Record deleted",
          record.fileName,
          { recordId, storageType: record.storageType || "unknown" }
        );

        res.json({ message: "Patient record deleted successfully" });
      } catch (error) {
        console.error("Error deleting patient record:", error);
        res.status(500).json({ message: "Failed to delete patient record" });
      }
    }
  );

  // Task routes
  app.get("/api/tasks", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const currentUserId = authenticatedUser.id;
      const currentUser = await storage.getUser(currentUserId);

      if (!currentUser) {
        return res.status(403).json({ message: "User not found" });
      }

      const { userId, patientId, page, limit } = req.query;

      // Parse pagination parameters with defaults
      const pageNum = parseInt(page as string) || 1;
      const limitNum = parseInt(limit as string) || 5;

      // Validate pagination parameters - minimum limit is 5
      const validLimit = Math.max(
        5,
        [5, 10, 50, 100].includes(limitNum) ? limitNum : 5
      );
      const validPage = pageNum > 0 ? pageNum : 1;

      // HIPAA compliance: only admins can query arbitrary user's tasks
      let filterUserId: string | undefined;
      let filterPatientId: string | undefined;

      if (userId && typeof userId === "string") {
        if (currentUser.role !== "admin" && userId !== currentUserId) {
          return res
            .status(403)
            .json({ message: "Access denied - can only view own tasks" });
        }
        filterUserId = userId;
      } else if (patientId && typeof patientId === "string") {
        // Only admins can query tasks by patient ID
        if (currentUser.role !== "admin") {
          return res
            .status(403)
            .json({ message: "Access denied - insufficient permissions" });
        }
        filterPatientId = patientId;
      } else {
        // Non-admins only see their own tasks, admins see all
        if (currentUser.role !== "admin") {
          filterUserId = currentUserId;
        }
      }

      // Use paginated method
      const result = await storage.getTasksPaginated(
        validPage,
        validLimit,
        filterUserId,
        filterPatientId,
        currentUser.role
      );

      // Return response in the format expected by frontend
      res.json({
        tasks: result.tasks,
        pagination: {
          page: validPage,
          limit: validLimit,
          total: result.total,
          totalPages: result.totalPages,
        },
      });
    } catch (error) {
      console.error("Error fetching tasks:", error);
      res.status(500).json({ message: "Failed to fetch tasks" });
    }
  });

  app.post("/api/tasks", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(403).json({ message: "User not found" });
      }

      const taskData = insertTaskSchema.parse({
        ...req.body,
        createdBy: userId,
      });

      // HIPAA compliance: Validate patient ownership for staff users
      if (taskData.patientId && user.role !== "admin") {
        const patient = await storage.getPatient(taskData.patientId);
        if (!patient) {
          return res.status(404).json({ message: "Patient not found" });
        }

        // Staff can only create tasks for patients they created
        if (patient.createdBy.id !== userId) {
          await auditLog(req, "task_create_denied", "task", "", {
            role: user.role,
            patientId: taskData.patientId,
            reason: "not_patient_creator",
          });
          return res.status(403).json({
            message:
              "Access denied - can only create tasks for patients you created",
          });
        }
      }

      const task = await storage.createTask(taskData);

      // Send notification to assigned user
      try {
        const assignedUser = await storage.getUser(taskData.assignedTo);
        if (assignedUser) {
          let patientName: string | undefined;
          if (taskData.patientId) {
            const patient = await storage.getPatient(taskData.patientId);
            if (patient) {
              patientName = `${patient.firstName} ${patient.lastName}`;
            }
          }

          await notificationService.sendTaskNotification(
            taskData.assignedTo,
            `${assignedUser.firstName} ${assignedUser.lastName}`,
            taskData.title,
            taskData.patientId || undefined,
            patientName
          );
        }
      } catch (notificationError) {
        // Log but don't fail the request if notification fails
        console.error("Failed to send task notification:", notificationError);
      }

      // HIPAA-safe audit log - no PHI in details
      await auditLog(req, "created", "task", task.id, {
        role: user.role,
        patientId: taskData.patientId || null,
        priority: taskData.priority,
        hasTitle: !!taskData.title,
        hasDescription: !!taskData.description,
      });

      res.status(201).json(task);
    } catch (error) {
      console.error("Error creating task:", error);
      res.status(400).json({
        message: "Failed to create task",
        error: (error as Error).message,
      });
    }
  });

  app.put("/api/tasks/:id", authGuard, async (req: any, res) => {
    try {
      const taskId = req.params.id;
      const userId = req.user.id;
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(403).json({ message: "User not found" });
      }

      // Get existing task to check ownership
      const existingTask = await storage.getTask(taskId);
      if (!existingTask) {
        return res.status(404).json({ message: "Task not found" });
      }

      // Authorization: Only admin, assignee, or creator can update task
      if (
        user.role !== "admin" &&
        existingTask.assignedTo !== userId &&
        existingTask.createdBy !== userId
      ) {
        await auditLog(req, "task_update_denied", "task", taskId, {
          role: user.role,
          reason: "not_assigned_or_creator",
        });
        return res.status(403).json({
          message:
            "Access denied - can only update tasks assigned to you or that you created",
        });
      }

      const taskData = insertTaskSchema.partial().parse(req.body);
      const task = await storage.updateTask(taskId, taskData);
      // HIPAA-safe audit log - no PHI in details
      await auditLog(req, "updated", "task", task.id, {
        role: user.role,
        fieldsUpdated: Object.keys(taskData),
        priority: taskData.priority,
        hasTitle: !!taskData.title,
        hasDescription: !!taskData.description,
      });

      res.json(task);
    } catch (error) {
      console.error("Error updating task:", error);
      res.status(400).json({
        message: "Failed to update task",
        error: (error as Error).message,
      });
    }
  });

  // Appointment routes
  app.get("/api/appointments", authGuard, async (req: any, res) => {
    try {
      const { patientId, providerId } = req.query;
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(403).json({ message: "User not found" });
      }

      let appointments;

      if (patientId && typeof patientId === "string") {
        appointments = await storage.getAppointmentsByPatient(patientId);
      } else if (providerId && typeof providerId === "string") {
        appointments = await storage.getAppointmentsByProvider(providerId);
      } else {
        appointments = await storage.getAppointments();
      }

      // HIPAA compliance: Filter appointments by patient ownership for staff
      if (user.role !== "admin") {
        // Get all unique patient IDs from appointments
        const patientIdsSet = new Set(appointments.map((apt) => apt.patientId));
        const patientIds = Array.from(patientIdsSet);

        // Get all patients to check ownership
        const patients = await Promise.all(
          patientIds.map((id) => storage.getPatient(id))
        );
        const ownedPatientIds = new Set(
          patients
            .filter((patient) => patient && patient.createdBy.id === userId)
            .map((patient) => patient!.id)
        );

        // Filter appointments to only include those for owned patients
        appointments = appointments.filter((apt) =>
          ownedPatientIds.has(apt.patientId)
        );
      }

      // Audit log the access
      await auditLog(req, "appointments_list_accessed", "appointments", "", {
        count: appointments.length,
        role: user.role,
        patientId: patientId || "all",
        providerId: providerId || "all",
      });

      res.json(appointments);
    } catch (error) {
      console.error("Error fetching appointments:", error);
      res.status(500).json({ message: "Failed to fetch appointments" });
    }
  });

  app.post("/api/appointments", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(403).json({ message: "User not found" });
      }

      // Role check for appointment creation
      if (user.role !== "admin" && user.role !== "staff") {
        await auditLog(req, "appointment_create_denied", "appointment", "", {
          role: user.role,
          reason: "insufficient_role",
        });
        return res
          .status(403)
          .json({ message: "Insufficient permissions to create appointments" });
      }

      const appointmentData = insertAppointmentSchema.parse({
        ...req.body,
        createdBy: userId,
      });

      // Check if patient can be scheduled (consent must be signed)
      const patient = await storage.getPatient(appointmentData.patientId);
      if (!patient) {
        return res.status(404).json({ message: "Patient not found" });
      }

      // Check if case is closed - only admin can create appointments for closed cases
      if (patient.status === "case_closed" && user.role !== "admin") {
        await auditLog(req, "appointment_create_denied", "appointments", "", {
          role: user.role,
          reason: "case_closed",
          status: patient.status,
        });
        return res.status(403).json({
          message:
            "Cannot create appointment - case is closed. Only admin can perform this action.",
        });
      }

      // HIPAA compliance: Staff can only schedule appointments for patients they created
      if (user.role !== "admin" && patient.createdBy.id !== userId) {
        await auditLog(req, "appointment_create_denied", "appointment", "", {
          role: user.role,
          patientId: appointmentData.patientId,
          reason: "not_patient_creator",
        });
        return res.status(403).json({
          message:
            "Access denied - can only create appointments for patients you created",
        });
      }

      if (
        patient.status !== "consent_signed" &&
        patient.status !== "schedulable"
      ) {
        return res.status(400).json({
          message: "Patient must have signed consent before scheduling",
        });
      }

      const appointment = await storage.createAppointment(appointmentData);

      // Update patient status to schedulable when appointment is scheduled
      if (
        patient.status === "consent_signed" ||
        patient.status === "schedulable"
      ) {
        await storage.updatePatient(patient.id, { status: "schedulable" });
      }

      // HIPAA-safe audit log - no PHI in details
      await auditLog(req, "created", "appointment", appointment.id, {
        role: user.role,
        patientId: appointmentData.patientId,
        hasScheduledAt: !!appointmentData.scheduledAt,
        hasNotes: !!appointmentData.notes,
        status: appointmentData.status,
      });

      // Send appointment confirmation email to patient
      if (patient.email && appointmentData.scheduledAt) {
        try {
          await sendAppointmentEmail({
            to: patient.email,
            patientName: `${patient.firstName} ${patient.lastName}`,
            scheduledAt: new Date(appointmentData.scheduledAt),
            duration: appointmentData.duration || 60,
            location: appointmentData.notes || null,
            isUpdate: false,
          });

          // Log email sent in patient history
          await patientHistoryLog(
            req,
            patient.id,
            "appointment_email_sent",
            "Appointment confirmation email sent",
            `Confirmation email sent to ${patient.email}`,
            {
              appointmentId: appointment.id,
              emailType: "confirmation",
            }
          );
        } catch (emailError) {
          // Log error but don't fail the appointment creation
          console.error("Error sending appointment email:", emailError);
          // Still log that we attempted to send email
          await patientHistoryLog(
            req,
            patient.id,
            "appointment_email_failed",
            "Appointment email failed to send",
            `Failed to send confirmation email to ${patient.email}`,
            {
              appointmentId: appointment.id,
              emailType: "confirmation",
              error: (emailError as Error).message,
            }
          );
        }
      }

      res.status(201).json(appointment);
    } catch (error) {
      console.error("Error creating appointment:", error);
      res.status(400).json({
        message: "Failed to create appointment",
        error: (error as Error).message,
      });
    }
  });

  // Update appointment (reschedule/status/notes) - admin/staff only
  app.put("/api/appointments/:id", authGuard, async (req: any, res) => {
    try {
      const appointmentId = req.params.id;
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);

      if (!user) {
        return res.status(403).json({ message: "User not found" });
      }

      if (user.role !== "admin" && user.role !== "staff") {
        await auditLog(
          req,
          "appointment_update_denied",
          "appointment",
          appointmentId,
          {
            role: user.role,
            reason: "insufficient_role",
          }
        );
        return res
          .status(403)
          .json({ message: "Insufficient permissions to update appointments" });
      }

      const existing = await storage.getAppointment(appointmentId);
      if (!existing) {
        return res.status(404).json({ message: "Appointment not found" });
      }

      const patient = await storage.getPatient(existing.patientId);
      if (!patient) {
        return res.status(404).json({ message: "Patient not found" });
      }

      // Staff can only update appointments for patients they created
      if (user.role !== "admin" && patient.createdBy.id !== userId) {
        await auditLog(
          req,
          "appointment_update_denied",
          "appointment",
          appointmentId,
          {
            role: user.role,
            patientId: existing.patientId,
            reason: "not_patient_creator",
          }
        );
        return res.status(403).json({
          message:
            "Access denied - can only update appointments for patients you created",
        });
      }

      const appointmentData = insertAppointmentSchema.partial().parse(req.body);

      const updated = await storage.updateAppointment(
        appointmentId,
        appointmentData
      );

      const scheduledAtChanged =
        appointmentData.scheduledAt !== undefined &&
        new Date(appointmentData.scheduledAt as any).getTime() !==
          new Date(existing.scheduledAt).getTime();

      const statusChanged =
        appointmentData.status !== undefined &&
        appointmentData.status !== (existing.status as any);

      await auditLog(
        req,
        scheduledAtChanged ? "appointment_rescheduled" : "updated",
        "appointment",
        appointmentId,
        {
          role: user.role,
          patientId: existing.patientId,
          fieldsUpdated: Object.keys(appointmentData),
          scheduledAtChanged,
          statusChanged,
          oldStatus: existing.status,
          newStatus: appointmentData.status,
        }
      );

      // Optional: if appointment status marked completed, log treatment completion intent (status workflow handled separately)
      if (statusChanged && appointmentData.status === "completed") {
        await auditLog(
          req,
          "appointment_completed",
          "appointment",
          appointmentId,
          {
            role: user.role,
            patientId: existing.patientId,
          }
        );
      }

      if (scheduledAtChanged) {
        await patientHistoryLog(
          req,
          existing.patientId,
          "appointment_rescheduled",
          "Appointment rescheduled",
          undefined,
          {
            appointmentId,
            oldScheduledAt: existing.scheduledAt,
            newScheduledAt: appointmentData.scheduledAt,
          }
        );

        // Send appointment update email to patient when time changes
        if (patient.email && appointmentData.scheduledAt) {
          try {
            await sendAppointmentEmail({
              to: patient.email,
              patientName: `${patient.firstName} ${patient.lastName}`,
              scheduledAt: new Date(appointmentData.scheduledAt as any),
              duration: updated.duration || 60,
              location: updated.notes || null,
              isUpdate: true,
              oldScheduledAt: new Date(existing.scheduledAt),
            });

            // Log email sent in patient history
            await patientHistoryLog(
              req,
              existing.patientId,
              "appointment_email_sent",
              "Appointment update email sent",
              `Update email sent to ${patient.email}`,
              {
                appointmentId,
                emailType: "update",
              }
            );
          } catch (emailError) {
            // Log error but don't fail the appointment update
            console.error(
              "Error sending appointment update email:",
              emailError
            );
            // Still log that we attempted to send email
            await patientHistoryLog(
              req,
              existing.patientId,
              "appointment_email_failed",
              "Appointment email failed to send",
              `Failed to send update email to ${patient.email}`,
              {
                appointmentId,
                emailType: "update",
                error: (emailError as Error).message,
              }
            );
          }
        }
      } else if (Object.keys(appointmentData).length > 0) {
        await patientHistoryLog(
          req,
          existing.patientId,
          "appointment_updated",
          "Appointment updated",
          undefined,
          { appointmentId, fieldsUpdated: Object.keys(appointmentData) }
        );
      }

      if (statusChanged && appointmentData.status === "completed") {
        await patientHistoryLog(
          req,
          existing.patientId,
          "appointment_completed",
          "Appointment completed",
          undefined,
          { appointmentId }
        );
      }

      res.json(updated);
    } catch (error) {
      console.error("Error updating appointment:", error);
      res.status(400).json({
        message: "Failed to update appointment",
        error: (error as Error).message,
      });
    }
  });

  // Mark treatment completed (staff/admin) - updates patient status and logs
  app.post(
    "/api/patients/:id/treatment-completed",
    authGuard,
    async (req: any, res) => {
      try {
        const patientId = req.params.id;
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);

        if (!user) return res.status(403).json({ message: "User not found" });
        if (user.role !== "admin" && user.role !== "staff") {
          await auditLog(
            req,
            "treatment_complete_denied",
            "patient",
            patientId,
            {
              role: user.role,
              reason: "insufficient_role",
            }
          );
          return res.status(403).json({ message: "Insufficient permissions" });
        }

        const patient = await storage.getPatient(patientId);
        if (!patient)
          return res.status(404).json({ message: "Patient not found" });
        if (!canAccessPatient(user, patient)) {
          await auditLog(
            req,
            "treatment_complete_denied",
            "patient",
            patientId,
            {
              role: user.role,
              reason: "insufficient_permissions",
            }
          );
          return res
            .status(403)
            .json({ message: "Access denied - insufficient permissions" });
        }

        const oldStatus = patient.status;
        const updatedPatient = await storage.updatePatient(patientId, {
          status: "treatment_completed" as any,
        });

        await auditLog(req, "treatment_completed", "patient", patientId, {
          role: user.role,
          completedBy: userId,
          oldStatus,
          newStatus: "treatment_completed",
        });

        await patientHistoryLog(
          req,
          patientId,
          "treatment_completed",
          "Treatment completed",
          undefined,
          { oldStatus, newStatus: "treatment_completed" }
        );

        res.json({
          message: "Treatment marked as completed",
          patient: updatedPatient,
        });
      } catch (error) {
        console.error("Error marking treatment completed:", error);
        res.status(500).json({ message: "Failed to mark treatment completed" });
      }
    }
  );

  // Get records forwarding status - checks if there are new records to forward and if admin should see buttons
  app.get(
    "/api/patients/:id/records/forward-status",
    authGuard,
    async (req: any, res) => {
      try {
        const patientId = req.params.id;
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);

        if (!user) return res.status(403).json({ message: "User not found" });

        const patient = await storage.getPatient(patientId);
        if (!patient)
          return res.status(404).json({ message: "Patient not found" });
        if (!canAccessPatient(user, patient)) {
          return res
            .status(403)
            .json({ message: "Access denied - insufficient permissions" });
        }

        const records = await storage.getPatientRecords(patientId);
        const historyLogs = await storage.getPatientHistoryLogs(patientId);

        // Find the most recent forward event
        const forwardLogs = historyLogs.filter(
          (log) => log.eventType === "records_forwarded"
        );
        const lastForwardLog = forwardLogs.length > 0 ? forwardLogs[0] : null;
        const lastForwardTimestamp = lastForwardLog?.createdAt
          ? new Date(lastForwardLog.createdAt)
          : null;

        // Find the most recent verify or correction event
        const verifyLogs = historyLogs.filter(
          (log) =>
            log.eventType === "records_verified" ||
            log.eventType === "records_sent_for_correction"
        );
        const lastVerifyOrCorrectionLog =
          verifyLogs.length > 0 ? verifyLogs[0] : null;
        const lastVerifyOrCorrectionTimestamp =
          lastVerifyOrCorrectionLog?.createdAt
            ? new Date(lastVerifyOrCorrectionLog.createdAt)
            : null;

        // Check if there are new records (created after last forward)
        const hasNewRecords =
          !lastForwardTimestamp ||
          records.some(
            (record) =>
              lastForwardTimestamp &&
              record.createdAt &&
              new Date(record.createdAt) > lastForwardTimestamp
          );

        // For admin: show buttons if status is records_forwarded AND
        // the last forward is after the last verify/correction (meaning there are pending records)
        const shouldShowAdminButtons =
          user.role === "admin" &&
          patient.status === "records_forwarded" &&
          lastForwardLog &&
          lastForwardLog.createdAt &&
          (!lastVerifyOrCorrectionTimestamp ||
            (lastVerifyOrCorrectionTimestamp &&
              new Date(lastForwardLog.createdAt as string | number | Date) >
                lastVerifyOrCorrectionTimestamp));

        res.json({
          hasNewRecords,
          shouldShowAdminButtons,
          lastForwardTimestamp: lastForwardTimestamp?.toISOString() || null,
          lastVerifyOrCorrectionTimestamp:
            lastVerifyOrCorrectionTimestamp?.toISOString() || null,
        });
      } catch (error) {
        console.error("Error checking records forward status:", error);
        res.status(500).json({ message: "Failed to check records status" });
      }
    }
  );

  // Forward records (admin/staff) - logs who records were forwarded to and updates patient status
  app.post(
    "/api/patients/:id/records/forward",
    authGuard,
    async (req: any, res) => {
      try {
        const patientId = req.params.id;
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);

        if (!user) return res.status(403).json({ message: "User not found" });
        if (user.role !== "admin" && user.role !== "staff") {
          await auditLog(req, "records_forward_denied", "patient", patientId, {
            role: user.role,
            reason: "insufficient_role",
          });
          return res.status(403).json({ message: "Insufficient permissions" });
        }

        const patient = await storage.getPatient(patientId);
        if (!patient)
          return res.status(404).json({ message: "Patient not found" });
        if (!canAccessPatient(user, patient)) {
          await auditLog(req, "records_forward_denied", "patient", patientId, {
            role: user.role,
            reason: "insufficient_permissions",
          });
          return res
            .status(403)
            .json({ message: "Access denied - insufficient permissions" });
        }

        const forwardToUserIds: string[] = Array.isArray(
          req.body?.forwardToUserIds
        )
          ? req.body.forwardToUserIds.filter(
              (id: any) => typeof id === "string"
            )
          : [];
        const forwardToAdmins: boolean = req.body?.forwardToAdmins === true;
        const note: string | undefined =
          typeof req.body?.note === "string" ? req.body.note.trim() : undefined;

        // Convenience: allow forwarding to admins without the client having to look up admin IDs
        // - Staff UI should set { forwardToAdmins: true }
        let effectiveForwardToUserIds = forwardToUserIds;
        if (effectiveForwardToUserIds.length === 0 && forwardToAdmins) {
          const allUsers = await storage.getUsers();
          const activeAdmins = allUsers.filter(
            (u) => u.role === "admin" && u.isActive
          );
          effectiveForwardToUserIds = activeAdmins.map((a) => a.id);
        }
        if (effectiveForwardToUserIds.length === 0) {
          return res
            .status(400)
            .json({ message: "forwardToUserIds is required" });
        }

        // Validate recipients exist and are active
        const recipients = await Promise.all(
          effectiveForwardToUserIds.map((id) => storage.getUser(id))
        );
        const invalidRecipient = recipients.find((u) => !u || !u.isActive);
        if (invalidRecipient) {
          return res.status(400).json({
            message: "One or more recipients are invalid or inactive",
          });
        }

        const oldStatus = patient.status;
        const updatedPatient = await storage.updatePatient(patientId, {
          status: "records_forwarded" as any,
        });

        await auditLog(req, "records_forwarded", "patient", patientId, {
          role: user.role,
          forwardedBy: userId,
          forwardToUserIds: effectiveForwardToUserIds,
          noteLength: note ? note.length : 0,
          oldStatus,
          newStatus: "records_forwarded",
        });

        // Store forward timestamp to track which records were forwarded
        const forwardTimestamp = new Date();
        await patientHistoryLog(
          req,
          patientId,
          "records_forwarded",
          "Records forwarded for verification",
          note,
          {
            oldStatus,
            newStatus: "records_forwarded",
            forwardToUserIds: effectiveForwardToUserIds,
            forwardedBy: userId,
            forwardTimestamp: forwardTimestamp.toISOString(),
          }
        );

        // Notify admins when staff forwards records
        if (user.role === "staff") {
          try {
            const staffName =
              [user.firstName, user.lastName]
                .filter(Boolean)
                .join(" ")
                .trim() ||
              user.email ||
              "Staff";
            const patientName =
              `${patient.firstName} ${patient.lastName}`.trim();
            const message = `${staffName} has forwarded records for ${patientName} for verification`;

            await Promise.all(
              effectiveForwardToUserIds.map((adminId) =>
                storage.createAlert({
                  type: "records_forwarded",
                  patientId,
                  userId: adminId,
                  message,
                  scheduledFor: new Date(),
                })
              )
            );
          } catch (notifyError) {
            // Don't fail forward if alert creation fails
            console.warn(
              "Failed to create admin alerts for record forwarding:",
              notifyError
            );
          }
        }

        res.json({ message: "Records forwarded", patient: updatedPatient });
      } catch (error) {
        console.error("Error forwarding records:", error);
        res.status(500).json({ message: "Failed to forward records" });
      }
    }
  );

  // Verify forwarded records (admin only) - sets status to records_forwarded after verification
  app.post(
    "/api/patients/:id/records/verify",
    authGuard,
    async (req: any, res) => {
      try {
        const patientId = req.params.id;
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);

        if (!user) return res.status(403).json({ message: "User not found" });
        if (user.role !== "admin") {
          await auditLog(req, "records_verify_denied", "patient", patientId, {
            role: user.role,
            reason: "insufficient_role",
          });
          return res.status(403).json({ message: "Insufficient permissions" });
        }

        const patient = await storage.getPatient(patientId);
        if (!patient)
          return res.status(404).json({ message: "Patient not found" });
        if (!canAccessPatient(user, patient)) {
          await auditLog(req, "records_verify_denied", "patient", patientId, {
            role: user.role,
            reason: "insufficient_permissions",
          });
          return res
            .status(403)
            .json({ message: "Access denied - insufficient permissions" });
        }

        const note: string | undefined =
          typeof req.body?.note === "string" ? req.body.note.trim() : undefined;

        const oldStatus = patient.status;
        // After verification, change status to records_verified
        const updatedPatient = await storage.updatePatient(patientId, {
          status: "records_verified" as any,
        });

        await auditLog(req, "records_verified", "patient", patientId, {
          role: user.role,
          verifiedBy: userId,
          oldStatus,
          newStatus: "records_verified",
          noteLength: note ? note.length : 0,
        });

        await patientHistoryLog(
          req,
          patientId,
          "records_verified",
          "Records verified",
          note,
          {
            oldStatus,
            newStatus: "records_verified",
            verifiedAt: new Date().toISOString(),
          }
        );

        // Notify staff who forwarded the records
        try {
          // Find who forwarded the records by checking patient history logs
          const historyLogs = await storage.getPatientHistoryLogs(patientId);
          const forwardLog = historyLogs.find(
            (log) =>
              log.eventType === "records_forwarded" &&
              log.metadata &&
              typeof log.metadata === "object" &&
              "forwardedBy" in log.metadata
          );

          if (forwardLog && forwardLog.metadata) {
            const metadata = forwardLog.metadata as any;
            const forwardedByUserId = metadata.forwardedBy;
            const forwardedByUser = await storage.getUser(forwardedByUserId);

            if (forwardedByUser && forwardedByUser.role === "staff") {
              const adminName =
                [user.firstName, user.lastName]
                  .filter(Boolean)
                  .join(" ")
                  .trim() ||
                user.email ||
                "Admin";
              const patientName =
                `${patient.firstName} ${patient.lastName}`.trim();
              const message = `${adminName} has verified the records for ${patientName}`;

              await storage.createAlert({
                type: "records_verified",
                patientId,
                userId: forwardedByUserId,
                message,
                scheduledFor: new Date(),
              });
            }
          }
        } catch (notifyError) {
          // Don't fail verify if alert creation fails
          console.warn(
            "Failed to create staff alert for record verification:",
            notifyError
          );
        }

        res.json({ message: "Records verified", patient: updatedPatient });
      } catch (error) {
        console.error("Error verifying records:", error);
        res.status(500).json({ message: "Failed to verify records" });
      }
    }
  );

  // Send records for correction (admin only) - sets status back to pending_records
  app.post(
    "/api/patients/:id/records/send-for-correction",
    authGuard,
    async (req: any, res) => {
      try {
        const patientId = req.params.id;
        const authenticatedUser = req.user as AuthenticatedUser;
        const userId = authenticatedUser.id;
        const user = await storage.getUser(userId);

        if (!user) return res.status(403).json({ message: "User not found" });
        if (user.role !== "admin") {
          await auditLog(
            req,
            "records_correction_denied",
            "patient",
            patientId,
            {
              role: user.role,
              reason: "insufficient_role",
            }
          );
          return res.status(403).json({ message: "Insufficient permissions" });
        }

        const patient = await storage.getPatient(patientId);
        if (!patient)
          return res.status(404).json({ message: "Patient not found" });
        if (!canAccessPatient(user, patient)) {
          await auditLog(
            req,
            "records_correction_denied",
            "patient",
            patientId,
            {
              role: user.role,
              reason: "insufficient_permissions",
            }
          );
          return res
            .status(403)
            .json({ message: "Access denied - insufficient permissions" });
        }

        const correctionMessage: string | undefined =
          typeof req.body?.note === "string" ? req.body.note.trim() : undefined;

        if (!correctionMessage || correctionMessage.length === 0) {
          return res.status(400).json({
            message: "Correction message is required",
          });
        }

        const oldStatus = patient.status;
        const updatedPatient = await storage.updatePatient(patientId, {
          status: "pending_records" as any,
        });

        // Create a legal note with the correction message
        try {
          await storage.createPatientNote({
            patientId,
            createdBy: userId,
            content: correctionMessage,
            noteType: "legal",
          });
        } catch (noteError) {
          console.warn(
            "Failed to create legal note for correction:",
            noteError
          );
          // Continue even if note creation fails
        }

        await auditLog(
          req,
          "records_sent_for_correction",
          "patient",
          patientId,
          {
            role: user.role,
            sentBy: userId,
            oldStatus,
            newStatus: "pending_records",
            noteLength: correctionMessage ? correctionMessage.length : 0,
          }
        );

        await patientHistoryLog(
          req,
          patientId,
          "records_sent_for_correction",
          "Records sent for correction",
          correctionMessage,
          {
            oldStatus,
            newStatus: "pending_records",
            correctedAt: new Date().toISOString(),
          }
        );

        // Notify staff who forwarded the records
        try {
          // Find who forwarded the records by checking patient history logs
          const historyLogs = await storage.getPatientHistoryLogs(patientId);
          const forwardLog = historyLogs.find(
            (log) =>
              log.eventType === "records_forwarded" &&
              log.metadata &&
              typeof log.metadata === "object" &&
              "forwardedBy" in log.metadata
          );

          if (forwardLog && forwardLog.metadata) {
            const metadata = forwardLog.metadata as any;
            const forwardedByUserId = metadata.forwardedBy;
            const forwardedByUser = await storage.getUser(forwardedByUserId);

            if (forwardedByUser && forwardedByUser.role === "staff") {
              const adminName =
                [user.firstName, user.lastName]
                  .filter(Boolean)
                  .join(" ")
                  .trim() ||
                user.email ||
                "Admin";
              const patientName =
                `${patient.firstName} ${patient.lastName}`.trim();
              const message = `${adminName} has sent records for ${patientName} back for correction${
                correctionMessage ? `: ${correctionMessage}` : ""
              }`;

              await storage.createAlert({
                type: "records_correction_needed",
                patientId,
                userId: forwardedByUserId,
                message,
                scheduledFor: new Date(),
              });
            }
          }
        } catch (notifyError) {
          // Don't fail if alert creation fails
          console.warn(
            "Failed to create staff alert for record correction:",
            notifyError
          );
        }

        res.json({
          message: "Records sent for correction",
          patient: updatedPatient,
        });
      } catch (error) {
        console.error("Error sending records for correction:", error);
        res
          .status(500)
          .json({ message: "Failed to send records for correction" });
      }
    }
  );

  // Close case (admin only) - sets status to case_closed
  app.post("/api/patients/:id/close-case", authGuard, async (req: any, res) => {
    try {
      const patientId = req.params.id;
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const user = await storage.getUser(userId);

      if (!user) return res.status(403).json({ message: "User not found" });
      if (user.role !== "admin") {
        await auditLog(req, "case_close_denied", "patient", patientId, {
          role: user.role,
          reason: "insufficient_role",
        });
        return res.status(403).json({ message: "Insufficient permissions" });
      }

      const patient = await storage.getPatient(patientId);
      if (!patient)
        return res.status(404).json({ message: "Patient not found" });
      if (!canAccessPatient(user, patient)) {
        await auditLog(req, "case_close_denied", "patient", patientId, {
          role: user.role,
          reason: "insufficient_permissions",
        });
        return res
          .status(403)
          .json({ message: "Access denied - insufficient permissions" });
      }

      // Only allow closing cases that are in records_verified status
      if (patient.status !== "records_verified") {
        return res.status(400).json({
          message: `Cannot close case - patient status is ${patient.status}. Only records_verified cases can be closed.`,
        });
      }

      const oldStatus = patient.status;
      const updatedPatient = await storage.updatePatient(patientId, {
        status: "case_closed" as any,
      });

      await auditLog(req, "case_closed", "patient", patientId, {
        role: user.role,
        closedBy: userId,
        oldStatus,
        newStatus: "case_closed",
      });

      await patientHistoryLog(
        req,
        patientId,
        "case_closed",
        "Case closed",
        undefined,
        { oldStatus, newStatus: "case_closed", closedBy: userId }
      );

      res.json({
        message: "Case closed successfully",
        patient: updatedPatient,
      });
    } catch (error) {
      console.error("Error closing case:", error);
      res.status(500).json({ message: "Failed to close case" });
    }
  });

  // Alert routes
  app.get("/api/alerts", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      // Only return user's own alerts for HIPAA compliance - least privilege principle
      const alerts = await storage.getAlerts(userId);

      res.json(alerts);
    } catch (error) {
      console.error("Error fetching alerts:", error);
      res.status(500).json({ message: "Failed to fetch alerts" });
    }
  });

  app.put("/api/alerts/:id/read", authGuard, async (req: any, res) => {
    try {
      const alertId = req.params.id;
      const userId = req.user.id;

      // Security check: only allow users to mark their own alerts as read
      const userAlerts = await storage.getAlerts(userId);
      const userAlert = userAlerts.find((alert) => alert.id === alertId);

      if (!userAlert) {
        return res
          .status(403)
          .json({ message: "Access denied - alert does not belong to user" });
      }

      await storage.markAlertAsRead(alertId);
      res.json({ message: "Alert marked as read" });
    } catch (error) {
      console.error("Error marking alert as read:", error);
      res.status(500).json({ message: "Failed to mark alert as read" });
    }
  });

  // Mark all alerts as read for the current user
  app.put("/api/alerts/mark-all-read", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;

      // Get all user's alerts and mark them as read
      const userAlerts = await storage.getAlerts(userId);
      const unreadAlerts = userAlerts.filter((alert) => !alert.isRead);

      // Mark each unread alert as read
      for (const alert of unreadAlerts) {
        await storage.markAlertAsRead(alert.id);
      }

      res.json({
        message: "All alerts marked as read",
        markedCount: unreadAlerts.length,
      });
    } catch (error) {
      console.error("Error marking all alerts as read:", error);
      res.status(500).json({ message: "Failed to mark all alerts as read" });
    }
  });

  // Get unread alert count for the current user
  app.get("/api/alerts/unread-count", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const userId = authenticatedUser.id;
      const alerts = await storage.getAlerts(userId);
      const unreadCount = alerts.filter((alert) => !alert.isRead).length;
      res.json({ unreadCount });
    } catch (error) {
      console.error("Error fetching unread count:", error);
      res.status(500).json({ message: "Failed to fetch unread count" });
    }
  });

  // Audit log routes
  app.get("/api/audit-logs", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const user = await storage.getUser(authenticatedUser.id);

      // Only admins can view audit logs
      if (user?.role !== "admin") {
        return res.status(403).json({ message: "Insufficient permissions" });
      }

      const { patientId } = req.query;
      const auditLogs = await storage.getAuditLogs(
        patientId && typeof patientId === "string" ? patientId : undefined
      );

      res.json(auditLogs);
    } catch (error) {
      console.error("Error fetching audit logs:", error);
      res.status(500).json({ message: "Failed to fetch audit logs" });
    }
  });

  // Patient history (product timeline) - Admin only
  app.get("/api/patients/:id/history", authGuard, async (req: any, res) => {
    try {
      const authenticatedUser = req.user as AuthenticatedUser;
      const user = await storage.getUser(authenticatedUser.id);

      if (user?.role !== "admin") {
        return res.status(403).json({ message: "Insufficient permissions" });
      }

      const patientId = req.params.id;
      const logs = await storage.getPatientHistoryLogs(patientId);
      res.json(logs);
    } catch (error) {
      console.error("Error fetching patient history logs:", error);
      res.status(500).json({ message: "Failed to fetch patient history logs" });
    }
  });

  // DocuSign webhook endpoint - NO AUTH (DocuSign calls this)
  // Use text parser for XML body
  // app.post('/api/docusign/webhook', async (req: any, res) => {
  //   try {
  //     console.log('📬 [DocuSign Webhook] Received webhook request');

  //     // Get raw body as text (assuming XML)
  //     let xmlData = '';

  //     if (typeof req.body === 'string') {
  //       xmlData = req.body;
  //     } else if (Buffer.isBuffer(req.body)) {
  //       xmlData = req.body.toString();
  //     } else {
  //       // If body is already parsed as JSON, try to get it from raw
  //       xmlData = JSON.stringify(req.body);
  //     }

  //     console.log('📬 [DocuSign Webhook] Raw data:', xmlData.substring(0, 500)); // Log first 500 chars

  //     // Optional HMAC signature verification for security
  //     const hmacSecret = process.env.DOCUSIGN_HMAC_KEY || '';
  //     if (hmacSecret) {
  //       const signature = req.headers['x-docusign-signature-1'];

  //       if (!signature) {
  //         console.error('📬 [DocuSign Webhook] HMAC signature missing');
  //         return res.status(401).json({ message: 'HMAC signature required' });
  //       }

  //       // Compute expected HMAC signature
  //       const crypto = await import('crypto');
  //       const computedSignature = crypto
  //         .createHmac('sha256', hmacSecret)
  //         .update(xmlData)
  //         .digest('base64');

  //       // Compare signatures (timing-safe comparison)
  //       if (!crypto.timingSafeEqual(
  //         Buffer.from(signature as string),
  //         Buffer.from(computedSignature)
  //       )) {
  //         console.error('📬 [DocuSign Webhook] HMAC signature verification failed');
  //         return res.status(401).json({ message: 'Invalid HMAC signature' });
  //       }

  //       console.log('✅ [DocuSign Webhook] HMAC signature verified');
  //     } else {
  //       console.warn('⚠️  [DocuSign Webhook] HMAC verification disabled (no DOCUSIGN_HMAC_KEY set)');
  //     }

  //     // Parse XML body
  //     const { XMLParser } = await import('fast-xml-parser');
  //     const parser = new XMLParser();
  //     const parsed = parser.parse(xmlData);

  //     // Extract envelope data from DocuSign XML structure
  //     const envelopeInfo = parsed?.DocuSignEnvelopeInformation?.EnvelopeStatus;

  //     if (!envelopeInfo) {
  //       console.error('📬 [DocuSign Webhook] Invalid XML structure');
  //       return res.status(400).json({ message: 'Invalid XML structure' });
  //     }

  //     const envelopeId = envelopeInfo.EnvelopeID;
  //     const status = envelopeInfo.Status?.toLowerCase();
  //     const completedTime = envelopeInfo.Completed;

  //     console.log(`📬 [DocuSign Webhook] Envelope ${envelopeId} status: ${status}`);

  //     // Find patient by envelope ID
  //     const patients = await storage.getPatients();
  //     const patient = patients.find((p: any) => p.docusignEnvelopeId === envelopeId);

  //     if (!patient) {
  //       console.warn(`📬 [DocuSign Webhook] No patient found for envelope ${envelopeId}`);
  //       // Still return 200 to prevent DocuSign retries
  //       return res.status(200).json({ message: 'Envelope not tracked' });
  //     }

  //     console.log(`📬 [DocuSign Webhook] Found patient: ${patient.firstName} ${patient.lastName} (${patient.id})`);

  //     // Update patient based on status
  //     let updateData: any = {};

  //     switch (status) {
  //       case 'completed':
  //         updateData = {
  //           status: 'consent_received' as const,
  //           consentSignedAt: completedTime ? new Date(completedTime) : new Date(),
  //         };
  //         console.log(`📬 [DocuSign Webhook] Marking patient as consent_received`);

  //         // Create audit log for consent completion
  //         await storage.createAuditLog({
  //           userId: 'system', // System action
  //           action: 'update',
  //           resourceType: 'patient',
  //           resourceId: patient.id,
  //           patientId: patient.id,
  //           details: {
  //             field: 'status',
  //             oldValue: patient.status,
  //             newValue: 'consent_received',
  //             source: 'docusign_webhook',
  //             envelopeId: envelopeId
  //           }
  //         });
  //         break;

  //       case 'declined':
  //         updateData = {
  //           status: 'pending_consent' as const,
  //         };
  //         console.log(`📬 [DocuSign Webhook] Patient declined consent`);

  //         await storage.createAuditLog({
  //           userId: 'system',
  //           action: 'update',
  //           resourceType: 'patient',
  //           resourceId: patient.id,
  //           patientId: patient.id,
  //           details: {
  //             field: 'status',
  //             oldValue: patient.status,
  //             newValue: 'pending_consent',
  //             source: 'docusign_webhook',
  //             reason: 'declined',
  //             envelopeId: envelopeId
  //           }
  //         });
  //         break;

  //       case 'voided':
  //         updateData = {
  //           status: 'pending_consent' as const,
  //         };
  //         console.log(`📬 [DocuSign Webhook] Envelope voided`);

  //         await storage.createAuditLog({
  //           userId: 'system',
  //           action: 'update',
  //           resourceType: 'patient',
  //           resourceId: patient.id,
  //           patientId: patient.id,
  //           details: {
  //             field: 'status',
  //             oldValue: patient.status,
  //             newValue: 'pending_consent',
  //             source: 'docusign_webhook',
  //             reason: 'voided',
  //             envelopeId: envelopeId
  //           }
  //         });
  //         break;

  //       default:
  //         console.log(`📬 [DocuSign Webhook] Status ${status} - no action needed`);
  //         // Return 200 for intermediate statuses (sent, delivered, etc.)
  //         return res.status(200).json({ message: 'Status noted' });
  //     }

  //     // Update patient if we have changes
  //     if (Object.keys(updateData).length > 0) {
  //       await storage.updatePatient(patient.id, updateData);
  //       console.log(`📬 [DocuSign Webhook] Patient updated successfully`);
  //     }

  //     // Return 200 OK quickly (DocuSign expects fast response)
  //     res.status(200).json({
  //       message: 'Webhook processed successfully',
  //       envelopeId,
  //       status
  //     });

  //   } catch (error) {
  //     console.error('📬 [DocuSign Webhook] Error processing webhook:', error);
  //     // Still return 200 to prevent DocuSign from retrying on our errors
  //     res.status(200).json({ message: 'Error processed' });
  //   }
  // });

  // Start the alert service
  alertService.start();

  const httpServer = createServer(app);
  return httpServer;
}
