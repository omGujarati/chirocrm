import { sql } from "drizzle-orm";
import { relations } from "drizzle-orm";
import {
  index,
  jsonb,
  pgTable,
  timestamp,
  varchar,
  text,
  integer,
  boolean,
  pgEnum,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Session storage table (required for Replit Auth)
export const sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull(),
  },
  (table) => [index("IDX_session_expire").on(table.expire)]
);

// User roles enum
export const userRoleEnum = pgEnum("user_role", ["admin", "staff", "attorney"]);

// Account verification status enum
export const accountVerificationStatusEnum = pgEnum(
  "account_verification_status",
  ["pending_verification", "verified", "rejected"]
);

// Patient status enum
export const patientStatusEnum = pgEnum("patient_status", [
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
]);

// Task status enum
export const taskStatusEnum = pgEnum("task_status", [
  "pending",
  "in_progress",
  "completed",
  "cancelled",
]);

// Task priority enum
export const taskPriorityEnum = pgEnum("task_priority", [
  "low",
  "normal",
  "high",
  "urgent",
]);

// Users table
export const users = pgTable("users", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  email: varchar("email").unique().notNull(),
  passwordHash: varchar("password_hash"),
  firstName: varchar("first_name"),
  lastName: varchar("last_name"),
  profileImageUrl: varchar("profile_image_url"),
  role: userRoleEnum("role").notNull().default("staff"),
  isActive: boolean("is_active").notNull().default(true),
  mustChangePassword: boolean("must_change_password").notNull().default(false),
  verificationStatus: accountVerificationStatusEnum("verification_status"),
  rejectionReason: text("rejection_reason"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Temporary OTP table for password reset
export const tempOtps = pgTable(
  "temp_otps",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    email: varchar("email").notNull(),
    otpHash: varchar("otp_hash").notNull(),
    createdAt: timestamp("created_at").defaultNow().notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    consumedAt: timestamp("consumed_at"),
  },
  (table) => [
    index("IDX_temp_otps_email_created_at").on(table.email, table.createdAt),
    index("IDX_temp_otps_email_expires_at").on(table.email, table.expiresAt),
  ]
);

// Patients table
export const patients = pgTable("patients", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  firstName: varchar("first_name").notNull(),
  lastName: varchar("last_name").notNull(),
  email: varchar("email").notNull().unique(),
  phone: varchar("phone"),
  dateOfBirth: timestamp("date_of_birth"),
  dateOfInjury: timestamp("date_of_injury"),
  address: text("address"),
  status: patientStatusEnum("status").notNull().default("pending_consent"),
  consentFormUrl: varchar("consent_form_url"),
  consentSignedAt: timestamp("consent_signed_at"),
  docusignEnvelopeId: varchar("docusign_envelope_id"),
  consentLanguage: varchar("consent_language"), // 'en' or 'es' for English or Spanish
  notes: text("notes"),
  assignedAttorney: varchar("assigned_attorney").references(() => users.id),
  // Initial consultation scheduling fields
  consultationDate: timestamp("consultation_date"),
  consultationTime: varchar("consultation_time"), // Store as "HH:MM" format
  consultationLocation: text("consultation_location"),
  // Drop functionality fields
  dropReason: text("drop_reason"),
  droppedBy: varchar("dropped_by").references(() => users.id),
  droppedAt: timestamp("dropped_at"),
  createdBy: varchar("created_by")
    .notNull()
    .references(() => users.id),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Tasks table
export const tasks = pgTable("tasks", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  title: varchar("title").notNull(),
  description: text("description"),
  patientId: varchar("patient_id").references(() => patients.id),
  assignedTo: varchar("assigned_to")
    .notNull()
    .references(() => users.id),
  createdBy: varchar("created_by")
    .notNull()
    .references(() => users.id),
  status: taskStatusEnum("status").notNull().default("pending"),
  priority: taskPriorityEnum("priority").notNull().default("normal"),
  dueDate: timestamp("due_date"),
  completedAt: timestamp("completed_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Appointments table
export const appointments = pgTable("appointments", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  patientId: varchar("patient_id")
    .notNull()
    .references(() => patients.id),
  providerId: varchar("provider_id")
    .notNull()
    .references(() => users.id),
  scheduledAt: timestamp("scheduled_at").notNull(),
  duration: integer("duration").notNull().default(60), // minutes
  status: varchar("status").notNull().default("scheduled"), // scheduled, completed, cancelled, no_show
  notes: text("notes"),
  createdBy: varchar("created_by")
    .notNull()
    .references(() => users.id),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Patient records table for file uploads
export const patientRecords = pgTable("patient_records", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  patientId: varchar("patient_id")
    .notNull()
    .references(() => patients.id),
  fileName: varchar("file_name").notNull(),
  filePath: varchar("file_path"), // Legacy field - kept for backward compatibility with existing local files
  fileSize: integer("file_size"), // bytes
  mimeType: varchar("mime_type"),
  description: text("description"),
  uploadedBy: varchar("uploaded_by")
    .notNull()
    .references(() => users.id),
  s3Key: varchar("s3_key"), // S3 object key (folder path + filename) - bucket name comes from env var
  storageType: varchar("storage_type").notNull().default("local"), // 'local' or 's3' - for migration support
  createdAt: timestamp("created_at").defaultNow(),
});

// Audit logs table for HIPAA compliance
export const auditLogs = pgTable("audit_logs", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  userId: varchar("user_id")
    .notNull()
    .references(() => users.id),
  patientId: varchar("patient_id").references(() => patients.id),
  action: varchar("action").notNull(), // created, updated, deleted, viewed, etc.
  resourceType: varchar("resource_type").notNull(), // patient, task, appointment, etc.
  resourceId: varchar("resource_id").notNull(),
  details: jsonb("details"), // Store additional context
  ipAddress: varchar("ip_address"),
  userAgent: varchar("user_agent"),
  createdAt: timestamp("created_at").defaultNow(),
});

// Patient history logs table (product-facing timeline inside Patient Details)
// Stores patient-wise events (created, status changes, docusign events, notes changes, record actions, etc.)
export const patientHistoryLogs = pgTable(
  "patient_history_logs",
  {
    id: varchar("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    patientId: varchar("patient_id")
      .notNull()
      .references(() => patients.id),
    actorUserId: varchar("actor_user_id").references(() => users.id), // nullable for system/webhook events if needed
    eventType: varchar("event_type").notNull(), // patient_created, status_changed, consent_sent, consent_signed, note_added, record_uploaded, etc.
    title: varchar("title").notNull(), // short label for UI
    message: text("message"), // human-readable description (optional)
    metadata: jsonb("metadata"), // structured context (ids, old/new status, envelopeId, etc.)
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("IDX_patient_history_patient_created_at").on(
      table.patientId,
      table.createdAt
    ),
    index("IDX_patient_history_event_type").on(table.eventType),
  ]
);

// Alerts table for automated notifications
export const alerts = pgTable("alerts", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  type: varchar("type").notNull(), // consent_24h, consent_48h, appointment_reminder, etc.
  patientId: varchar("patient_id")
    .notNull()
    .references(() => patients.id),
  userId: varchar("user_id").references(() => users.id), // who should receive the alert
  message: text("message").notNull(),
  isRead: boolean("is_read").notNull().default(false),
  emailSent: boolean("email_sent").notNull().default(false),
  scheduledFor: timestamp("scheduled_for"),
  sentAt: timestamp("sent_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

// Patient notes table for timestamped case updates
export const patientNotes = pgTable("patient_notes", {
  id: varchar("id")
    .primaryKey()
    .default(sql`gen_random_uuid()`),
  patientId: varchar("patient_id")
    .notNull()
    .references(() => patients.id),
  createdBy: varchar("created_by")
    .notNull()
    .references(() => users.id),
  content: text("content").notNull(),
  noteType: varchar("note_type").notNull().default("general"), // general, appointment, status_update, missed_appointment, etc.
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Relations
export const usersRelations = relations(users, ({ many }) => ({
  createdPatients: many(patients, { relationName: "PatientCreatedBy" }),
  assignedPatients: many(patients, { relationName: "PatientAssignedAttorney" }),
  assignedTasks: many(tasks, { relationName: "TaskAssignedTo" }),
  createdTasks: many(tasks, { relationName: "TaskCreatedBy" }),
  appointments: many(appointments, { relationName: "AppointmentProvider" }),
  createdAppointments: many(appointments, {
    relationName: "AppointmentCreatedBy",
  }),
  auditLogs: many(auditLogs),
  patientHistoryLogs: many(patientHistoryLogs),
  alerts: many(alerts),
  createdPatientNotes: many(patientNotes, {
    relationName: "PatientNoteCreatedBy",
  }),
  uploadedPatientRecords: many(patientRecords, {
    relationName: "PatientRecordUploadedBy",
  }),
}));

export const patientsRelations = relations(patients, ({ one, many }) => ({
  createdBy: one(users, {
    fields: [patients.createdBy],
    references: [users.id],
    relationName: "PatientCreatedBy",
  }),
  assignedAttorney: one(users, {
    fields: [patients.assignedAttorney],
    references: [users.id],
    relationName: "PatientAssignedAttorney",
  }),
  tasks: many(tasks),
  appointments: many(appointments),
  auditLogs: many(auditLogs),
  patientHistoryLogs: many(patientHistoryLogs),
  alerts: many(alerts),
  patientNotes: many(patientNotes),
  patientRecords: many(patientRecords),
}));

export const tasksRelations = relations(tasks, ({ one }) => ({
  patient: one(patients, {
    fields: [tasks.patientId],
    references: [patients.id],
  }),
  assignedTo: one(users, {
    fields: [tasks.assignedTo],
    references: [users.id],
    relationName: "TaskAssignedTo",
  }),
  createdBy: one(users, {
    fields: [tasks.createdBy],
    references: [users.id],
    relationName: "TaskCreatedBy",
  }),
}));

export const appointmentsRelations = relations(appointments, ({ one }) => ({
  patient: one(patients, {
    fields: [appointments.patientId],
    references: [patients.id],
  }),
  provider: one(users, {
    fields: [appointments.providerId],
    references: [users.id],
    relationName: "AppointmentProvider",
  }),
  createdBy: one(users, {
    fields: [appointments.createdBy],
    references: [users.id],
    relationName: "AppointmentCreatedBy",
  }),
}));

export const auditLogsRelations = relations(auditLogs, ({ one }) => ({
  user: one(users, {
    fields: [auditLogs.userId],
    references: [users.id],
  }),
  patient: one(patients, {
    fields: [auditLogs.patientId],
    references: [patients.id],
  }),
}));

export const patientHistoryLogsRelations = relations(
  patientHistoryLogs,
  ({ one }) => ({
    actor: one(users, {
      fields: [patientHistoryLogs.actorUserId],
      references: [users.id],
    }),
    patient: one(patients, {
      fields: [patientHistoryLogs.patientId],
      references: [patients.id],
    }),
  })
);

export const alertsRelations = relations(alerts, ({ one }) => ({
  patient: one(patients, {
    fields: [alerts.patientId],
    references: [patients.id],
  }),
  user: one(users, {
    fields: [alerts.userId],
    references: [users.id],
  }),
}));

export const patientNotesRelations = relations(patientNotes, ({ one }) => ({
  patient: one(patients, {
    fields: [patientNotes.patientId],
    references: [patients.id],
  }),
  createdBy: one(users, {
    fields: [patientNotes.createdBy],
    references: [users.id],
    relationName: "PatientNoteCreatedBy",
  }),
}));

export const patientRecordsRelations = relations(patientRecords, ({ one }) => ({
  patient: one(patients, {
    fields: [patientRecords.patientId],
    references: [patients.id],
  }),
  uploadedBy: one(users, {
    fields: [patientRecords.uploadedBy],
    references: [users.id],
    relationName: "PatientRecordUploadedBy",
  }),
}));

// Insert schemas
export const insertUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertUserWithPasswordSchema = insertUserSchema.extend({
  password: z.string().min(8, "Password must be at least 8 characters"),
});

// Attorney registration schema (simple - just name and email)
export const attorneyRegistrationSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(8, "Password must be at least 8 characters"),
  firstName: z.string().min(1, "First name is required"),
  lastName: z.string().min(1, "Last name is required"),
});

export const insertPatientSchema = createInsertSchema(patients)
  .omit({
    id: true,
    createdAt: true,
    updatedAt: true,
  })
  .extend({
    dateOfBirth: z.coerce.date().optional().nullable(),
    dateOfInjury: z.coerce.date().optional().nullable(),
  });

export const insertTaskSchema = createInsertSchema(tasks)
  .omit({
    id: true,
    createdAt: true,
    updatedAt: true,
  })
  .extend({
    dueDate: z.coerce.date().optional().nullable(),
    completedAt: z.coerce.date().optional().nullable(),
  });

export const insertAppointmentSchema = createInsertSchema(appointments).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertAuditLogSchema = createInsertSchema(auditLogs).omit({
  id: true,
  createdAt: true,
});

export const insertPatientHistoryLogSchema = createInsertSchema(
  patientHistoryLogs
).omit({
  id: true,
  createdAt: true,
});

export const insertAlertSchema = createInsertSchema(alerts).omit({
  id: true,
  createdAt: true,
});

export const insertPatientNoteSchema = createInsertSchema(patientNotes).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertPatientRecordSchema = createInsertSchema(
  patientRecords
).omit({
  id: true,
  createdAt: true,
});

// Upsert schema for auth
export const upsertUserSchema = createInsertSchema(users).pick({
  id: true,
  email: true,
  passwordHash: true,
  firstName: true,
  lastName: true,
  profileImageUrl: true,
  role: true,
  isActive: true, // Include isActive for security checks
  mustChangePassword: true, // Include for password change enforcement
  verificationStatus: true, // Include for attorney verification
  rejectionReason: true, // Include for rejection reason
});

// Types
export type User = typeof users.$inferSelect;
export type UpsertUser = z.infer<typeof upsertUserSchema>;
export type InsertUser = z.infer<typeof insertUserSchema>;
export type Patient = typeof patients.$inferSelect;
export type InsertPatient = z.infer<typeof insertPatientSchema>;
export type Task = typeof tasks.$inferSelect;
export type InsertTask = z.infer<typeof insertTaskSchema>;
export type Appointment = typeof appointments.$inferSelect;
export type InsertAppointment = z.infer<typeof insertAppointmentSchema>;
export type AuditLog = typeof auditLogs.$inferSelect;
export type InsertAuditLog = z.infer<typeof insertAuditLogSchema>;
export type PatientHistoryLog = typeof patientHistoryLogs.$inferSelect;
export type InsertPatientHistoryLog = z.infer<
  typeof insertPatientHistoryLogSchema
>;
export type Alert = typeof alerts.$inferSelect;
export type InsertAlert = z.infer<typeof insertAlertSchema>;
export type PatientNote = typeof patientNotes.$inferSelect;
export type InsertPatientNote = z.infer<typeof insertPatientNoteSchema>;
export type PatientRecord = typeof patientRecords.$inferSelect;
export type InsertPatientRecord = z.infer<typeof insertPatientRecordSchema>;

// Patient with relations type
export type PatientWithCreator = Omit<
  Patient,
  "createdBy" | "assignedAttorney"
> & {
  createdBy: User;
  assignedAttorney?: User;
};

// Task with relations type
export type TaskWithRelations = Omit<
  Task,
  "patient" | "assignedTo" | "createdBy"
> & {
  patient?: Patient;
  assignedTo: User;
  createdBy: User;
};
