import {
  users,
  patients,
  tasks,
  appointments,
  auditLogs,
  alerts,
  patientNotes,
  patientRecords,
  type User,
  type UpsertUser,
  type Patient,
  type InsertPatient,
  type PatientWithCreator,
  type Task,
  type InsertTask,
  type TaskWithRelations,
  type Appointment,
  type InsertAppointment,
  type AuditLog,
  type InsertAuditLog,
  type Alert,
  type InsertAlert,
  type PatientNote,
  type InsertPatientNote,
  type PatientRecord,
  type InsertPatientRecord,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and, or, count, sql } from "drizzle-orm";

export interface IStorage {
  // User operations (required for Replit Auth)
  getUser(id: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  getUsers(): Promise<User[]>;
  getUsersPaginated(
    page: number,
    limit: number
  ): Promise<{ users: User[]; total: number; totalPages: number }>;
  upsertUser(user: UpsertUser): Promise<User>;
  updateUser(id: string, updates: Partial<UpsertUser>): Promise<User>;
  updateUserStatus(id: string, isActive: boolean): Promise<User>;
  deleteUser(id: string): Promise<void>;

  // Patient operations
  getPatients(): Promise<PatientWithCreator[]>;
  getPatientsPaginated(
    page: number,
    limit: number,
    status?: string,
    userId?: string,
    userRole?: string
  ): Promise<{
    patients: PatientWithCreator[];
    total: number;
    totalPages: number;
  }>;
  getPatient(id: string): Promise<PatientWithCreator | undefined>;
  createPatient(patient: InsertPatient): Promise<Patient>;
  updatePatient(id: string, patient: Partial<InsertPatient>): Promise<Patient>;
  deletePatient(id: string): Promise<void>;
  getPatientsByStatus(status: string): Promise<PatientWithCreator[]>;
  getPatientsByAssignedAttorney(
    attorneyId: string
  ): Promise<PatientWithCreator[]>;

  // Task operations
  getTasks(): Promise<TaskWithRelations[]>;
  getTasksPaginated(
    page: number,
    limit: number,
    userId?: string,
    patientId?: string,
    userRole?: string
  ): Promise<{ tasks: TaskWithRelations[]; total: number; totalPages: number }>;
  getTask(id: string): Promise<TaskWithRelations | undefined>;
  createTask(task: InsertTask): Promise<Task>;
  updateTask(id: string, task: Partial<InsertTask>): Promise<Task>;
  deleteTask(id: string): Promise<void>;
  getTasksByUser(userId: string): Promise<TaskWithRelations[]>;
  getTasksByPatient(patientId: string): Promise<TaskWithRelations[]>;

  // Appointment operations
  getAppointments(): Promise<Appointment[]>;
  getAppointment(id: string): Promise<Appointment | undefined>;
  createAppointment(appointment: InsertAppointment): Promise<Appointment>;
  updateAppointment(
    id: string,
    appointment: Partial<InsertAppointment>
  ): Promise<Appointment>;
  deleteAppointment(id: string): Promise<void>;
  getAppointmentsByPatient(patientId: string): Promise<Appointment[]>;
  getAppointmentsByProvider(providerId: string): Promise<Appointment[]>;

  // Audit log operations
  createAuditLog(auditLog: InsertAuditLog): Promise<AuditLog>;
  getAuditLogs(patientId?: string): Promise<AuditLog[]>;

  // Alert operations
  getAlerts(userId?: string): Promise<Alert[]>;
  getSystemScheduledAlerts(): Promise<Alert[]>;
  createAlert(alert: InsertAlert): Promise<Alert>;
  markAlertAsRead(id: string): Promise<void>;
  markAlertEmailSent(id: string): Promise<void>;

  // Patient notes operations
  getPatientNotes(patientId: string): Promise<PatientNote[]>;
  createPatientNote(note: InsertPatientNote): Promise<PatientNote>;
  updatePatientNote(
    id: string,
    note: Partial<InsertPatientNote>
  ): Promise<PatientNote>;
  deletePatientNote(id: string): Promise<void>;

  // Patient drop operations
  dropPatient(
    patientId: string,
    dropReason: string,
    droppedBy: string
  ): Promise<Patient>;

  // Patient records operations
  getPatientRecords(patientId: string): Promise<PatientRecord[]>;
  createPatientRecord(record: InsertPatientRecord): Promise<PatientRecord>;
  deletePatientRecord(id: string): Promise<void>;

  // Dashboard stats
  getDashboardStats(): Promise<{
    totalPatients: number;
    pendingConsent: number;
    consentSigned: number;
    schedulable: number;
  }>;
}

export class DatabaseStorage implements IStorage {
  // User operations
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user;
  }

  async getUsers(): Promise<User[]> {
    return await db.select().from(users).orderBy(desc(users.createdAt));
  }

  async getUsersPaginated(
    page: number,
    limit: number
  ): Promise<{ users: User[]; total: number; totalPages: number }> {
    const offset = (page - 1) * limit;

    // Get total count
    const [{ count: totalCount }] = await db
      .select({ count: count() })
      .from(users);
    const total = Number(totalCount);

    // Get paginated users
    const paginatedUsers = await db
      .select()
      .from(users)
      .orderBy(desc(users.createdAt))
      .limit(limit)
      .offset(offset);

    const totalPages = Math.ceil(total / limit);

    return {
      users: paginatedUsers,
      total,
      totalPages,
    };
  }

  async upsertUser(userData: UpsertUser): Promise<User> {
    // First try to find user by OIDC subject (primary identifier)
    const existingById = await db
      .select()
      .from(users)
      .where(eq(users.id, userData.id!))
      .limit(1);

    if (existingById.length > 0) {
      // Update existing user by ID (preserve primary key and existing role)
      const [user] = await db
        .update(users)
        .set({
          email: userData.email,
          firstName: userData.firstName,
          lastName: userData.lastName,
          profileImageUrl: userData.profileImageUrl,
          // Preserve existing role - don't overwrite it from OIDC claims
          updatedAt: new Date(),
        })
        .where(eq(users.id, userData.id!))
        .returning();
      return user;
    }

    // Check if email exists with different ID (potential conflict)
    const existingByEmail = await db
      .select()
      .from(users)
      .where(eq(users.email, userData.email!))
      .limit(1);

    if (existingByEmail.length > 0) {
      // For admin users, ensure they have admin role but DON'T change ID (breaks foreign keys)
      if (
        userData.email?.includes("@chirocare.com") ||
        userData.email?.includes("admin")
      ) {
        // Update user info but preserve existing ID to avoid foreign key violations
        const [user] = await db
          .update(users)
          .set({
            // DON'T update ID - it breaks foreign key constraints with audit_logs
            firstName: userData.firstName,
            lastName: userData.lastName,
            profileImageUrl: userData.profileImageUrl,
            role: "admin", // Ensure admin role
            updatedAt: new Date(),
          })
          .where(eq(users.email, userData.email!))
          .returning();
        return user;
      }

      // For other users, return existing user without changes to avoid conflicts
      console.warn(
        `Email conflict for ${userData.email}, using existing account`
      );
      return existingByEmail[0];
    }

    // Safe to insert new user
    const [user] = await db.insert(users).values(userData).returning();
    return user;
  }

  async updateUser(id: string, updates: Partial<UpsertUser>): Promise<User> {
    const [user] = await db
      .update(users)
      .set({
        ...updates,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id))
      .returning();
    return user;
  }

  async updateUserStatus(id: string, isActive: boolean): Promise<User> {
    const [user] = await db
      .update(users)
      .set({
        isActive,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id))
      .returning();
    return user;
  }

  async deleteUser(id: string): Promise<void> {
    await db.delete(users).where(eq(users.id, id));
  }

  // Patient operations
  async getPatients(): Promise<PatientWithCreator[]> {
    const rows = await db
      .select({
        patient: patients,
        creator: users,
        attorney: {
          id: sql<string | null>`attorney.id`,
          email: sql<string | null>`attorney.email`,
          firstName: sql<string | null>`attorney.first_name`,
          lastName: sql<string | null>`attorney.last_name`,
          profileImageUrl: sql<string | null>`attorney.profile_image_url`,
          role: sql<"admin" | "staff" | "attorney" | null>`attorney.role`,
          isActive: sql<boolean | null>`attorney.is_active`,
          createdAt: sql<Date | null>`attorney.created_at`,
          updatedAt: sql<Date | null>`attorney.updated_at`,
        },
      })
      .from(patients)
      .leftJoin(users, eq(patients.createdBy, users.id))
      .leftJoin(
        sql`users AS attorney`,
        eq(patients.assignedAttorney, sql`attorney.id`)
      )
      .orderBy(desc(patients.createdAt));

    return rows.map((row) => ({
      ...row.patient,
      createdBy: row.creator!,
      assignedAttorney: row.attorney.id
        ? ({
            id: row.attorney.id,
            email: row.attorney.email,
            firstName: row.attorney.firstName,
            lastName: row.attorney.lastName,
            profileImageUrl: row.attorney.profileImageUrl,
            role: row.attorney.role!,
            isActive: row.attorney.isActive!,
            createdAt: row.attorney.createdAt,
            updatedAt: row.attorney.updatedAt,
          } as User)
        : undefined,
    }));
  }

  async getPatient(id: string): Promise<PatientWithCreator | undefined> {
    const [result] = await db
      .select({
        patient: patients,
        creator: users,
        attorney: {
          id: sql<string | null>`attorney.id`,
          email: sql<string | null>`attorney.email`,
          firstName: sql<string | null>`attorney.first_name`,
          lastName: sql<string | null>`attorney.last_name`,
          profileImageUrl: sql<string | null>`attorney.profile_image_url`,
          role: sql<"admin" | "staff" | "attorney" | null>`attorney.role`,
          isActive: sql<boolean | null>`attorney.is_active`,
          createdAt: sql<Date | null>`attorney.created_at`,
          updatedAt: sql<Date | null>`attorney.updated_at`,
        },
      })
      .from(patients)
      .leftJoin(users, eq(patients.createdBy, users.id))
      .leftJoin(
        sql`users AS attorney`,
        eq(patients.assignedAttorney, sql`attorney.id`)
      )
      .where(eq(patients.id, id));

    if (!result) return undefined;

    return {
      ...result.patient,
      createdBy: result.creator!,
      assignedAttorney: result.attorney.id
        ? ({
            id: result.attorney.id,
            email: result.attorney.email,
            firstName: result.attorney.firstName,
            lastName: result.attorney.lastName,
            profileImageUrl: result.attorney.profileImageUrl,
            role: result.attorney.role!,
            isActive: result.attorney.isActive!,
            createdAt: result.attorney.createdAt,
            updatedAt: result.attorney.updatedAt,
          } as User)
        : undefined,
    };
  }

  async createPatient(patient: InsertPatient): Promise<Patient> {
    const [newPatient] = await db.insert(patients).values(patient).returning();
    return newPatient;
  }

  async updatePatient(
    id: string,
    patient: Partial<InsertPatient>
  ): Promise<Patient> {
    const [updatedPatient] = await db
      .update(patients)
      .set({ ...patient, updatedAt: new Date() })
      .where(eq(patients.id, id))
      .returning();
    return updatedPatient;
  }

  async deletePatient(id: string): Promise<void> {
    await db.delete(patients).where(eq(patients.id, id));
  }

  async getPatientsByStatus(status: string): Promise<PatientWithCreator[]> {
    const rows = await db
      .select({
        patient: patients,
        creator: users,
        attorney: {
          id: sql<string | null>`attorney.id`,
          email: sql<string | null>`attorney.email`,
          firstName: sql<string | null>`attorney.first_name`,
          lastName: sql<string | null>`attorney.last_name`,
          profileImageUrl: sql<string | null>`attorney.profile_image_url`,
          role: sql<"admin" | "staff" | "attorney" | null>`attorney.role`,
          isActive: sql<boolean | null>`attorney.is_active`,
          createdAt: sql<Date | null>`attorney.created_at`,
          updatedAt: sql<Date | null>`attorney.updated_at`,
        },
      })
      .from(patients)
      .leftJoin(users, eq(patients.createdBy, users.id))
      .leftJoin(
        sql`users AS attorney`,
        eq(patients.assignedAttorney, sql`attorney.id`)
      )
      .where(eq(patients.status, status as any))
      .orderBy(desc(patients.createdAt));

    return rows.map((row) => ({
      ...row.patient,
      createdBy: row.creator!,
      assignedAttorney: row.attorney.id
        ? ({
            id: row.attorney.id,
            email: row.attorney.email,
            firstName: row.attorney.firstName,
            lastName: row.attorney.lastName,
            profileImageUrl: row.attorney.profileImageUrl,
            role: row.attorney.role!,
            isActive: row.attorney.isActive!,
            createdAt: row.attorney.createdAt,
            updatedAt: row.attorney.updatedAt,
          } as User)
        : undefined,
    }));
  }

  async getPatientsPaginated(
    page: number,
    limit: number,
    status?: string,
    userId?: string,
    userRole?: string
  ): Promise<{
    patients: PatientWithCreator[];
    total: number;
    totalPages: number;
  }> {
    const offset = (page - 1) * limit;

    console.log(
      `[getPatientsPaginated] page=${page}, limit=${limit}, offset=${offset}, status=${status}, userId=${userId}, userRole=${userRole}`
    );

    // Build where conditions
    const conditions: any[] = [];

    // Add status filter if provided
    if (status) {
      conditions.push(eq(patients.status, status as any));
    }

    // Add role-based filtering for non-admin users
    if (userRole && userRole !== "admin" && userId) {
      if (userRole === "staff") {
        // Staff can see patients they created OR patients assigned to them
        conditions.push(
          or(
            eq(patients.createdBy, userId),
            eq(patients.assignedAttorney, userId)
          )
        );
      } else if (userRole === "attorney") {
        // Attorneys can only see patients assigned to them
        conditions.push(eq(patients.assignedAttorney, userId));
      }
    }

    // Get total count with all filters
    let countQuery = db.select({ count: count() }).from(patients);
    if (conditions.length > 0) {
      const whereClause =
        conditions.length === 1 ? conditions[0] : and(...conditions);
      countQuery = countQuery.where(whereClause) as any;
    }
    const [{ count: totalCount }] = await countQuery;
    const total = Number(totalCount);

    console.log(`[getPatientsPaginated] Total count: ${total}`);

    // Build select query with joins - ensure limit and offset are always applied
    const baseQuery = db
      .select({
        patient: patients,
        creator: users,
        attorney: {
          id: sql<string | null>`attorney.id`,
          email: sql<string | null>`attorney.email`,
          firstName: sql<string | null>`attorney.first_name`,
          lastName: sql<string | null>`attorney.last_name`,
          profileImageUrl: sql<string | null>`attorney.profile_image_url`,
          role: sql<"admin" | "staff" | "attorney" | null>`attorney.role`,
          isActive: sql<boolean | null>`attorney.is_active`,
          createdAt: sql<Date | null>`attorney.created_at`,
          updatedAt: sql<Date | null>`attorney.updated_at`,
        },
      })
      .from(patients)
      .leftJoin(users, eq(patients.createdBy, users.id))
      .leftJoin(
        sql`users AS attorney`,
        eq(patients.assignedAttorney, sql`attorney.id`)
      );

    // Apply where conditions if any, then order, limit, and offset in one chain
    let rows;
    if (conditions.length > 0) {
      const whereClause =
        conditions.length === 1 ? conditions[0] : and(...conditions);
      rows = await baseQuery
        .where(whereClause)
        .orderBy(desc(patients.createdAt))
        .limit(limit)
        .offset(offset);
    } else {
      rows = await baseQuery
        .orderBy(desc(patients.createdAt))
        .limit(limit)
        .offset(offset);
    }

    console.log(
      `[getPatientsPaginated] Returned ${rows.length} rows (expected max ${limit})`
    );

    const paginatedPatients = rows.map((row: any) => ({
      ...row.patient,
      createdBy: row.creator!,
      assignedAttorney: row.attorney.id
        ? ({
            id: row.attorney.id,
            email: row.attorney.email,
            firstName: row.attorney.firstName,
            lastName: row.attorney.lastName,
            profileImageUrl: row.attorney.profileImageUrl,
            role: row.attorney.role!,
            isActive: row.attorney.isActive!,
            createdAt: row.attorney.createdAt,
            updatedAt: row.attorney.updatedAt,
          } as User)
        : undefined,
    }));

    const totalPages = Math.ceil(total / limit);

    console.log(
      `[getPatientsPaginated] Returning ${paginatedPatients.length} patients, total=${total}, totalPages=${totalPages}`
    );

    return {
      patients: paginatedPatients,
      total,
      totalPages,
    };
  }

  async getPatientsByAssignedAttorney(
    attorneyId: string
  ): Promise<PatientWithCreator[]> {
    const rows = await db
      .select({
        patient: patients,
        creator: users,
        attorney: {
          id: sql<string | null>`attorney.id`,
          email: sql<string | null>`attorney.email`,
          firstName: sql<string | null>`attorney.first_name`,
          lastName: sql<string | null>`attorney.last_name`,
          profileImageUrl: sql<string | null>`attorney.profile_image_url`,
          role: sql<"admin" | "staff" | "attorney" | null>`attorney.role`,
          isActive: sql<boolean | null>`attorney.is_active`,
          createdAt: sql<Date | null>`attorney.created_at`,
          updatedAt: sql<Date | null>`attorney.updated_at`,
        },
      })
      .from(patients)
      .leftJoin(users, eq(patients.createdBy, users.id))
      .leftJoin(
        sql`users AS attorney`,
        eq(patients.assignedAttorney, sql`attorney.id`)
      )
      .where(eq(patients.assignedAttorney, attorneyId))
      .orderBy(desc(patients.createdAt));

    return rows.map((row) => ({
      ...row.patient,
      createdBy: row.creator!,
      assignedAttorney: row.attorney.id
        ? ({
            id: row.attorney.id,
            email: row.attorney.email,
            firstName: row.attorney.firstName,
            lastName: row.attorney.lastName,
            profileImageUrl: row.attorney.profileImageUrl,
            role: row.attorney.role!,
            isActive: row.attorney.isActive!,
            createdAt: row.attorney.createdAt,
            updatedAt: row.attorney.updatedAt,
          } as User)
        : undefined,
    }));
  }

  // Task operations
  async getTasks(): Promise<TaskWithRelations[]> {
    const rows = await db
      .select()
      .from(tasks)
      .leftJoin(patients, eq(tasks.patientId, patients.id))
      .leftJoin(users, eq(tasks.assignedTo, users.id))
      .orderBy(desc(tasks.createdAt));

    const tasksWithCreator = await Promise.all(
      rows.map(async (row) => {
        const [creator] = await db
          .select()
          .from(users)
          .where(eq(users.id, row.tasks.createdBy));

        return {
          ...row.tasks,
          patient: row.patients || undefined,
          assignedTo: row.users!,
          createdBy: creator!,
        } as TaskWithRelations;
      })
    );
    return tasksWithCreator;
  }

  async getTasksPaginated(
    page: number,
    limit: number,
    userId?: string,
    patientId?: string,
    userRole?: string
  ): Promise<{
    tasks: TaskWithRelations[];
    total: number;
    totalPages: number;
  }> {
    const offset = (page - 1) * limit;

    console.log(
      `[getTasksPaginated] page=${page}, limit=${limit}, offset=${offset}, userId=${userId}, patientId=${patientId}, userRole=${userRole}`
    );

    // Build where conditions
    const conditions: any[] = [];

    // Add patient filter if provided
    if (patientId) {
      conditions.push(eq(tasks.patientId, patientId));
    }

    // Add role-based filtering for non-admin users
    if (userRole && userRole !== "admin" && userId) {
      // Non-admins only see tasks assigned to them
      conditions.push(eq(tasks.assignedTo, userId));
    } else if (userId && userRole === "admin") {
      // Admin can optionally filter by userId, but if not provided, see all
      // This is handled by not adding the condition
    }

    // Get total count with all filters
    let countQuery = db.select({ count: count() }).from(tasks);
    if (conditions.length > 0) {
      const whereClause =
        conditions.length === 1 ? conditions[0] : and(...conditions);
      countQuery = countQuery.where(whereClause) as any;
    }
    const [{ count: totalCount }] = await countQuery;
    const total = Number(totalCount);

    console.log(`[getTasksPaginated] Total count: ${total}`);

    // Build select query with joins
    const baseQuery = db
      .select({
        task: tasks,
        patient: patients,
        assignedUser: users,
      })
      .from(tasks)
      .leftJoin(patients, eq(tasks.patientId, patients.id))
      .leftJoin(users, eq(tasks.assignedTo, users.id));

    // Apply where conditions if any, then order, limit, and offset
    let rows;
    if (conditions.length > 0) {
      const whereClause =
        conditions.length === 1 ? conditions[0] : and(...conditions);
      rows = await baseQuery
        .where(whereClause)
        .orderBy(desc(tasks.createdAt))
        .limit(limit)
        .offset(offset);
    } else {
      rows = await baseQuery
        .orderBy(desc(tasks.createdAt))
        .limit(limit)
        .offset(offset);
    }

    console.log(
      `[getTasksPaginated] Returned ${rows.length} rows (expected max ${limit})`
    );

    // Get creators for all tasks
    const tasksWithCreator = await Promise.all(
      rows.map(async (row: any) => {
        const [creator] = await db
          .select()
          .from(users)
          .where(eq(users.id, row.task.createdBy));

        return {
          ...row.task,
          patient: row.patient || undefined,
          assignedTo: row.assignedUser!,
          createdBy: creator!,
        } as TaskWithRelations;
      })
    );

    const totalPages = Math.ceil(total / limit);

    console.log(
      `[getTasksPaginated] Returning ${tasksWithCreator.length} tasks, total=${total}, totalPages=${totalPages}`
    );

    return {
      tasks: tasksWithCreator,
      total,
      totalPages,
    };
  }

  async getTask(id: string): Promise<TaskWithRelations | undefined> {
    const [result] = await db
      .select()
      .from(tasks)
      .leftJoin(patients, eq(tasks.patientId, patients.id))
      .leftJoin(users, eq(tasks.assignedTo, users.id))
      .where(eq(tasks.id, id));

    if (!result) return undefined;

    const [creator] = await db
      .select()
      .from(users)
      .where(eq(users.id, result.tasks.createdBy));

    return {
      ...result.tasks,
      patient: result.patients || undefined,
      assignedTo: result.users!,
      createdBy: creator!,
    } as TaskWithRelations;
  }

  async createTask(task: InsertTask): Promise<Task> {
    const [newTask] = await db.insert(tasks).values(task).returning();
    return newTask;
  }

  async updateTask(id: string, task: Partial<InsertTask>): Promise<Task> {
    const [updatedTask] = await db
      .update(tasks)
      .set({ ...task, updatedAt: new Date() })
      .where(eq(tasks.id, id))
      .returning();
    return updatedTask;
  }

  async deleteTask(id: string): Promise<void> {
    await db.delete(tasks).where(eq(tasks.id, id));
  }

  async getTasksByUser(userId: string): Promise<TaskWithRelations[]> {
    const rows = await db
      .select()
      .from(tasks)
      .leftJoin(patients, eq(tasks.patientId, patients.id))
      .leftJoin(users, eq(tasks.assignedTo, users.id))
      .where(eq(tasks.assignedTo, userId))
      .orderBy(desc(tasks.createdAt));

    const tasksWithCreator = await Promise.all(
      rows.map(async (row) => {
        const [creator] = await db
          .select()
          .from(users)
          .where(eq(users.id, row.tasks.createdBy));

        return {
          ...row.tasks,
          patient: row.patients || undefined,
          assignedTo: row.users!,
          createdBy: creator!,
        } as TaskWithRelations;
      })
    );
    return tasksWithCreator;
  }

  async getTasksByPatient(patientId: string): Promise<TaskWithRelations[]> {
    const rows = await db
      .select()
      .from(tasks)
      .leftJoin(patients, eq(tasks.patientId, patients.id))
      .leftJoin(users, eq(tasks.assignedTo, users.id))
      .where(eq(tasks.patientId, patientId))
      .orderBy(desc(tasks.createdAt));

    const tasksWithCreator = await Promise.all(
      rows.map(async (row) => {
        const [creator] = await db
          .select()
          .from(users)
          .where(eq(users.id, row.tasks.createdBy));

        return {
          ...row.tasks,
          patient: row.patients || undefined,
          assignedTo: row.users!,
          createdBy: creator!,
        } as TaskWithRelations;
      })
    );
    return tasksWithCreator;
  }

  // Appointment operations
  async getAppointments(): Promise<Appointment[]> {
    return await db
      .select()
      .from(appointments)
      .orderBy(desc(appointments.scheduledAt));
  }

  async getAppointment(id: string): Promise<Appointment | undefined> {
    const [appointment] = await db
      .select()
      .from(appointments)
      .where(eq(appointments.id, id));
    return appointment;
  }

  async createAppointment(
    appointment: InsertAppointment
  ): Promise<Appointment> {
    const [newAppointment] = await db
      .insert(appointments)
      .values(appointment)
      .returning();
    return newAppointment;
  }

  async updateAppointment(
    id: string,
    appointment: Partial<InsertAppointment>
  ): Promise<Appointment> {
    const [updatedAppointment] = await db
      .update(appointments)
      .set({ ...appointment, updatedAt: new Date() })
      .where(eq(appointments.id, id))
      .returning();
    return updatedAppointment;
  }

  async deleteAppointment(id: string): Promise<void> {
    await db.delete(appointments).where(eq(appointments.id, id));
  }

  async getAppointmentsByPatient(patientId: string): Promise<Appointment[]> {
    return await db
      .select()
      .from(appointments)
      .where(eq(appointments.patientId, patientId))
      .orderBy(desc(appointments.scheduledAt));
  }

  async getAppointmentsByProvider(providerId: string): Promise<Appointment[]> {
    return await db
      .select()
      .from(appointments)
      .where(eq(appointments.providerId, providerId))
      .orderBy(desc(appointments.scheduledAt));
  }

  // Audit log operations
  async createAuditLog(auditLog: InsertAuditLog): Promise<AuditLog> {
    const [newAuditLog] = await db
      .insert(auditLogs)
      .values(auditLog)
      .returning();
    return newAuditLog;
  }

  async getAuditLogs(patientId?: string): Promise<AuditLog[]> {
    const query = db.select().from(auditLogs);

    if (patientId) {
      return await query
        .where(eq(auditLogs.patientId, patientId))
        .orderBy(desc(auditLogs.createdAt));
    }

    return await query.orderBy(desc(auditLogs.createdAt));
  }

  // Alert operations
  async getAlerts(userId?: string): Promise<Alert[]> {
    const query = db.select().from(alerts);

    if (userId) {
      return await query
        .where(eq(alerts.userId, userId))
        .orderBy(desc(alerts.createdAt));
    }

    return await query.orderBy(desc(alerts.createdAt));
  }

  async getSystemScheduledAlerts(): Promise<Alert[]> {
    // Only get system alerts that are scheduled (not user notifications)
    return await db
      .select()
      .from(alerts)
      .where(
        sql`${alerts.userId} IS NULL AND ${alerts.scheduledFor} IS NOT NULL`
      )
      .orderBy(desc(alerts.createdAt));
  }

  async createAlert(alert: InsertAlert): Promise<Alert> {
    const [newAlert] = await db.insert(alerts).values(alert).returning();
    return newAlert;
  }

  async markAlertAsRead(id: string): Promise<void> {
    await db.update(alerts).set({ isRead: true }).where(eq(alerts.id, id));
  }

  async markAlertEmailSent(id: string): Promise<void> {
    await db
      .update(alerts)
      .set({ emailSent: true, sentAt: new Date() })
      .where(eq(alerts.id, id));
  }

  // Patient notes operations
  async getPatientNotes(patientId: string): Promise<PatientNote[]> {
    return await db
      .select()
      .from(patientNotes)
      .where(eq(patientNotes.patientId, patientId))
      .orderBy(desc(patientNotes.createdAt));
  }

  async createPatientNote(note: InsertPatientNote): Promise<PatientNote> {
    const [newNote] = await db.insert(patientNotes).values(note).returning();
    return newNote;
  }

  async updatePatientNote(
    id: string,
    note: Partial<InsertPatientNote>
  ): Promise<PatientNote> {
    const [updatedNote] = await db
      .update(patientNotes)
      .set({ ...note, updatedAt: new Date() })
      .where(eq(patientNotes.id, id))
      .returning();
    return updatedNote;
  }

  async deletePatientNote(id: string): Promise<void> {
    await db.delete(patientNotes).where(eq(patientNotes.id, id));
  }

  // Patient drop operations
  async dropPatient(
    patientId: string,
    dropReason: string,
    droppedBy: string
  ): Promise<Patient> {
    const [patient] = await db
      .update(patients)
      .set({
        status: "dropped",
        dropReason,
        droppedBy,
        droppedAt: new Date(),
        updatedAt: new Date(),
      })
      .where(eq(patients.id, patientId))
      .returning();
    return patient;
  }

  // Patient records operations
  async getPatientRecords(patientId: string): Promise<PatientRecord[]> {
    return await db
      .select()
      .from(patientRecords)
      .where(eq(patientRecords.patientId, patientId))
      .orderBy(desc(patientRecords.createdAt));
  }

  async createPatientRecord(
    record: InsertPatientRecord
  ): Promise<PatientRecord> {
    const [newRecord] = await db
      .insert(patientRecords)
      .values(record)
      .returning();
    return newRecord;
  }

  async deletePatientRecord(id: string): Promise<void> {
    await db.delete(patientRecords).where(eq(patientRecords.id, id));
  }

  // Dashboard stats
  async getDashboardStats(): Promise<{
    totalPatients: number;
    pendingConsent: number;
    consentSigned: number;
    schedulable: number;
  }> {
    const [totalPatients] = await db.select({ count: count() }).from(patients);

    const [pendingConsent] = await db
      .select({ count: count() })
      .from(patients)
      .where(
        or(
          eq(patients.status, "pending_consent"),
          eq(patients.status, "consent_sent")
        )
      );

    const [consentSigned] = await db
      .select({ count: count() })
      .from(patients)
      .where(eq(patients.status, "consent_signed"));

    const [schedulable] = await db
      .select({ count: count() })
      .from(patients)
      .where(eq(patients.status, "schedulable"));

    return {
      totalPatients: totalPatients.count,
      pendingConsent: pendingConsent.count,
      consentSigned: consentSigned.count,
      schedulable: schedulable.count,
    };
  }
}

export const storage = new DatabaseStorage();
