import {
  users,
  patients,
  tasks,
  appointments,
  auditLogs,
  patientHistoryLogs,
  alerts,
  patientNotes,
  patientRecords,
  tempOtps,
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
  type PatientHistoryLog,
  type InsertPatientHistoryLog,
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
  getUsersPaginated(page: number, limit: number): Promise<{ users: User[]; total: number; totalPages: number }>;
  upsertUser(user: UpsertUser): Promise<User>;
  updateUser(id: string, updates: Partial<UpsertUser>): Promise<User>;
  updateUserStatus(id: string, isActive: boolean): Promise<User>;
  deleteUser(id: string): Promise<void>;
  
  // Patient operations
  getPatients(): Promise<PatientWithCreator[]>;
  getPatientsPaginated(page: number, limit: number, status?: string, userId?: string, userRole?: string): Promise<{ patients: PatientWithCreator[]; total: number; totalPages: number }>;
  getPatient(id: string): Promise<PatientWithCreator | undefined>;
  createPatient(patient: InsertPatient): Promise<Patient>;
  updatePatient(id: string, patient: Partial<InsertPatient>): Promise<Patient>;
  deletePatient(id: string): Promise<void>;
  getPatientsByStatus(status: string): Promise<PatientWithCreator[]>;
  getPatientsByAssignedAttorney(attorneyId: string): Promise<PatientWithCreator[]>;
  
  // Task operations
  getTasks(): Promise<TaskWithRelations[]>;
  getTasksPaginated(page: number, limit: number, userId?: string, patientId?: string, userRole?: string): Promise<{ tasks: TaskWithRelations[]; total: number; totalPages: number }>;
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
  updateAppointment(id: string, appointment: Partial<InsertAppointment>): Promise<Appointment>;
  deleteAppointment(id: string): Promise<void>;
  getAppointmentsByPatient(patientId: string): Promise<Appointment[]>;
  getAppointmentsByProvider(providerId: string): Promise<Appointment[]>;
  
  // Audit log operations
  createAuditLog(auditLog: InsertAuditLog): Promise<AuditLog>;
  getAuditLogs(patientId?: string): Promise<AuditLog[]>;

  // Patient history (product timeline) operations
  createPatientHistoryLog(log: InsertPatientHistoryLog): Promise<PatientHistoryLog>;
  getPatientHistoryLogs(patientId: string): Promise<PatientHistoryLog[]>;
  
  // Alert operations
  getAlerts(userId?: string): Promise<Alert[]>;
  getSystemScheduledAlerts(): Promise<Alert[]>;
  createAlert(alert: InsertAlert): Promise<Alert>;
  markAlertAsRead(id: string): Promise<void>;
  markAlertEmailSent(id: string): Promise<void>;
  
  // Patient notes operations
  getPatientNotes(patientId: string): Promise<PatientNote[]>;
  createPatientNote(note: InsertPatientNote): Promise<PatientNote>;
  updatePatientNote(id: string, note: Partial<InsertPatientNote>): Promise<PatientNote>;
  deletePatientNote(id: string): Promise<void>;
  
  // Patient drop operations
  dropPatient(patientId: string, dropReason: string, droppedBy: string): Promise<Patient>;
  
  // Patient records operations
  getPatientRecords(patientId: string): Promise<PatientRecord[]>;
  createPatientRecord(record: InsertPatientRecord): Promise<PatientRecord>;
  deletePatientRecord(id: string): Promise<void>;
  
  // Dashboard stats
  getDashboardStats(): Promise<{
    cards: Array<{
      key: "totalPatients" | "pendingConsent" | "consentSigned" | "schedulable";
      title: string;
      value: number;
      trendPercent: number;
      trendUp: boolean;
      trendLabel: string;
      color: "emerald" | "amber" | "blue" | "purple";
    }>;
  }>;

  // Dashboard activity (time series)
  getDashboardActivity(range: "weekly" | "monthly"): Promise<
    Array<{
      name: string;
      newPatients: number;
      consents: number;
    }>
  >;

  // Dashboard activity with previous-period comparison
  getDashboardActivityWithCompare(range: "weekly" | "monthly"): Promise<{
    current: Array<{ name: string; newPatients: number; consents: number }>;
    previous: Array<{ name: string; newPatients: number; consents: number }>;
  }>;

  // Password reset OTP operations
  cleanupExpiredTempOtps(now?: Date): Promise<number>;
  countRecentTempOtpsByEmail(email: string, since: Date): Promise<number>;
  createTempOtp(params: {
    email: string;
    otpHash: string;
    expiresAt: Date;
  }): Promise<{ id: string; email: string; createdAt: Date; expiresAt: Date }>;
  getLatestValidTempOtpByEmail(
    email: string,
    now?: Date
  ): Promise<
    | {
        id: string;
        email: string;
        otpHash: string;
        createdAt: Date;
        expiresAt: Date;
        consumedAt: Date | null;
      }
    | undefined
  >;
  consumeTempOtp(id: string, consumedAt?: Date): Promise<void>;
  deleteTempOtpsByEmail(email: string): Promise<number>;
}

export class DatabaseStorage implements IStorage {
  private formatLocalDateKey(d: Date): string {
    // YYYY-MM-DD in *local* time (avoids UTC day-shift from toISOString())
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, "0");
    const day = String(d.getDate()).padStart(2, "0");
    return `${year}-${month}-${day}`;
  }

  private buildWeeklySeriesFromMaps(params: {
    offsetDays: number; // 0 = last 7 days incl today, 7 = previous week, etc.
    newPatientsByDay: Map<string, number>;
    consentsByDay: Map<string, number>;
  }): Array<{ name: string; newPatients: number; consents: number }> {
    const series: Array<{ name: string; newPatients: number; consents: number }> = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setHours(0, 0, 0, 0);
      d.setDate(d.getDate() - params.offsetDays - i);
      const key = this.formatLocalDateKey(d);
      const name = d.toLocaleDateString("en-US", { weekday: "short" });
      series.push({
        name,
        newPatients: params.newPatientsByDay.get(key) ?? 0,
        consents: params.consentsByDay.get(key) ?? 0,
      });
    }
    return series;
  }

  private buildMonthlySeriesFromMaps(params: {
    offsetMonths: number; // 0 = last 12 months incl current, 12 = previous 12 months, etc.
    newPatientsByMonth: Map<string, number>;
    consentsByMonth: Map<string, number>;
  }): Array<{ name: string; newPatients: number; consents: number }> {
    const series: Array<{ name: string; newPatients: number; consents: number }> = [];
    const now = new Date();
    // Start at first day of current month, shift back offset, then walk back 11 more months
    const start = new Date(now.getFullYear(), now.getMonth(), 1);
    start.setMonth(start.getMonth() - (11 + params.offsetMonths));
    for (let i = 0; i < 12; i++) {
      const d = new Date(start.getFullYear(), start.getMonth() + i, 1);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
      const name = d.toLocaleDateString("en-US", { month: "short" });
      series.push({
        name,
        newPatients: params.newPatientsByMonth.get(key) ?? 0,
        consents: params.consentsByMonth.get(key) ?? 0,
      });
    }
    return series;
  }

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

  async getUsersPaginated(page: number, limit: number): Promise<{ users: User[]; total: number; totalPages: number }> {
    const offset = (page - 1) * limit;
    
    // Get total count
    const [{ count: totalCount }] = await db.select({ count: count() }).from(users);
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
    const existingById = await db.select().from(users).where(eq(users.id, userData.id!)).limit(1);
    
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
    const existingByEmail = await db.select().from(users).where(eq(users.email, userData.email!)).limit(1);
    
    if (existingByEmail.length > 0) {
      // For admin users, ensure they have admin role but DON'T change ID (breaks foreign keys)
      if (userData.email?.includes('@chirocare.com') || userData.email?.includes('admin')) {
        // Update user info but preserve existing ID to avoid foreign key violations
        const [user] = await db
          .update(users)
          .set({
            // DON'T update ID - it breaks foreign key constraints with audit_logs
            firstName: userData.firstName,
            lastName: userData.lastName,
            profileImageUrl: userData.profileImageUrl,
            role: 'admin', // Ensure admin role
            updatedAt: new Date(),
          })
          .where(eq(users.email, userData.email!))
          .returning();
        return user;
      }
      
      // For other users, return existing user without changes to avoid conflicts
      console.warn(`Email conflict for ${userData.email}, using existing account`);
      return existingByEmail[0];
    }
    
    // Safe to insert new user
    const [user] = await db
      .insert(users)
      .values(userData)
      .returning();
    return user;
  }

  async updateUser(id: string, updates: Partial<UpsertUser>): Promise<User> {
    const [user] = await db
      .update(users)
      .set({ 
        ...updates,
        updatedAt: new Date() 
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
        updatedAt: new Date() 
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
          role: sql<'admin' | 'staff' | 'attorney' | null>`attorney.role`,
          isActive: sql<boolean | null>`attorney.is_active`,
          createdAt: sql<Date | null>`attorney.created_at`,
          updatedAt: sql<Date | null>`attorney.updated_at`,
        }
      })
      .from(patients)
      .leftJoin(users, eq(patients.createdBy, users.id))
      .leftJoin(sql`users AS attorney`, eq(patients.assignedAttorney, sql`attorney.id`))
      .orderBy(desc(patients.createdAt));
    
    return rows.map(row => ({
      ...row.patient,
      createdBy: row.creator!,
      assignedAttorney: row.attorney.id ? {
        id: row.attorney.id,
        email: row.attorney.email,
        firstName: row.attorney.firstName,
        lastName: row.attorney.lastName,
        profileImageUrl: row.attorney.profileImageUrl,
        role: row.attorney.role!,
        isActive: row.attorney.isActive!,
        createdAt: row.attorney.createdAt,
        updatedAt: row.attorney.updatedAt,
      } as User : undefined,
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
          role: sql<'admin' | 'staff' | 'attorney' | null>`attorney.role`,
          isActive: sql<boolean | null>`attorney.is_active`,
          createdAt: sql<Date | null>`attorney.created_at`,
          updatedAt: sql<Date | null>`attorney.updated_at`,
        }
      })
      .from(patients)
      .leftJoin(users, eq(patients.createdBy, users.id))
      .leftJoin(sql`users AS attorney`, eq(patients.assignedAttorney, sql`attorney.id`))
      .where(eq(patients.id, id));
    
    if (!result) return undefined;
    
    return {
      ...result.patient,
      createdBy: result.creator!,
      assignedAttorney: result.attorney.id ? {
        id: result.attorney.id,
        email: result.attorney.email,
        firstName: result.attorney.firstName,
        lastName: result.attorney.lastName,
        profileImageUrl: result.attorney.profileImageUrl,
        role: result.attorney.role!,
        isActive: result.attorney.isActive!,
        createdAt: result.attorney.createdAt,
        updatedAt: result.attorney.updatedAt,
      } as User : undefined,
    };
  }

  async createPatient(patient: InsertPatient): Promise<Patient> {
    const [newPatient] = await db
      .insert(patients)
      .values(patient)
      .returning();
    return newPatient;
  }

  async updatePatient(id: string, patient: Partial<InsertPatient>): Promise<Patient> {
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
          role: sql<'admin' | 'staff' | 'attorney' | null>`attorney.role`,
          isActive: sql<boolean | null>`attorney.is_active`,
          createdAt: sql<Date | null>`attorney.created_at`,
          updatedAt: sql<Date | null>`attorney.updated_at`,
        }
      })
      .from(patients)
      .leftJoin(users, eq(patients.createdBy, users.id))
      .leftJoin(sql`users AS attorney`, eq(patients.assignedAttorney, sql`attorney.id`))
      .where(eq(patients.status, status as any))
      .orderBy(desc(patients.createdAt));
    
    return rows.map(row => ({
      ...row.patient,
      createdBy: row.creator!,
      assignedAttorney: row.attorney.id ? {
        id: row.attorney.id,
        email: row.attorney.email,
        firstName: row.attorney.firstName,
        lastName: row.attorney.lastName,
        profileImageUrl: row.attorney.profileImageUrl,
        role: row.attorney.role!,
        isActive: row.attorney.isActive!,
        createdAt: row.attorney.createdAt,
        updatedAt: row.attorney.updatedAt,
      } as User : undefined,
    }));
  }

  async getPatientsPaginated(page: number, limit: number, status?: string, userId?: string, userRole?: string): Promise<{ patients: PatientWithCreator[]; total: number; totalPages: number }> {
    const offset = (page - 1) * limit;
    
    console.log(`[getPatientsPaginated] page=${page}, limit=${limit}, offset=${offset}, status=${status}, userId=${userId}, userRole=${userRole}`);
    
    // Build where conditions
    const conditions: any[] = [];
    
    // Add status filter if provided
    if (status) {
      conditions.push(eq(patients.status, status as any));
    }
    
    // Add role-based filtering for non-admin users
    if (userRole && userRole !== 'admin' && userId) {
      if (userRole === 'staff') {
        // Staff can see patients they created OR patients assigned to them
        conditions.push(or(
          eq(patients.createdBy, userId),
          eq(patients.assignedAttorney, userId)
        ));
      } else if (userRole === 'attorney') {
        // Attorneys can only see patients assigned to them
        conditions.push(eq(patients.assignedAttorney, userId));
      }
    }
    
    // Get total count with all filters
    let countQuery = db.select({ count: count() }).from(patients);
    if (conditions.length > 0) {
      const whereClause = conditions.length === 1 ? conditions[0] : and(...conditions);
      countQuery = countQuery.where(whereClause) as any;
    }
    const [{ count: totalCount }] = await countQuery;
    const total = Number(totalCount);
    
    console.log(`[getPatientsPaginated] Total count: ${total}`);
    
    // Build select query with joins - ensure limit and offset are always applied
    const baseQuery = db
      .select({
        patient: patients,
        recordsCount: sql<number>`(
          select count(*)
          from patient_records pr
          where pr.patient_id = ${patients.id}
        )`,
        creator: users,
        attorney: {
          id: sql<string | null>`attorney.id`,
          email: sql<string | null>`attorney.email`,
          firstName: sql<string | null>`attorney.first_name`,
          lastName: sql<string | null>`attorney.last_name`,
          profileImageUrl: sql<string | null>`attorney.profile_image_url`,
          role: sql<'admin' | 'staff' | 'attorney' | null>`attorney.role`,
          isActive: sql<boolean | null>`attorney.is_active`,
          createdAt: sql<Date | null>`attorney.created_at`,
          updatedAt: sql<Date | null>`attorney.updated_at`,
        }
      })
      .from(patients)
      .leftJoin(users, eq(patients.createdBy, users.id))
      .leftJoin(sql`users AS attorney`, eq(patients.assignedAttorney, sql`attorney.id`));
    
    // Apply where conditions if any, then order, limit, and offset in one chain
    let rows;
    if (conditions.length > 0) {
      const whereClause = conditions.length === 1 ? conditions[0] : and(...conditions);
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
    
    console.log(`[getPatientsPaginated] Returned ${rows.length} rows (expected max ${limit})`);
    
    const paginatedPatients = rows.map((row: any) => ({
      ...row.patient,
      recordsCount: Number(row.recordsCount ?? 0),
      createdBy: row.creator!,
      assignedAttorney: row.attorney.id ? {
        id: row.attorney.id,
        email: row.attorney.email,
        firstName: row.attorney.firstName,
        lastName: row.attorney.lastName,
        profileImageUrl: row.attorney.profileImageUrl,
        role: row.attorney.role!,
        isActive: row.attorney.isActive!,
        createdAt: row.attorney.createdAt,
        updatedAt: row.attorney.updatedAt,
      } as User : undefined,
    }));
    
    const totalPages = Math.ceil(total / limit);
    
    console.log(`[getPatientsPaginated] Returning ${paginatedPatients.length} patients, total=${total}, totalPages=${totalPages}`);
    
    return {
      patients: paginatedPatients,
      total,
      totalPages,
    };
  }

  async getPatientsByAssignedAttorney(attorneyId: string): Promise<PatientWithCreator[]> {
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
          role: sql<'admin' | 'staff' | 'attorney' | null>`attorney.role`,
          isActive: sql<boolean | null>`attorney.is_active`,
          createdAt: sql<Date | null>`attorney.created_at`,
          updatedAt: sql<Date | null>`attorney.updated_at`,
        }
      })
      .from(patients)
      .leftJoin(users, eq(patients.createdBy, users.id))
      .leftJoin(sql`users AS attorney`, eq(patients.assignedAttorney, sql`attorney.id`))
      .where(eq(patients.assignedAttorney, attorneyId))
      .orderBy(desc(patients.createdAt));
    
    return rows.map(row => ({
      ...row.patient,
      createdBy: row.creator!,
      assignedAttorney: row.attorney.id ? {
        id: row.attorney.id,
        email: row.attorney.email,
        firstName: row.attorney.firstName,
        lastName: row.attorney.lastName,
        profileImageUrl: row.attorney.profileImageUrl,
        role: row.attorney.role!,
        isActive: row.attorney.isActive!,
        createdAt: row.attorney.createdAt,
        updatedAt: row.attorney.updatedAt,
      } as User : undefined,
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

  async getTasksPaginated(page: number, limit: number, userId?: string, patientId?: string, userRole?: string): Promise<{ tasks: TaskWithRelations[]; total: number; totalPages: number }> {
    const offset = (page - 1) * limit;
    
    console.log(`[getTasksPaginated] page=${page}, limit=${limit}, offset=${offset}, userId=${userId}, patientId=${patientId}, userRole=${userRole}`);
    
    // Build where conditions
    const conditions: any[] = [];
    
    // Add patient filter if provided
    if (patientId) {
      conditions.push(eq(tasks.patientId, patientId));
    }
    
    // Add role-based filtering for non-admin users
    if (userRole && userRole !== 'admin' && userId) {
      // Non-admins only see tasks assigned to them
      conditions.push(eq(tasks.assignedTo, userId));
    } else if (userId && userRole === 'admin') {
      // Admin can optionally filter by userId, but if not provided, see all
      // This is handled by not adding the condition
    }
    
    // Get total count with all filters
    let countQuery = db.select({ count: count() }).from(tasks);
    if (conditions.length > 0) {
      const whereClause = conditions.length === 1 ? conditions[0] : and(...conditions);
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
      const whereClause = conditions.length === 1 ? conditions[0] : and(...conditions);
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
    
    console.log(`[getTasksPaginated] Returned ${rows.length} rows (expected max ${limit})`);
    
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
    
    console.log(`[getTasksPaginated] Returning ${tasksWithCreator.length} tasks, total=${total}, totalPages=${totalPages}`);
    
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
    const [newTask] = await db
      .insert(tasks)
      .values(task)
      .returning();
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

  async createAppointment(appointment: InsertAppointment): Promise<Appointment> {
    const [newAppointment] = await db
      .insert(appointments)
      .values(appointment)
      .returning();
    return newAppointment;
  }

  async updateAppointment(id: string, appointment: Partial<InsertAppointment>): Promise<Appointment> {
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

  // Patient history (product timeline) operations
  async createPatientHistoryLog(
    log: InsertPatientHistoryLog
  ): Promise<PatientHistoryLog> {
    const [row] = await db.insert(patientHistoryLogs).values(log).returning();
    return row;
  }

  async getPatientHistoryLogs(patientId: string): Promise<PatientHistoryLog[]> {
    return await db
      .select()
      .from(patientHistoryLogs)
      .where(eq(patientHistoryLogs.patientId, patientId))
      .orderBy(desc(patientHistoryLogs.createdAt));
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
    return await db.select().from(alerts)
      .where(sql`${alerts.userId} IS NULL AND ${alerts.scheduledFor} IS NOT NULL`)
      .orderBy(desc(alerts.createdAt));
  }

  async createAlert(alert: InsertAlert): Promise<Alert> {
    const [newAlert] = await db
      .insert(alerts)
      .values(alert)
      .returning();
    return newAlert;
  }

  async markAlertAsRead(id: string): Promise<void> {
    await db
      .update(alerts)
      .set({ isRead: true })
      .where(eq(alerts.id, id));
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
    const [newNote] = await db
      .insert(patientNotes)
      .values(note)
      .returning();
    return newNote;
  }

  async updatePatientNote(id: string, note: Partial<InsertPatientNote>): Promise<PatientNote> {
    const [updatedNote] = await db
      .update(patientNotes)
      .set({ ...note, updatedAt: new Date() })
      .where(eq(patientNotes.id, id))
      .returning();
    return updatedNote;
  }

  async deletePatientNote(id: string): Promise<void> {
    await db
      .delete(patientNotes)
      .where(eq(patientNotes.id, id));
  }

  // Patient drop operations
  async dropPatient(patientId: string, dropReason: string, droppedBy: string): Promise<Patient> {
    const [patient] = await db
      .update(patients)
      .set({
        status: 'dropped',
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

  async createPatientRecord(record: InsertPatientRecord): Promise<PatientRecord> {
    const [newRecord] = await db
      .insert(patientRecords)
      .values(record)
      .returning();
    return newRecord;
  }

  async deletePatientRecord(id: string): Promise<void> {
    await db
      .delete(patientRecords)
      .where(eq(patientRecords.id, id));
  }

  // Dashboard stats
  async getDashboardStats(): Promise<{
    cards: Array<{
      key: "totalPatients" | "pendingConsent" | "consentSigned" | "schedulable";
      title: string;
      value: number;
      trendPercent: number;
      trendUp: boolean;
      trendLabel: string;
      color: "emerald" | "amber" | "blue" | "purple";
    }>;
  }> {
    // Current snapshot values (as shown on cards)
    const [totalPatients] = await db.select({ count: count() }).from(patients);

    const [pendingConsent] = await db
      .select({ count: count() })
      .from(patients)
      .where(or(eq(patients.status, "pending_consent"), eq(patients.status, "consent_sent")));

    const [consentSigned] = await db
      .select({ count: count() })
      .from(patients)
      .where(eq(patients.status, "consent_signed"));

    const [schedulable] = await db
      .select({ count: count() })
      .from(patients)
      .where(eq(patients.status, "schedulable"));

    // Trend windows: last 30 days vs prior 30 days
    const [newPatientsLast30] = await db
      .select({ count: count() })
      .from(patients)
      .where(sql`${patients.createdAt} >= (now() - interval '30 days')`);
    const [newPatientsPrev30] = await db
      .select({ count: count() })
      .from(patients)
      .where(
        and(
          sql`${patients.createdAt} < (now() - interval '30 days')`,
          sql`${patients.createdAt} >= (now() - interval '60 days')`
        )
      );

    // Status-based trends use updatedAt as a best-effort proxy for "changed in period"
    const [pendingUpdatedLast30] = await db
      .select({ count: count() })
      .from(patients)
      .where(
        and(
          or(eq(patients.status, "pending_consent"), eq(patients.status, "consent_sent")),
          sql`${patients.updatedAt} >= (now() - interval '30 days')`
        )
      );
    const [pendingUpdatedPrev30] = await db
      .select({ count: count() })
      .from(patients)
      .where(
        and(
          or(eq(patients.status, "pending_consent"), eq(patients.status, "consent_sent")),
          sql`${patients.updatedAt} < (now() - interval '30 days')`,
          sql`${patients.updatedAt} >= (now() - interval '60 days')`
        )
      );

    const [consentsSignedLast30] = await db
      .select({ count: count() })
      .from(patients)
      .where(
        and(
          sql`${patients.consentSignedAt} is not null`,
          sql`${patients.consentSignedAt} >= (now() - interval '30 days')`
        )
      );
    const [consentsSignedPrev30] = await db
      .select({ count: count() })
      .from(patients)
      .where(
        and(
          sql`${patients.consentSignedAt} is not null`,
          sql`${patients.consentSignedAt} < (now() - interval '30 days')`,
          sql`${patients.consentSignedAt} >= (now() - interval '60 days')`
        )
      );

    const [schedulableUpdatedLast30] = await db
      .select({ count: count() })
      .from(patients)
      .where(
        and(eq(patients.status, "schedulable"), sql`${patients.updatedAt} >= (now() - interval '30 days')`)
      );
    const [schedulableUpdatedPrev30] = await db
      .select({ count: count() })
      .from(patients)
      .where(
        and(
          eq(patients.status, "schedulable"),
          sql`${patients.updatedAt} < (now() - interval '30 days')`,
          sql`${patients.updatedAt} >= (now() - interval '60 days')`
        )
      );

    const pct = (current: number, previous: number) => {
      if (previous <= 0) return current > 0 ? 100 : 0;
      return ((current - previous) / previous) * 100;
    };

    const mkTrend = (current: number, previous: number) => {
      const raw = pct(current, previous);
      const rounded = Math.round(raw * 10) / 10;
      return { trendPercent: Math.abs(rounded), trendUp: raw >= 0 };
    };

    const totalVal = Number(totalPatients.count);
    const pendingVal = Number(pendingConsent.count);
    const signedVal = Number(consentSigned.count);
    const schedVal = Number(schedulable.count);

    const t1 = mkTrend(Number(newPatientsLast30.count), Number(newPatientsPrev30.count));
    const t2 = mkTrend(Number(pendingUpdatedLast30.count), Number(pendingUpdatedPrev30.count));
    const t3 = mkTrend(Number(consentsSignedLast30.count), Number(consentsSignedPrev30.count));
    const t4 = mkTrend(Number(schedulableUpdatedLast30.count), Number(schedulableUpdatedPrev30.count));

    return {
      cards: [
        {
          key: "totalPatients",
          title: "Total Patients",
          value: totalVal,
          ...t1,
          trendLabel: "vs last 30 days",
          color: "emerald",
        },
        {
          key: "pendingConsent",
          title: "Pending Consent",
          value: pendingVal,
          ...t2,
          trendLabel: "vs last 30 days",
          color: "amber",
        },
        {
          key: "consentSigned",
          title: "Consent Signed",
          value: signedVal,
          ...t3,
          trendLabel: "vs last 30 days",
          color: "blue",
        },
        {
          key: "schedulable",
          title: "Ready to Schedule",
          value: schedVal,
          ...t4,
          trendLabel: "vs last 30 days",
          color: "purple",
        },
      ],
    };
  }

  // Dashboard activity (time series)
  async getDashboardActivity(range: "weekly" | "monthly"): Promise<
    Array<{
      name: string;
      newPatients: number;
      consents: number;
    }>
  > {
    // Use DB time functions to avoid timezone drift between app server and DB
    if (range === "weekly") {
      // Last 7 days including today, grouped by day
      const rows = await db
        .select({
          day: sql<string>`to_char(date_trunc('day', ${patients.createdAt}), 'YYYY-MM-DD')`,
          newPatients: count(patients.id),
        })
        .from(patients)
        .where(sql`${patients.createdAt} >= (now() - interval '6 days')`)
        .groupBy(sql`date_trunc('day', ${patients.createdAt})`)
        .orderBy(sql`date_trunc('day', ${patients.createdAt})`);

      const consentRows = await db
        .select({
          day: sql<string>`to_char(date_trunc('day', ${patients.consentSignedAt}), 'YYYY-MM-DD')`,
          consents: count(patients.id),
        })
        .from(patients)
        .where(
          and(
            sql`${patients.consentSignedAt} is not null`,
            sql`${patients.consentSignedAt} >= (now() - interval '6 days')`
          )
        )
        .groupBy(sql`date_trunc('day', ${patients.consentSignedAt})`)
        .orderBy(sql`date_trunc('day', ${patients.consentSignedAt})`);

      const newPatientsByDay = new Map<string, number>(
        rows.map((r) => [r.day, Number(r.newPatients)])
      );
      const consentsByDay = new Map<string, number>(
        consentRows.map((r) => [r.day, Number(r.consents)])
      );

      return this.buildWeeklySeriesFromMaps({
        offsetDays: 0,
        newPatientsByDay,
        consentsByDay,
      });
    }

    // Monthly: last 12 months including current, grouped by month
    const rows = await db
      .select({
        month: sql<string>`to_char(date_trunc('month', ${patients.createdAt}), 'YYYY-MM')`,
        newPatients: count(patients.id),
      })
      .from(patients)
      .where(sql`${patients.createdAt} >= (date_trunc('month', now()) - interval '11 months')`)
      .groupBy(sql`date_trunc('month', ${patients.createdAt})`)
      .orderBy(sql`date_trunc('month', ${patients.createdAt})`);

    const consentRows = await db
      .select({
        month: sql<string>`to_char(date_trunc('month', ${patients.consentSignedAt}), 'YYYY-MM')`,
        consents: count(patients.id),
      })
      .from(patients)
      .where(
        and(
          sql`${patients.consentSignedAt} is not null`,
          sql`${patients.consentSignedAt} >= (date_trunc('month', now()) - interval '11 months')`
        )
      )
      .groupBy(sql`date_trunc('month', ${patients.consentSignedAt})`)
      .orderBy(sql`date_trunc('month', ${patients.consentSignedAt})`);

    const newPatientsByMonth = new Map<string, number>(
      rows.map((r) => [r.month, Number(r.newPatients)])
    );
    const consentsByMonth = new Map<string, number>(
      consentRows.map((r) => [r.month, Number(r.consents)])
    );

    return this.buildMonthlySeriesFromMaps({
      offsetMonths: 0,
      newPatientsByMonth,
      consentsByMonth,
    });
  }

  async getDashboardActivityWithCompare(range: "weekly" | "monthly"): Promise<{
    current: Array<{ name: string; newPatients: number; consents: number }>;
    previous: Array<{ name: string; newPatients: number; consents: number }>;
  }> {
    if (range === "weekly") {
      // Current: last 7 days (now - 6 days .. now)
      const currentRows = await db
        .select({
          day: sql<string>`to_char(date_trunc('day', ${patients.createdAt}), 'YYYY-MM-DD')`,
          newPatients: count(patients.id),
        })
        .from(patients)
        .where(sql`${patients.createdAt} >= (now() - interval '6 days')`)
        .groupBy(sql`date_trunc('day', ${patients.createdAt})`);

      const currentConsentRows = await db
        .select({
          day: sql<string>`to_char(date_trunc('day', ${patients.consentSignedAt}), 'YYYY-MM-DD')`,
          consents: count(patients.id),
        })
        .from(patients)
        .where(
          and(
            sql`${patients.consentSignedAt} is not null`,
            sql`${patients.consentSignedAt} >= (now() - interval '6 days')`
          )
        )
        .groupBy(sql`date_trunc('day', ${patients.consentSignedAt})`);

      // Previous: 7 days before current (now - 13 days .. now - 7 days)
      const prevRows = await db
        .select({
          day: sql<string>`to_char(date_trunc('day', ${patients.createdAt}), 'YYYY-MM-DD')`,
          newPatients: count(patients.id),
        })
        .from(patients)
        .where(
          and(
            sql`${patients.createdAt} >= (now() - interval '13 days')`,
            sql`${patients.createdAt} < (now() - interval '6 days')`
          )
        )
        .groupBy(sql`date_trunc('day', ${patients.createdAt})`);

      const prevConsentRows = await db
        .select({
          day: sql<string>`to_char(date_trunc('day', ${patients.consentSignedAt}), 'YYYY-MM-DD')`,
          consents: count(patients.id),
        })
        .from(patients)
        .where(
          and(
            sql`${patients.consentSignedAt} is not null`,
            sql`${patients.consentSignedAt} >= (now() - interval '13 days')`,
            sql`${patients.consentSignedAt} < (now() - interval '6 days')`
          )
        )
        .groupBy(sql`date_trunc('day', ${patients.consentSignedAt})`);

      const currentNewPatientsByDay = new Map<string, number>(
        currentRows.map((r) => [r.day, Number(r.newPatients)])
      );
      const currentConsentsByDay = new Map<string, number>(
        currentConsentRows.map((r) => [r.day, Number(r.consents)])
      );
      const prevNewPatientsByDay = new Map<string, number>(
        prevRows.map((r) => [r.day, Number(r.newPatients)])
      );
      const prevConsentsByDay = new Map<string, number>(
        prevConsentRows.map((r) => [r.day, Number(r.consents)])
      );

      return {
        current: this.buildWeeklySeriesFromMaps({
          offsetDays: 0,
          newPatientsByDay: currentNewPatientsByDay,
          consentsByDay: currentConsentsByDay,
        }),
        previous: this.buildWeeklySeriesFromMaps({
          offsetDays: 7,
          newPatientsByDay: prevNewPatientsByDay,
          consentsByDay: prevConsentsByDay,
        }),
      };
    }

    // Monthly: current last 12 months incl current month; previous 12 months before that
    const currentRows = await db
      .select({
        month: sql<string>`to_char(date_trunc('month', ${patients.createdAt}), 'YYYY-MM')`,
        newPatients: count(patients.id),
      })
      .from(patients)
      .where(sql`${patients.createdAt} >= (date_trunc('month', now()) - interval '11 months')`)
      .groupBy(sql`date_trunc('month', ${patients.createdAt})`);

    const currentConsentRows = await db
      .select({
        month: sql<string>`to_char(date_trunc('month', ${patients.consentSignedAt}), 'YYYY-MM')`,
        consents: count(patients.id),
      })
      .from(patients)
      .where(
        and(
          sql`${patients.consentSignedAt} is not null`,
          sql`${patients.consentSignedAt} >= (date_trunc('month', now()) - interval '11 months')`
        )
      )
      .groupBy(sql`date_trunc('month', ${patients.consentSignedAt})`);

    const prevRows = await db
      .select({
        month: sql<string>`to_char(date_trunc('month', ${patients.createdAt}), 'YYYY-MM')`,
        newPatients: count(patients.id),
      })
      .from(patients)
      .where(
        and(
          sql`${patients.createdAt} >= (date_trunc('month', now()) - interval '23 months')`,
          sql`${patients.createdAt} < (date_trunc('month', now()) - interval '11 months')`
        )
      )
      .groupBy(sql`date_trunc('month', ${patients.createdAt})`);

    const prevConsentRows = await db
      .select({
        month: sql<string>`to_char(date_trunc('month', ${patients.consentSignedAt}), 'YYYY-MM')`,
        consents: count(patients.id),
      })
      .from(patients)
      .where(
        and(
          sql`${patients.consentSignedAt} is not null`,
          sql`${patients.consentSignedAt} >= (date_trunc('month', now()) - interval '23 months')`,
          sql`${patients.consentSignedAt} < (date_trunc('month', now()) - interval '11 months')`
        )
      )
      .groupBy(sql`date_trunc('month', ${patients.consentSignedAt})`);

    const currentNewPatientsByMonth = new Map<string, number>(
      currentRows.map((r) => [r.month, Number(r.newPatients)])
    );
    const currentConsentsByMonth = new Map<string, number>(
      currentConsentRows.map((r) => [r.month, Number(r.consents)])
    );
    const prevNewPatientsByMonth = new Map<string, number>(
      prevRows.map((r) => [r.month, Number(r.newPatients)])
    );
    const prevConsentsByMonth = new Map<string, number>(
      prevConsentRows.map((r) => [r.month, Number(r.consents)])
    );

    return {
      current: this.buildMonthlySeriesFromMaps({
        offsetMonths: 0,
        newPatientsByMonth: currentNewPatientsByMonth,
        consentsByMonth: currentConsentsByMonth,
      }),
      previous: this.buildMonthlySeriesFromMaps({
        offsetMonths: 12,
        newPatientsByMonth: prevNewPatientsByMonth,
        consentsByMonth: prevConsentsByMonth,
      }),
    };
  }

  // Password reset OTP operations
  async cleanupExpiredTempOtps(_now: Date = new Date()): Promise<number> {
    const deleted = await db
      .delete(tempOtps)
      // Use DB time to avoid timezone/casting mismatches between JS Date and DB timestamp
      .where(sql`${tempOtps.expiresAt} <= now()`)
      .returning({ id: tempOtps.id });
    return deleted.length;
  }

  async countRecentTempOtpsByEmail(email: string, since: Date): Promise<number> {
    const [{ count: totalCount }] = await db
      .select({ count: count() })
      .from(tempOtps)
      .where(and(eq(tempOtps.email, email), sql`${tempOtps.createdAt} >= ${since}`));
    return Number(totalCount);
  }

  async createTempOtp(params: {
    email: string;
    otpHash: string;
    expiresAt: Date;
  }): Promise<{ id: string; email: string; createdAt: Date; expiresAt: Date }> {
    const [row] = await db
      .insert(tempOtps)
      .values({
        email: params.email,
        otpHash: params.otpHash,
        expiresAt: params.expiresAt,
      })
      .returning({
        id: tempOtps.id,
        email: tempOtps.email,
        createdAt: tempOtps.createdAt,
        expiresAt: tempOtps.expiresAt,
      });
    return row;
  }

  async getLatestValidTempOtpByEmail(
    email: string,
    _now: Date = new Date()
  ): Promise<
    | {
        id: string;
        email: string;
        otpHash: string;
        createdAt: Date;
        expiresAt: Date;
        consumedAt: Date | null;
      }
    | undefined
  > {
    const [row] = await db
      .select({
        id: tempOtps.id,
        email: tempOtps.email,
        otpHash: tempOtps.otpHash,
        createdAt: tempOtps.createdAt,
        expiresAt: tempOtps.expiresAt,
        consumedAt: tempOtps.consumedAt,
      })
      .from(tempOtps)
      .where(
        and(
          eq(tempOtps.email, email),
          // Use DB time to avoid timezone/casting mismatches between JS Date and DB timestamp
          sql`${tempOtps.expiresAt} > now()`,
          sql`${tempOtps.consumedAt} IS NULL`
        )
      )
      .orderBy(desc(tempOtps.createdAt))
      .limit(1);

    return row;
  }

  async consumeTempOtp(id: string, consumedAt: Date = new Date()): Promise<void> {
    await db
      .update(tempOtps)
      .set({ consumedAt })
      .where(eq(tempOtps.id, id));
  }

  async deleteTempOtpsByEmail(email: string): Promise<number> {
    const deleted = await db
      .delete(tempOtps)
      .where(eq(tempOtps.email, email))
      .returning({ id: tempOtps.id });
    return deleted.length;
  }
}

export const storage = new DatabaseStorage();
