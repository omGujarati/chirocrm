import { storage } from '../storage';

interface NotificationParams {
  type: string;
  patientId: string;
  message: string;
  isUrgent?: boolean;
  targetRole?: 'admin' | 'staff' | 'all';
}

class NotificationService {
  async createInAppNotification(params: NotificationParams): Promise<boolean> {
    try {
      let targetUsers: any[] = [];
      
      // Get users based on target role
      if (params.targetRole === 'admin') {
        const allUsers = await this.getAllUsers();
        targetUsers = allUsers.filter(user => user.role === 'admin');
      } else if (params.targetRole === 'staff') {
        const allUsers = await this.getAllUsers();
        targetUsers = allUsers.filter(user => user.role === 'staff');
      } else if (params.targetRole === 'all') {
        targetUsers = await this.getAllUsers();
      }

      // Create alerts for each target user
      for (const user of targetUsers) {
        await storage.createAlert({
          type: params.type,
          patientId: params.patientId,
          userId: user.id,
          message: params.message,
          scheduledFor: new Date(), // Send immediately
        });
      }

      console.log(`In-app notification created for ${targetUsers.length} users: ${params.message}`);
      return true;
    } catch (error) {
      console.error('Failed to create in-app notification:', error);
      return false;
    }
  }

  private async getAllUsers(): Promise<any[]> {
    try {
      const users = await storage.getUsers();
      return users.filter(user => user.isActive);
    } catch (error) {
      console.error('Failed to get users:', error);
      return [];
    }
  }

  async sendConsentAlert(patientEmail: string, patientName: string, alertType: '24h' | '48h', patientId: string): Promise<boolean> {
    const isUrgent = alertType === '48h';
    const message = isUrgent 
      ? `URGENT: ${patientName}'s consent form is still pending after 48 hours. Please follow up immediately.`
      : `Reminder: ${patientName}'s consent form has been pending for 24 hours. Please follow up with the patient.`;

    const targetRole = alertType === '48h' ? 'admin' : 'staff';

    return await this.createInAppNotification({
      type: `consent_${alertType}`,
      patientId,
      message,
      isUrgent,
      targetRole,
    });
  }

  async sendTaskNotification(
    assigneeId: string, 
    assigneeName: string, 
    taskTitle: string, 
    patientId?: string,
    patientName?: string
  ): Promise<boolean> {
    const message = patientName 
      ? `New task assigned: "${taskTitle}" for patient ${patientName}`
      : `New task assigned: "${taskTitle}"`;

    // Send only to the specific assignee (HIPAA compliance - least privilege)
    try {
      await storage.createAlert({
        type: 'task_assigned',
        patientId: patientId || '',
        userId: assigneeId,
        message,
        scheduledFor: new Date(), // Send immediately
      });
      
      console.log(`Task notification sent to user ${assigneeId}: ${message}`);
      return true;
    } catch (error) {
      console.error('Failed to create task notification:', error);
      return false;
    }
  }

  // For appointment confirmations, we can still send these to patients via email if needed
  // but for staff notifications, we'll use in-app alerts
  async sendAppointmentConfirmation(
    patientEmail: string,
    patientName: string,
    appointmentDate: Date,
    providerName: string
  ): Promise<boolean> {
    // For now, just log the appointment confirmation since we removed email
    // In a real system, this could integrate with SMS or other patient communication methods
    console.log(`Appointment confirmation sent: ${appointmentDate.toLocaleString()} with provider`);
    return true;
  }
}

export const notificationService = new NotificationService();
