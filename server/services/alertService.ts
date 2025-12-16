import cron from 'node-cron';
import { storage } from '../storage';
import { notificationService } from './emailService';

class AlertService {
  private isRunning = false;

  start() {
    if (this.isRunning) return;
    
    this.isRunning = true;
    console.log('Starting alert service...');

    // Run every hour to check for alerts
    cron.schedule('0 * * * *', async () => {
      await this.processAlerts();
    });

    // Run immediately on startup
    setTimeout(() => this.processAlerts(), 5000);
  }

  async scheduleConsentAlerts(patientId: string) {
    const patient = await storage.getPatient(patientId);
    if (!patient) return;

    const now = new Date();
    const twentyFourHours = new Date(now.getTime() + 24 * 60 * 60 * 1000);
    const fortyEightHours = new Date(now.getTime() + 48 * 60 * 60 * 1000);

    // Schedule 24-hour alert
    await storage.createAlert({
      type: 'consent_24h',
      patientId: patient.id,
      message: `24-hour reminder: Consent form pending for ${patient.firstName} ${patient.lastName}`,
      scheduledFor: twentyFourHours,
    });

    // Schedule 48-hour alert (for admin)
    await storage.createAlert({
      type: 'consent_48h',
      patientId: patient.id,
      message: `URGENT: 48-hour alert - Consent form still pending for ${patient.firstName} ${patient.lastName}`,
      scheduledFor: fortyEightHours,
    });
  }

  private async processAlerts() {
    try {
      const now = new Date();
      // Only process system-scheduled alerts (where userId is null)
      // This prevents reprocessing user-specific notifications
      const alerts = await storage.getSystemScheduledAlerts();

      for (const alert of alerts) {
        // Skip if already sent or not yet scheduled
        if (alert.emailSent || !alert.scheduledFor || alert.scheduledFor > now) {
          continue;
        }

        const patient = await storage.getPatient(alert.patientId);
        if (!patient) continue;

        // Skip if patient has already signed consent or is schedulable
        if (patient.status === 'consent_signed' || patient.status === 'schedulable') {
          console.log(`Skipping alert for patient ${patient.id} - consent already signed (status: ${patient.status})`);
          await storage.markAlertEmailSent(alert.id);
          continue;
        }

        let emailSent = false;

        switch (alert.type) {
          case 'consent_24h':
            emailSent = await notificationService.sendConsentAlert(
              patient.email,
              `${patient.firstName} ${patient.lastName}`,
              '24h',
              patient.id
            );
            break;

          case 'consent_48h':
            emailSent = await notificationService.sendConsentAlert(
              patient.email,
              `${patient.firstName} ${patient.lastName}`,
              '48h',
              patient.id
            );
            break;

          default:
            console.log(`Unknown alert type: ${alert.type}`);
            continue;
        }

        if (emailSent) {
          await storage.markAlertEmailSent(alert.id);
          console.log(`Alert sent for patient ID ${patient.id}: ${alert.type}`);
        }
      }
    } catch (error) {
      console.error('Error processing alerts:', error);
    }
  }

  async cancelPendingConsentAlerts(patientId: string) {
    try {
      // Get all pending consent alerts for this patient
      const allAlerts = await storage.getSystemScheduledAlerts();
      const pendingAlerts = allAlerts.filter(alert => 
        alert.patientId === patientId && 
        (alert.type === 'consent_24h' || alert.type === 'consent_48h') &&
        !alert.emailSent
      );

      // Mark them as sent to prevent processing
      for (const alert of pendingAlerts) {
        await storage.markAlertEmailSent(alert.id);
        console.log(`Cancelled pending consent alert ${alert.type} for patient ${patientId}`);
      }
    } catch (error) {
      console.error('Error cancelling pending consent alerts:', error);
    }
  }

  async createTaskAlert(taskId: string, assigneeId: string) {
    const task = await storage.getTask(taskId);
    const assignee = await storage.getUser(assigneeId);
    
    if (!task || !assignee) return;

    // Send in-app notification only (no double creation)
    const patient = task.patient;
    await notificationService.sendTaskNotification(
      assigneeId,
      `${assignee.firstName} ${assignee.lastName}`,
      task.title,
      task.patientId || undefined,
      patient ? `${patient.firstName} ${patient.lastName}` : undefined
    );
  }
}

export const alertService = new AlertService();
