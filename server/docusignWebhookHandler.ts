import type { Request, Response } from "express";
import crypto from "crypto";
import { XMLParser } from "fast-xml-parser";
import { storage } from "./storage";
import { notificationService } from "./services/emailService";

export async function docusignWebhookHandler(req: Request, res: Response) {
  try {
    console.log("📬 [DocuSign Webhook] Received webhook request");

    // -------------------------------------------------------
    // 1️⃣ GET RAW BODY EXACTLY AS SENT
    // -------------------------------------------------------
    let rawBody = "";

    if (typeof req.body === "string") {
      rawBody = req.body;
    } else if (Buffer.isBuffer(req.body)) {
      rawBody = req.body.toString();
    } else {
      rawBody = JSON.stringify(req.body);
    }

    console.log("📬 [Webhook Raw Data]:", rawBody.substring(0, 500));

    // -------------------------------------------------------
    // 2️⃣ VERIFY HMAC SIGNATURE (if enabled)
    // -------------------------------------------------------
    const hmacSecret = process.env.DOCUSIGN_HMAC_KEY || "";
    console.log("HMAC_SECRET:", hmacSecret);

    if (hmacSecret) {
      const signature = req.headers["x-docusign-signature-1"];
      console.log("HEADER_SIG:", signature);

      if (!signature) {
        console.error("❌ Missing HMAC signature");
        return res.status(401).json({ message: "HMAC signature required" });
      }

      console.log("=== RAW BODY START ===");
      console.log(rawBody);
      console.log("=== RAW BODY END ===");

      const computedSig = crypto
        .createHmac("sha256", hmacSecret)
        .update(rawBody)
        .digest("base64");

      const isValid = crypto.timingSafeEqual(
        Buffer.from(signature as string),
        Buffer.from(computedSig)
      );

      if (!isValid) {
        console.error("❌ Invalid HMAC signature");
        return res.status(401).json({ message: "Invalid HMAC signature" });
      }

      console.log("✅ HMAC signature verified");
    } else {
      console.warn("⚠️ HMAC disabled — DOCUSIGN_HMAC_KEY not set");
    }

    // -------------------------------------------------------
    // 3️⃣ DETERMINE FORMAT (JSON or XML)
    // -------------------------------------------------------
    let envelopeId = "";
    let status = "";
    let completedTime: string | null = null;

    const trimmed = rawBody.trim();
    const isXML = trimmed.startsWith("<");

    if (isXML) {
      console.log("📄 Webhook Format: XML");

      const parser = new XMLParser();
      const parsed = parser.parse(rawBody);

      const env = parsed?.DocuSignEnvelopeInformation?.EnvelopeStatus;
      if (!env) {
        console.error("❌ Invalid XML structure");
        return res.status(400).json({ message: "Invalid XML structure" });
      }

      envelopeId = env.EnvelopeID;
      status = env.Status?.toLowerCase();
      completedTime = env.Completed || null;
    } else {
      console.log("📄 Webhook Format: JSON");

      const json = JSON.parse(rawBody);

      envelopeId = json?.data?.envelopeId;
      status = json?.event?.toLowerCase();

      // Normalize Monitor events → completed
      if (status === "recipient-completed" || status === "recipient-signed") {
        status = "completed";
      }

      // Normalize declined/voided events
      if (status === "recipient-declined" || status === "envelope-declined") {
        status = "declined";
      }
      if (status === "recipient-voided" || status === "envelope-voided") {
        status = "voided";
      }
    }

    console.log("📬 Parsed Envelope ID:", envelopeId);
    console.log("📬 Normalized Status:", status);

    // -------------------------------------------------------
    // 4️⃣ FIND PATIENT RECORD
    // -------------------------------------------------------
    const patients = await storage.getPatients();
    const patient = patients.find(
      (p: any) => p.docusignEnvelopeId === envelopeId
    );

    if (!patient) {
      console.warn(`⚠️ No patient found for envelope ${envelopeId}`);
      return res.status(200).json({ message: "Envelope not tracked" });
    }

    console.log(`👤 Patient Found: ${patient.firstName} ${patient.lastName}`);

    // Get the user ID from the patient's creator (the user who originally created/sent the consent form)
    // This ensures we have a valid user ID for the audit log foreign key constraint
    const userId = patient.createdBy?.id;
    if (!userId) {
      console.error(
        "❌ Patient missing createdBy user - cannot create audit log"
      );
      return res.status(500).json({ message: "Patient data incomplete" });
    }

    // -------------------------------------------------------
    // 5️⃣ UPDATE PATIENT BASED ON STATUS
    // -------------------------------------------------------
    let updateData: any = {};

    switch (status) {
      case "completed":
        updateData = {
          status: "consent_signed",
          consentSignedAt: completedTime ? new Date(completedTime) : new Date(),
        };

        console.log("✔ Updating patient → consent_signed");

        await storage.createAuditLog({
          userId: userId,
          action: "update",
          resourceType: "patient",
          resourceId: patient.id,
          patientId: patient.id,
          details: {
            field: "status",
            oldValue: patient.status,
            newValue: "consent_signed",
            source: "docusign_webhook",
            envelopeId: envelopeId,
          },
        });
        break;

      case "declined":
      case "voided":
        updateData = {
          status: "pending_consent",
        };

        console.log(`⚠️ Envelope ${status}`);

        await storage.createAuditLog({
          userId: userId,
          action: "update",
          resourceType: "patient",
          resourceId: patient.id,
          patientId: patient.id,
          details: {
            field: "status",
            oldValue: patient.status,
            newValue: "pending_consent",
            source: "docusign_webhook",
            envelopeId: envelopeId,
            reason: status,
          },
        });

        // Send notification to admin when patient declines
        await notificationService.createInAppNotification({
          type: "consent_declined",
          patientId: patient.id,
          message: `Patient ${patient.firstName} ${patient.lastName} has ${
            status === "declined" ? "declined" : "voided"
          } the consent form. Status reset to pending consent.`,
          isUrgent: true,
          targetRole: "admin",
        });

        console.log(`📢 Admin notification sent for ${status} consent`);
        break;

      default:
        console.log(`ℹ️ Ignoring intermediate status: ${status}`);
        return res.status(200).json({ message: "Status noted" });
    }

    // -------------------------------------------------------
    // 6️⃣ SAVE UPDATE
    // -------------------------------------------------------
    if (Object.keys(updateData).length > 0) {
      await storage.updatePatient(patient.id, updateData);
      console.log("✅ Patient updated");
    }

    return res.status(200).json({
      message: "Webhook processed successfully",
      envelopeId,
      status,
    });
  } catch (error) {
    console.error("❌ Webhook Error:", error);
    return res.status(200).json({ message: "Error processed" });
  }
}
