import sgMail from "@sendgrid/mail";

function getSendGridConfig() {
  const apiKey = process.env.SENDGRID_API_KEY;
  const fromEmail = process.env.SENDGRID_FROM_EMAIL || process.env.FROM_EMAIL;
  const fromName = process.env.SENDGRID_FROM_NAME || "ChiroCareCRM";
  const replyToEmail =
    process.env.SENDGRID_REPLY_TO || process.env.REPLY_TO_EMAIL;
  const enabled =
    process.env.SENDGRID_ENABLED === "true" ||
    Boolean(process.env.SENDGRID_API_KEY);

  return { apiKey, fromEmail, fromName, replyToEmail, enabled };
}

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function buildPasswordResetOtpEmail(params: {
  otp: string;
  expiresInMinutes: number;
  supportEmail?: string;
}): { subject: string; text: string; html: string } {
  const otp = escapeHtml(params.otp);
  const expires = params.expiresInMinutes;
  const subject = `Your ChiroCareCRM password reset code: ${params.otp}`;
  const supportEmail = params.supportEmail;

  // Plain-text fallback
  const text =
    `ChiroCareCRM Password Reset\n\n` +
    `Your one-time verification code is: ${params.otp}\n` +
    `This code expires in ${expires} minutes.\n\n` +
    `If you didn’t request a password reset, you can ignore this email.\n` +
    (supportEmail ? `\nNeed help? Contact: ${supportEmail}\n` : "");

  const logoUrl = `${process.env.BASE_URL}/assets/icons/logo.png`;

  // Simple, production-friendly HTML (responsive, works across most clients)
  const previewText = `Your password reset code is ${params.otp}. Expires in ${expires} minutes.`;
  const html = `
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="x-apple-disable-message-reformatting" />
    <title>${escapeHtml(subject)}</title>
</head>

<body style="margin:0; padding:0; background-color:#f6f7fb;">
    <!-- Preheader (hidden) -->
    <div style="display:none; max-height:0; overflow:hidden; opacity:0; color:transparent; mso-hide:all;">
        ${escapeHtml(previewText)}
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#f6f7fb;">
        <tr>
            <td align="center" style="padding:24px 12px;">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="width:100%; max-width:600px;">
                    <tr>
                        <td align="left" style="padding:0 8px 12px 8px;">
                            <div style="font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial, sans-serif; font-size:14px; color:#111827; display:flex; align-items:center; gap:12px;">

                                <div style="display:flex; align-items:center; justify-content:center; width:48px; height:48px; background:#27aa83; border-radius:8px;">
                                   <img src="${logoUrl}" alt="ChiroCareCRM Logo" style="width:50%; height:50%; object-fit:contain;" />
                                </div>

                                <span style="font-weight:800; font-size:18px; line-height:1;">
                                    ChiroCareCRM
                                </span>

                            </div>

                        </td>
                    </tr>

                    <tr>
                        <td style="background:#ffffff; border-radius:14px; padding:24px; border:1px solid #e5e7eb;">
                            <div style="font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial, sans-serif; color:#111827;">
                                <h1 style="margin:0 0 8px; font-size:20px; line-height:28px; font-weight:800;">Reset your password</h1>
                                <p style="margin:0 0 16px; font-size:14px; line-height:22px; color:#374151;">
                                    Use the verification code below to reset your password. This code expires in <strong>${expires} minutes</strong>.
                                </p>

                                <div style="margin:18px 0 18px; padding:16px; background:#f3f4f6; border-radius:12px; text-align:center;">
                                    <div style="font-size:12px; letter-spacing:0.08em; text-transform:uppercase; color:#6b7280; margin-bottom:8px;">
                                        Your code
                                    </div>
                                    <div style="font-size:28px; letter-spacing:0.20em; font-weight:900; color:#111827;">
                                        ${otp}
                                    </div>
                                </div>

                                <p style="margin:0; font-size:12px; line-height:18px; color:#6b7280;">
                                    If you didn’t request a password reset, you can safely ignore this email.
                                </p>
                            </div>
                        </td>
                    </tr>

                    <tr>
                        <td style="padding:14px 8px 0 8px;">
                            <div style="font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial, sans-serif; font-size:12px; line-height:18px; color:#6b7280;">
                                ${
                                  supportEmail
                                    ? `Need help? <a href="mailto:${escapeHtml(
                                        supportEmail
                                      )}" style="color:#2563eb; text-decoration:none;">${escapeHtml(
                                        supportEmail
                                      )}</a>`
                                    : ""
                                }
                                <div style="margin-top:8px;">© ${new Date().getFullYear()} ChiroCareCRM</div>
                            </div>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>

</html>
`.trim();

  return { subject, text, html };
}

export async function sendOtpEmail(params: {
  to: string;
  otp: string;
  expiresInMinutes: number;
}): Promise<void> {
  const { apiKey, fromEmail, fromName, replyToEmail, enabled } =
    getSendGridConfig();

  if (!enabled || !apiKey) {
    // In dev/staging without SendGrid configured, log instead of failing.
    console.warn(
      `[SendGrid] Not configured. OTP for ${params.to}: ${params.otp} (expires in ${params.expiresInMinutes}m)`
    );
    return;
  }

  if (!fromEmail) {
    throw new Error(
      "SendGrid is enabled but FROM address is missing. Set SENDGRID_FROM_EMAIL (recommended) or FROM_EMAIL."
    );
  }

  sgMail.setApiKey(apiKey);

  const supportEmail = replyToEmail || fromEmail;
  const { subject, text, html } = buildPasswordResetOtpEmail({
    otp: params.otp,
    expiresInMinutes: params.expiresInMinutes,
    supportEmail,
  });

  await sgMail.send({
    to: params.to,
    from: { email: fromEmail, name: fromName },
    ...(replyToEmail ? { replyTo: replyToEmail } : {}),
    subject,
    text,
    html,
    // Categories help deliverability + analytics in SendGrid
    categories: ["chirocarecrm", "auth", "password-reset"],
  });
}

function buildAppointmentEmail(params: {
  patientName: string;
  scheduledAt: Date;
  duration: number;
  location?: string | null;
  isUpdate?: boolean;
  oldScheduledAt?: Date;
  supportEmail?: string;
}): { subject: string; text: string; html: string } {
  const {
    patientName,
    scheduledAt,
    duration,
    location,
    isUpdate,
    oldScheduledAt,
    supportEmail,
  } = params;

  // Format date and time
  const dateStr = scheduledAt.toLocaleDateString("en-US", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });
  const timeStr = scheduledAt.toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    hour12: true,
  });

  const oldDateStr = oldScheduledAt
    ? oldScheduledAt.toLocaleDateString("en-US", {
        weekday: "long",
        year: "numeric",
        month: "long",
        day: "numeric",
      })
    : null;
  const oldTimeStr = oldScheduledAt
    ? oldScheduledAt.toLocaleTimeString("en-US", {
        hour: "numeric",
        minute: "2-digit",
        hour12: true,
      })
    : null;

  const subject = isUpdate
    ? `Appointment Updated - ${dateStr} at ${timeStr}`
    : `Appointment Confirmed - ${dateStr} at ${timeStr}`;

  // Plain-text fallback
  const text =
    `${isUpdate ? "Appointment Updated" : "Appointment Confirmed"}\n\n` +
    `Dear ${escapeHtml(patientName)},\n\n` +
    (isUpdate && oldDateStr && oldTimeStr
      ? `Your appointment has been rescheduled.\n\n` +
        `Previous: ${oldDateStr} at ${oldTimeStr}\n` +
        `New: ${dateStr} at ${timeStr}\n\n`
      : `Your appointment has been confirmed for:\n\n`) +
    `Date: ${dateStr}\n` +
    `Time: ${timeStr}\n` +
    `Duration: ${duration} minutes\n` +
    (location ? `Location: ${escapeHtml(location)}\n` : "") +
    `\n${
      isUpdate
        ? "Please note the updated time and date."
        : "We look forward to seeing you."
    }\n` +
    (supportEmail ? `\nNeed help? Contact: ${supportEmail}\n` : "");

  const logoUrl = `${process.env.BASE_URL}/assets/icons/logo.png`;
  const previewText = isUpdate
    ? `Your appointment has been rescheduled to ${dateStr} at ${timeStr}`
    : `Your appointment is confirmed for ${dateStr} at ${timeStr}`;

  // HTML email matching OTP style
  const html = `
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="x-apple-disable-message-reformatting" />
    <title>${escapeHtml(subject)}</title>
</head>

<body style="margin:0; padding:0; background-color:#f6f7fb;">
    <!-- Preheader (hidden) -->
    <div style="display:none; max-height:0; overflow:hidden; opacity:0; color:transparent; mso-hide:all;">
        ${escapeHtml(previewText)}
    </div>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#f6f7fb;">
        <tr>
            <td align="center" style="padding:24px 12px;">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="width:100%; max-width:600px;">
                    <tr>
                        <td align="left" style="padding:0 8px 12px 8px;">
                            <div style="font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial, sans-serif; font-size:14px; color:#111827; display:flex; align-items:center; gap:12px;">

                                <div style="display:flex; align-items:center; justify-content:center; width:48px; height:48px; background:#27aa83; border-radius:8px;">
                                   <img src="${logoUrl}" alt="ChiroCareCRM Logo" style="width:50%; height:50%; object-fit:contain;" />
                                </div>

                                <span style="font-weight:800; font-size:18px; line-height:1;">
                                    ChiroCareCRM
                                </span>

                            </div>

                        </td>
                    </tr>

                    <tr>
                        <td style="background:#ffffff; border-radius:14px; padding:24px; border:1px solid #e5e7eb;">
                            <div style="font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial, sans-serif; color:#111827;">
                                <h1 style="margin:0 0 8px; font-size:20px; line-height:28px; font-weight:800;">${
                                  isUpdate
                                    ? "Appointment Updated"
                                    : "Appointment Confirmed"
                                }</h1>
                                <p style="margin:0 0 16px; font-size:14px; line-height:22px; color:#374151;">
                                    Dear ${escapeHtml(patientName)},
                                </p>
                                ${
                                  isUpdate && oldDateStr && oldTimeStr
                                    ? `<p style="margin:0 0 16px; font-size:14px; line-height:22px; color:#374151;">
                                    Your appointment has been rescheduled. Please note the updated details below.
                                </p>
                                <div style="margin:18px 0; padding:16px; background:#fef3c7; border-radius:12px; border-left:4px solid #f59e0b;">
                                    <div style="font-size:12px; color:#92400e; margin-bottom:8px; font-weight:600;">Previous Appointment</div>
                                    <div style="font-size:14px; color:#78350f; font-weight:500;">${escapeHtml(
                                      oldDateStr
                                    )} at ${escapeHtml(oldTimeStr)}</div>
                                </div>`
                                    : ""
                                }

                                <div style="margin:18px 0 18px; padding:16px; background:#f3f4f6; border-radius:12px;">
                                    <div style="font-size:12px; letter-spacing:0.08em; text-transform:uppercase; color:#6b7280; margin-bottom:12px;">
                                        Appointment Details
                                    </div>
                                    <div style="font-size:16px; font-weight:700; color:#111827; margin-bottom:8px;">
                                        ${escapeHtml(dateStr)}
                                    </div>
                                    <div style="font-size:16px; font-weight:700; color:#111827; margin-bottom:8px;">
                                        ${escapeHtml(timeStr)}
                                    </div>
                                    <div style="font-size:14px; color:#374151; margin-top:12px;">
                                        Duration: ${duration} minutes
                                    </div>
                                    ${
                                      location
                                        ? `<div style="font-size:14px; color:#374151; margin-top:8px;">
                                        Location: ${escapeHtml(location)}
                                    </div>`
                                        : ""
                                    }
                                </div>

                                <p style="margin:0; font-size:14px; line-height:22px; color:#374151;">
                                    ${
                                      isUpdate
                                        ? "Please make note of the updated appointment time. We look forward to seeing you."
                                        : "We look forward to seeing you at your scheduled appointment."
                                    }
                                </p>
                            </div>
                        </td>
                    </tr>

                    <tr>
                        <td style="padding:14px 8px 0 8px;">
                            <div style="font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, Arial, sans-serif; font-size:12px; line-height:18px; color:#6b7280;">
                                ${
                                  supportEmail
                                    ? `Need help? <a href="mailto:${escapeHtml(
                                        supportEmail
                                      )}" style="color:#2563eb; text-decoration:none;">${escapeHtml(
                                        supportEmail
                                      )}</a>`
                                    : ""
                                }
                                <div style="margin-top:8px;">© ${new Date().getFullYear()} ChiroCareCRM</div>
                            </div>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>

</html>
`.trim();

  return { subject, text, html };
}

export async function sendAppointmentEmail(params: {
  to: string;
  patientName: string;
  scheduledAt: Date;
  duration: number;
  location?: string | null;
  isUpdate?: boolean;
  oldScheduledAt?: Date;
}): Promise<void> {
  const { apiKey, fromEmail, fromName, replyToEmail, enabled } =
    getSendGridConfig();

  if (!enabled || !apiKey) {
    // In dev/staging without SendGrid configured, log instead of failing.
    console.warn(
      `[SendGrid] Not configured. Appointment email for ${
        params.to
      }: ${params.scheduledAt.toISOString()}`
    );
    return;
  }

  if (!fromEmail) {
    throw new Error(
      "SendGrid is enabled but FROM address is missing. Set SENDGRID_FROM_EMAIL (recommended) or FROM_EMAIL."
    );
  }

  sgMail.setApiKey(apiKey);

  const supportEmail = replyToEmail || fromEmail;
  const { subject, text, html } = buildAppointmentEmail({
    patientName: params.patientName,
    scheduledAt: params.scheduledAt,
    duration: params.duration,
    location: params.location,
    isUpdate: params.isUpdate,
    oldScheduledAt: params.oldScheduledAt,
    supportEmail,
  });

  await sgMail.send({
    to: params.to,
    from: { email: fromEmail, name: fromName },
    ...(replyToEmail ? { replyTo: replyToEmail } : {}),
    subject,
    text,
    html,
    // Categories help deliverability + analytics in SendGrid
    categories: [
      "chirocarecrm",
      "appointments",
      params.isUpdate ? "appointment-update" : "appointment-confirmation",
    ],
  });
}
