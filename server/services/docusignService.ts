import docusign from "docusign-esign";
import { docusignAuth } from "./docusignAuth";
import type { Patient } from "@shared/schema";

class DocuSignService {
  private basePath = "https://demo.docusign.net/restapi";
  private accountId = process.env.DOCUSIGN_ACCOUNT_ID || '';
  private templateId = process.env.DOCUSIGN_ENGLISH_TEMPLATE_ID || ''; // English template (default/fallback)
  private templateIdSpanish = process.env.DOCUSIGN_SPANISH_TEMPLATE_ID || '';
  private templateRoleName = process.env.DOCUSIGN_TEMPLATE_ROLE_NAME || '';

  async sendConsentForm(patient: Patient, language: 'en' | 'es' = 'en'): Promise<string> {
    try {
      const accessToken = await docusignAuth.getAccessToken();

      // Initialize API client
      const apiClient = new docusign.ApiClient();
      apiClient.setBasePath(this.basePath);
      apiClient.addDefaultHeader("Authorization", `Bearer ${accessToken}`);

      const envelopesApi = new docusign.EnvelopesApi(apiClient);

      // Select template based on language
      const templateId = language === 'es' && this.templateIdSpanish 
        ? this.templateIdSpanish 
        : this.templateId;

      if (!templateId) {
        throw new Error(`Template ID not configured for language: ${language}`);
      }

      // Create Template Role
      const templateRole = docusign.TemplateRole.constructFromObject({
        email: patient.email,
        name: `${patient.firstName} ${patient.lastName}`,
        roleName: this.templateRoleName,
      });

      // Create Envelope Definition
      const envelopeDefinition = new docusign.EnvelopeDefinition();
      envelopeDefinition.templateId = templateId;
      envelopeDefinition.templateRoles = [templateRole];
      envelopeDefinition.status = "sent";

      // Send Envelope
      const result = await envelopesApi.createEnvelope(this.accountId, {
        envelopeDefinition,
      });

      return result.envelopeId!;
    } catch (err) {
      console.error("DocuSign template send error:", err);
      throw new Error("Failed to send DocuSign template consent form");
    }
  }

  async getEnvelopeStatus(envelopeId: string): Promise<string> {
    try {
      const accessToken = await docusignAuth.getAccessToken();

      const apiClient = new docusign.ApiClient();
      apiClient.setBasePath(this.basePath);
      apiClient.addDefaultHeader("Authorization", `Bearer ${accessToken}`);

      const envelopesApi = new docusign.EnvelopesApi(apiClient);

      const result = await envelopesApi.getEnvelope(this.accountId, envelopeId);
      return result.status!;
    } catch (err) {
      console.error("DocuSign status error:", err);
      throw new Error("Failed to get envelope status");
    }
  }
}

export const docusignService = new DocuSignService();
