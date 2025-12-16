import fs from "fs";
import docusign from "docusign-esign";

export class DocuSignAuth {
  private apiClient = new docusign.ApiClient();

  constructor() {
    this.apiClient.setBasePath(process.env.DOCUSIGN_BASE_URL || '');
  }

  async getAccessToken(): Promise<string> {
    const privateKey = fs.readFileSync(process.env.DOCUSIGN_PRIVATE_KEY_PATH || '');

    const results = await this.apiClient.requestJWTUserToken(
      process.env.DOCUSIGN_API_KEY || '',
      process.env.DOCUSIGN_USER_ID || '',
      ["signature", "impersonation"],
      privateKey,
      3600
    );

    return results.body.access_token;
  }
}

export const docusignAuth = new DocuSignAuth();
