import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { Readable } from "stream";

// Initialize S3 client with credentials from environment variables
const s3Client = new S3Client({
  region: process.env.AWS_REGION || "us-east-1",
  credentials:
    process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY
      ? {
          accessKeyId: process.env.AWS_ACCESS_KEY_ID,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
        }
      : undefined, // If not provided, will use IAM role (for EC2/ECS/Lambda)
});

const BUCKET_NAME = process.env.AWS_S3_BUCKET_NAME;
const S3_FOLDER_PREFIX = process.env.AWS_S3_FOLDER_PREFIX || "patient-records"; // Default folder prefix

if (!BUCKET_NAME) {
  console.warn("⚠️  AWS_S3_BUCKET_NAME not set - S3 uploads will fail");
}

export interface S3UploadResult {
  key: string;
  url?: string; // Optional pre-signed URL for immediate access
}

/**
 * Upload a file buffer to S3
 * @param buffer File buffer
 * @param fileName Original filename
 * @param mimeType MIME type of the file
 * @param patientId Patient ID for folder organization
 * @returns S3 upload result with bucket and key
 */
export async function uploadToS3(
  buffer: Buffer,
  fileName: string,
  mimeType: string,
  patientId: string
): Promise<S3UploadResult> {
  if (!BUCKET_NAME) {
    throw new Error("AWS S3 bucket name not configured");
  }

  // Generate secure S3 key: patient-records/{patientId}/{timestamp}_{random}_{sanitizedFileName}
  const timestamp = Date.now();
  const randomString = Math.random().toString(36).substring(2, 15);
  const sanitizedFileName = fileName.replace(/[^a-zA-Z0-9.-]/g, "_");
  const s3Key = `${S3_FOLDER_PREFIX}/${patientId}/${timestamp}_${randomString}_${sanitizedFileName}`;

  // Upload to S3
  const command = new PutObjectCommand({
    Bucket: BUCKET_NAME,
    Key: s3Key,
    Body: buffer,
    ContentType: mimeType,
    // Security: Server-side encryption
    ServerSideEncryption: "AES256",
    // Metadata for tracking
    Metadata: {
      "patient-id": patientId,
      "original-filename": fileName,
      "uploaded-at": new Date().toISOString(),
    },
  });

  await s3Client.send(command);

  return {
    key: s3Key,
  };
}

/**
 * Download a file from S3 as a stream
 * @param key S3 object key
 * @returns Readable stream of the file
 */
export async function downloadFromS3(key: string): Promise<Readable> {
  if (!BUCKET_NAME) {
    throw new Error("AWS S3 bucket name not configured");
  }

  const command = new GetObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
  });

  const response = await s3Client.send(command);

  if (!response.Body) {
    throw new Error("File not found in S3");
  }

  // AWS SDK v3 returns the Body as a stream-like object
  // It's typically already a Readable stream or can be converted
  if (response.Body instanceof Readable) {
    return response.Body;
  }

  // Handle Uint8Array or Buffer types (convert to stream)
  if (response.Body instanceof Uint8Array || Buffer.isBuffer(response.Body)) {
    return Readable.from(Buffer.from(response.Body));
  }

  // For stream-like objects, try to use directly or convert
  // AWS SDK v3 Body is typically a Readable stream already
  try {
    // Check if it has stream methods (AWS SDK v3 streams are compatible with Node.js streams)
    const body = response.Body as any;
    if (typeof body.pipe === "function") {
      // AWS SDK v3 streams are compatible with Node.js Readable streams at runtime
      return body as unknown as Readable;
    }

    // Try to convert using Readable.from
    return Readable.from(body);
  } catch (error) {
    throw new Error(
      `Unable to convert S3 response body to stream: ${
        (error as Error).message
      }`
    );
  }
}

/**
 * Get file metadata from S3
 * @param key S3 object key
 * @returns File metadata including size and content type
 */
export async function getS3FileMetadata(key: string): Promise<{
  contentLength?: number;
  contentType?: string;
  lastModified?: Date;
}> {
  if (!BUCKET_NAME) {
    throw new Error("AWS S3 bucket name not configured");
  }

  const command = new HeadObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
  });

  const response = await s3Client.send(command);

  return {
    contentLength: response.ContentLength,
    contentType: response.ContentType,
    lastModified: response.LastModified,
  };
}

/**
 * Delete a file from S3
 * @param key S3 object key
 */
export async function deleteFromS3(key: string): Promise<void> {
  if (!BUCKET_NAME) {
    throw new Error("AWS S3 bucket name not configured");
  }

  const command = new DeleteObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
  });

  await s3Client.send(command);
}

/**
 * Generate a pre-signed URL for temporary file access (for downloads)
 * @param key S3 object key
 * @param expiresIn Expiration time in seconds (default: 1 hour)
 * @returns Pre-signed URL
 */
export async function getPresignedUrl(
  key: string,
  expiresIn: number = 3600
): Promise<string> {
  if (!BUCKET_NAME) {
    throw new Error("AWS S3 bucket name not configured");
  }

  const command = new GetObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
  });

  return await getSignedUrl(s3Client, command, { expiresIn });
}

/**
 * Check if S3 is properly configured
 * @returns true if S3 is configured, false otherwise
 */
export function isS3Configured(): boolean {
  return (
    !!BUCKET_NAME &&
    (!!(process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) ||
      // If no explicit credentials, assume IAM role (for EC2/ECS/Lambda)
      !!process.env.AWS_REGION)
  );
}
