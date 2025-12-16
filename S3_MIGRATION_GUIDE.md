# AWS S3 Migration Guide

This document describes the migration from local file storage to AWS S3 for patient records.

## Overview

Patient records are now stored in AWS S3 instead of local file system. The system maintains backward compatibility with existing local files.

## Changes Made

### 1. Database Schema Updates

- Added `s3Bucket` field to store S3 bucket name
- Added `s3Key` field to store S3 object key (folder path + filename)
- Added `storageType` field ('local' or 's3') to track storage location
- Kept `filePath` field for backward compatibility with existing local files

### 2. New S3 Service

- Created `server/services/s3Service.ts` with functions for:
  - Uploading files to S3
  - Downloading files from S3
  - Deleting files from S3
  - Getting file metadata
  - Generating pre-signed URLs

### 3. Updated Routes

- **Upload Route** (`POST /api/patients/:patientId/records`):
  - Now uploads to S3 if configured, falls back to local storage
  - Uses memory storage for S3 uploads (more efficient)
- **New Download Route** (`GET /api/patients/:patientId/records/:recordId/download`):

  - Secure endpoint with access control
  - Supports both S3 and local file downloads
  - Streams files directly to client

- **Delete Route** (`DELETE /api/patients/:patientId/records/:recordId`):
  - Now deletes from S3 if stored there
  - Also handles local file deletion for backward compatibility

### 4. Client Updates

- Updated `patient-records-modal.tsx` to use the new download endpoint
- Added proper file download functionality with error handling

## Setup Instructions

### 1. Install Dependencies

```bash
npm install
```

This will install:

- `@aws-sdk/client-s3` - AWS S3 client
- `@aws-sdk/s3-request-presigner` - For generating pre-signed URLs

### 2. Update Database Schema

```bash
npm run db:push
```

This will add the new S3-related columns to the `patient_records` table.

### 3. Configure AWS S3

#### Option A: Using IAM Roles (Recommended for Production)

1. Create an S3 bucket in AWS Console
2. Create an IAM role with S3 permissions:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "s3:PutObject",
           "s3:GetObject",
           "s3:DeleteObject",
           "s3:HeadObject"
         ],
         "Resource": "arn:aws:s3:::your-bucket-name/patient-records/*"
       }
     ]
   }
   ```
3. Attach the IAM role to your EC2 instance, ECS task, or Lambda function
4. Set environment variables (no credentials needed):
   ```env
   AWS_REGION=us-east-1
   AWS_S3_BUCKET_NAME=your-bucket-name
   AWS_S3_FOLDER_PREFIX=patient-records
   ```

#### Option B: Using Access Keys (For Development)

1. Create an S3 bucket in AWS Console
2. Create an IAM user with S3 permissions
3. Generate access keys for the user
4. Set environment variables:
   ```env
   AWS_REGION=us-east-1
   AWS_S3_BUCKET_NAME=your-bucket-name
   AWS_S3_FOLDER_PREFIX=patient-records
   AWS_ACCESS_KEY_ID=your-access-key-id
   AWS_SECRET_ACCESS_KEY=your-secret-access-key
   ```

### 4. S3 Bucket Configuration

- Enable server-side encryption (AES256) for HIPAA compliance
- Configure bucket policies to restrict access
- Set up lifecycle policies if needed (e.g., archive old files)
- Enable versioning for additional data protection

## Environment Variables

Add these to your `.env` file:

```env
# AWS S3 Configuration (Required for patient record storage)
AWS_REGION=us-east-1                    # AWS region where bucket is located
AWS_S3_BUCKET_NAME=your-bucket-name     # Name of your S3 bucket
AWS_S3_FOLDER_PREFIX=patient-records    # Folder prefix (default: patient-records)

# AWS Credentials (Optional - only if not using IAM role)
AWS_ACCESS_KEY_ID=your-access-key-id
AWS_SECRET_ACCESS_KEY=your-secret-access-key
```

## Backward Compatibility

The system maintains full backward compatibility:

- Existing local files continue to work
- Old records with `storageType='local'` are still accessible
- New uploads use S3 if configured, otherwise fall back to local storage
- Download endpoint handles both S3 and local files automatically

## Security Features

1. **Access Control**: All download requests require authentication and role-based authorization
2. **Server-Side Encryption**: Files are encrypted at rest in S3 (AES256)
3. **Secure File Names**: Server-generated secure filenames prevent path traversal
4. **HIPAA Compliance**: All file access is logged in audit logs
5. **IAM Roles**: Recommended use of IAM roles instead of access keys

## Migration of Existing Files

If you want to migrate existing local files to S3:

1. Create a migration script that:

   - Reads all records with `storageType='local'`
   - Uploads each file to S3
   - Updates the record with S3 bucket and key
   - Sets `storageType='s3'`
   - Optionally deletes the local file

2. Example migration script structure:
   ```typescript
   // scripts/migrate-to-s3.ts
   const records = await storage.getPatientRecords(patientId);
   for (const record of records) {
     if (record.storageType === "local" && record.filePath) {
       const fileBuffer = await fs.readFile(record.filePath);
       const s3Result = await uploadToS3(
         fileBuffer,
         record.fileName,
         record.mimeType,
         record.patientId
       );
       await storage.updatePatientRecord(record.id, {
         s3Bucket: s3Result.bucket,
         s3Key: s3Result.key,
         storageType: "s3",
         filePath: null,
       });
     }
   }
   ```

## Testing

1. **Test Upload**:

   - Upload a new patient record
   - Verify it appears in S3 bucket
   - Check database record has correct S3 fields

2. **Test Download**:

   - Download the uploaded file
   - Verify file content matches original
   - Check audit logs for download event

3. **Test Delete**:

   - Delete a record
   - Verify file is removed from S3
   - Verify database record is deleted

4. **Test Backward Compatibility**:
   - Access old local files
   - Verify they still download correctly

## Troubleshooting

### Files not uploading to S3

- Check AWS credentials/IAM role permissions
- Verify `AWS_S3_BUCKET_NAME` is set correctly
- Check S3 bucket exists and is accessible
- Review server logs for error messages

### Download fails

- Verify user has access to the patient
- Check S3 bucket and key are correct in database
- Verify IAM permissions include `s3:GetObject`
- Check network connectivity to S3

### TypeScript errors

- Run `npm install` to ensure AWS SDK packages are installed
- Restart TypeScript server in your IDE

## Support

For issues or questions, refer to:

- AWS S3 Documentation: https://docs.aws.amazon.com/s3/
- AWS SDK for JavaScript v3: https://docs.aws.amazon.com/sdk-for-javascript/v3/
