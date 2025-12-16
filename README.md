# ChiroCareCRM

A HIPAA-compliant patient management system designed for chiropractic practices and law firms. Built with modern web technologies for secure patient management, consent form tracking, and team collaboration.

## Features

- **Patient Management**: Complete patient records with status tracking through consent workflow
- **DocuSign Integration**: Automated consent form tracking with webhook support for real-time updates
- **Role-Based Access Control**: Admin, staff, and attorney roles with different permission levels
- **Audit Logging**: Comprehensive activity tracking for HIPAA compliance
- **Task Management**: Assignment system with priorities and status tracking
- **Appointment Scheduling**: Calendar integration for patient appointments
- **Patient Notes**: Timestamped notes with role-based visibility
- **Modern Dashboard**: Visual analytics with patient activity charts

## Tech Stack

- **Frontend**: React, TypeScript, Tailwind CSS, shadcn/ui, Recharts
- **Backend**: Node.js, Express.js, TypeScript
- **Database**: PostgreSQL with Drizzle ORM
- **Authentication**: Username/password with session-based auth
- **Build Tool**: Vite

## Getting Started

### Prerequisites

- Node.js 18+
- PostgreSQL database
- npm or yarn

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/YOUR_USERNAME/ChiroCRM.git
   cd ChiroCRM
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Set up environment variables**

   Create a `.env` file in the root directory with the following variables:

   ```env
   # Database (Required)
   DATABASE_URL=postgresql://username:password@host:port/database

   # Session (Required)
   SESSION_SECRET=your-secure-random-string-at-least-32-chars

   # Google OAuth (Required for Google login)
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret

   # DocuSign Integration (Optional)
   DOCUSIGN_API_KEY=your-docusign-api-key
   DOCUSIGN_ACCOUNT_ID=your-docusign-account-id
   DOCUSIGN_BASE_URL=https://demo.docusign.net/restapi/v2.1
   DOCUSIGN_HMAC_KEY=your-hmac-secret-for-webhooks

   # SendGrid Email (Optional)
   SENDGRID_API_KEY=your-sendgrid-api-key

   # AWS S3 Configuration (Required for patient record storage)
   AWS_REGION=us-east-1
   AWS_S3_BUCKET_NAME=your-s3-bucket-name
   AWS_S3_FOLDER_PREFIX=patient-records
   # AWS Credentials (Optional - if not using IAM role)
   AWS_ACCESS_KEY_ID=your-aws-access-key-id
   AWS_SECRET_ACCESS_KEY=your-aws-secret-access-key
   ```

   **Note**: If running on AWS (EC2, ECS, Lambda), you can omit `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` and use IAM roles instead for better security.

4. **Set up the database**

   ```bash
   npm run db:push
   ```

5. **Start the development server**

   ```bash
   npm run dev
   ```

   The app will be available at `http://localhost:5000`

### Default Admin Account

On first run in development mode, you can create an admin account by:

1. Navigate to `/login`
2. Use the credentials set up by your team admin

## Project Structure

```
├── client/                 # Frontend React application
│   ├── src/
│   │   ├── components/     # Reusable UI components
│   │   ├── hooks/          # Custom React hooks
│   │   ├── lib/            # Utility functions
│   │   └── pages/          # Page components
├── server/                 # Backend Express application
│   ├── services/           # Business logic services
│   ├── routes.ts           # API route definitions
│   ├── storage.ts          # Database operations
│   └── index.ts            # Server entry point
├── shared/                 # Shared types and schemas
│   └── schema.ts           # Drizzle database schema
└── package.json
```

## API Routes

### Authentication

- `POST /api/auth/login` - Login with email/password
- `POST /api/auth/logout` - Logout current user
- `GET /api/auth/user` - Get current authenticated user

### Patients

- `GET /api/patients` - List all patients
- `POST /api/patients` - Create new patient
- `GET /api/patients/:id` - Get patient by ID
- `PUT /api/patients/:id` - Update patient
- `DELETE /api/patients/:id` - Delete patient

### Patient Records

- `GET /api/patients/:patientId/records` - List all records for a patient
- `POST /api/patients/:patientId/records` - Upload a new patient record (multipart/form-data)
- `GET /api/patients/:patientId/records/:recordId/download` - Download a patient record file
- `DELETE /api/patients/:patientId/records/:recordId` - Delete a patient record (Admin only)

### Tasks

- `GET /api/tasks` - List all tasks
- `POST /api/tasks` - Create new task
- `PUT /api/tasks/:id` - Update task
- `DELETE /api/tasks/:id` - Delete task

### Appointments

- `GET /api/appointments` - List appointments
- `POST /api/appointments` - Create appointment

### Users (Admin only)

- `GET /api/users` - List all users
- `POST /api/users` - Create new user
- `PUT /api/users/:id` - Update user

## Environment Setup for Production

### Google OAuth Configuration

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Navigate to "APIs & Services" > "Credentials"
4. Create OAuth 2.0 Client ID
5. Add authorized redirect URIs:
   - `https://your-domain.com/api/auth/google/callback`
6. Copy Client ID and Client Secret to environment variables

### DocuSign Webhook Configuration

1. Configure webhook URL: `https://your-domain.com/api/docusign/webhook`
2. Enable HMAC verification with your secret key
3. Set up Connect configuration in DocuSign admin

### AWS S3 Configuration

1. **Create an S3 Bucket**:

   - Go to [AWS S3 Console](https://console.aws.amazon.com/s3/)
   - Create a new bucket with a unique name
   - Enable server-side encryption (AES256)
   - Configure bucket policies for security

2. **Set up IAM Permissions** (Recommended):

   - Create an IAM user or role with the following permissions:
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
   - If using EC2/ECS/Lambda, attach the IAM role to your instance/service
   - If using access keys, set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in environment variables

3. **Environment Variables**:
   - `AWS_REGION`: AWS region where your bucket is located (e.g., `us-east-1`)
   - `AWS_S3_BUCKET_NAME`: Name of your S3 bucket
   - `AWS_S3_FOLDER_PREFIX`: Folder prefix for patient records (default: `patient-records`)
   - `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`: Only needed if not using IAM roles

## Development

### Available Scripts

- `npm run dev` - Start development server with hot reload
- `npm run build` - Build for production
- `npm run db:push` - Push schema changes to database
- `npm run db:studio` - Open Drizzle Studio for database management

### Code Style

- TypeScript for type safety
- ESLint for code linting
- Tailwind CSS for styling
- shadcn/ui components for consistent UI

## Security Considerations

- All sensitive data uses environment variables
- Session-based authentication with secure cookies
- HIPAA-compliant audit logging
- Role-based access control
- Input validation with Zod schemas

## Contributing

1. Create a feature branch
2. Make your changes
3. Test thoroughly
4. Submit a pull request

## License

Private - All rights reserved
