# ChiroCareCRM - HIPAA-Compliant Patient Management System

## Overview

ChiroCareCRM is a comprehensive patient management system designed specifically for chiropractic practices and law firms. The application provides HIPAA-compliant patient management, task assignments, audit logging, user management, role-based access control, and patient notes tracking. Built with modern web technologies, it offers a full-stack solution for healthcare practice management with features like consent form management, appointment scheduling, automated alerting systems, and timestamped patient notes with attorney visibility.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React with TypeScript for type safety and better developer experience
- **Routing**: Wouter for lightweight client-side routing
- **UI Library**: Radix UI components with shadcn/ui design system for consistent, accessible interface
- **Styling**: Tailwind CSS with custom CSS variables for theming support
- **State Management**: TanStack React Query for server state management and caching
- **Forms**: React Hook Form with Zod validation for type-safe form handling
- **Build Tool**: Vite for fast development and optimized production builds

### Backend Architecture
- **Runtime**: Node.js with Express.js framework
- **Language**: TypeScript for consistent typing across the stack
- **Authentication**: Replit OAuth integration with session-based authentication
- **Session Storage**: PostgreSQL-backed sessions using connect-pg-simple
- **API Design**: RESTful endpoints with consistent error handling and audit logging middleware

### Database Layer
- **Primary Database**: PostgreSQL with Drizzle ORM for type-safe database operations
- **Database Hosting**: Configured for both Neon Database and Supabase compatibility
- **Schema Management**: Drizzle Kit for migrations and schema management
- **Connection Pooling**: Neon serverless driver with WebSocket support for optimal performance

### Key Data Models
- **Users**: Role-based system (admin/staff/attorney) with authentication integration
- **Patients**: Complete patient records with status tracking through consent workflow
- **Tasks**: Assignment system with priorities, status tracking, and user relationships
- **Appointments**: Scheduling system linked to patients
- **Patient Notes**: Timestamped notes system with role-based visibility and categorization
- **Audit Logs**: Comprehensive activity tracking for HIPAA compliance
- **Alerts**: Notification system for time-sensitive actions

### Authentication & Authorization
- **Provider**: Replit OAuth for secure authentication
- **Session Management**: Server-side sessions with PostgreSQL storage
- **Role-Based Access**: Admin and staff roles with different permission levels
- **HIPAA Compliance**: Audit logging for all user actions and data access

### Business Logic Features
- **Consent Management**: Automated consent form workflow with DocuSign integration
- **Alert System**: Time-based notifications for pending consents and overdue tasks
- **Email Notifications**: SendGrid integration for automated communications
- **Status Tracking**: Patient lifecycle management from initial contact to schedulable status

## External Dependencies

### Core Dependencies
- **@neondatabase/serverless**: Database connectivity with serverless support
- **drizzle-orm**: Type-safe ORM for PostgreSQL operations
- **@tanstack/react-query**: Client-side data fetching and caching
- **@radix-ui/react-***: Comprehensive UI component library for accessibility

### Development & Build Tools
- **Vite**: Modern build tool with HMR and optimized bundling
- **TypeScript**: Static typing for both client and server code
- **Tailwind CSS**: Utility-first CSS framework with custom design system
- **ESBuild**: Fast JavaScript bundler for production builds

### External Services Integration
- **Replit Authentication**: OAuth provider for user authentication
- **Google OAuth**: Google OAuth2 authentication for user login
- **DocuSign API**: Electronic signature service for consent forms (configurable)
- **SendGrid**: Email service for automated notifications (configurable)
- **PostgreSQL**: Primary database (supports Neon Database and Supabase)

## CRITICAL: Google OAuth Configuration Required

**⚠️ IMPORTANT: You must configure Google Cloud Console OAuth client settings for authentication to work.**

### Google Cloud Console Setup:

1. **Create OAuth 2.0 Client**:
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Navigate to "APIs & Services" → "Credentials" 
   - Click "Create Credentials" → "OAuth 2.0 Client IDs"
   - Application type: **Web application**

2. **Configure OAuth Consent Screen**:
   - Navigate to "APIs & Services" → "OAuth consent screen"
   - Choose **External** user type (most common)
   - For **Testing**: Add your email address in "Test users" section
   - For **Production**: Complete app verification and publish to production

3. **Configure Authorized Origins** (use your actual deployed domain):
   ```
   https://[your-replit-domain].replit.app
   http://localhost:5000
   ```

4. **Configure Authorized Redirect URIs** (use your actual deployed domain):
   ```
   https://[your-replit-domain].replit.app/api/auth/google/callback
   http://localhost:5000/api/auth/google/callback
   ```

5. **Update Environment Variables**:
   - Copy your Client ID to `GOOGLE_CLIENT_ID` secret
   - Copy your Client Secret to `GOOGLE_CLIENT_SECRET` secret

### Important Testing Notes:
- **Always test from the top-level app URL** (e.g., `https://[domain].replit.app`), not from Replit's embedded preview
- **Update Google Cloud config** whenever your domain changes
- **Add test users** in Google Console if using Testing mode

**Note**: Session configuration has been centralized and optimized for OAuth compatibility. The system uses `sameSite: 'none'` cookies with proper security settings for cross-site authentication.

### Development Environment
- **Replit Platform**: Integrated development environment with runtime error handling
- **WebSocket Support**: Real-time capabilities for database connections
- **Session Management**: Production-ready session handling with PostgreSQL storage