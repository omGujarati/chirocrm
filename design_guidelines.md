# ChiroCareCRM Dashboard Design Guidelines

## Design Approach
Reference-based design inspired by **Sequence.io**: Modern SaaS dashboard with emphasis on data clarity, sophisticated hierarchy, and professional polish. Balances information density with breathing room through strategic use of whitespace and clear visual separation.

## Layout System

**Overall Structure:**
- Fixed sidebar (240px wide) on left with dark theme treatment
- Main content area uses full remaining width with light/neutral background
- Content container: max-w-7xl with px-8 for generous horizontal breathing room
- Vertical sections use py-8 spacing between major groups

**Spacing Primitives:**
Primary units: **2, 4, 6, 8, 12** (as in p-2, gap-4, mb-6, py-8, mt-12)
- Tight spacing: 2-4 for related elements
- Medium spacing: 6-8 for section separation
- Large spacing: 12 for major content blocks

## Typography

**Font Stack:**
- Primary: Inter (via Google Fonts) for UI elements, numbers, body text
- Weight hierarchy: 400 (regular), 500 (medium), 600 (semibold), 700 (bold)

**Scale:**
- Dashboard title/page headers: text-2xl font-semibold
- Stat card large numbers: text-4xl font-bold
- Stat card labels: text-sm font-medium uppercase tracking-wide
- Section headings: text-lg font-semibold
- Body/table text: text-sm font-normal
- Metric labels: text-xs font-medium uppercase tracking-wider

## Component Library

### Sidebar Navigation
- Logo area at top (h-16, centered logo with practice name below)
- Navigation items with icons (Heroicons via CDN)
- Active state: subtle background treatment with teal/green accent indicator (3px left border)
- Items include: Dashboard, Patients, Appointments, Treatments, Billing, Reports, Settings
- User profile section at bottom with avatar, name, role

### Stat Cards (Top Priority Section)
- Grid: grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6
- Card structure:
  - Large metric number (text-4xl font-bold)
  - Descriptive label above number (text-sm uppercase tracking-wide)
  - Percentage change indicator with up/down arrow icon (text-sm font-medium)
  - Small trend sparkline chart beneath (optional subtle visualization)
- Cards have subtle shadow (shadow-sm), rounded corners (rounded-lg), padding p-6
- Metrics: Total Patients, Active Treatments, Today's Appointments, Revenue MTD

### Activity/Trends Chart Section
- Full-width chart container below stat cards (mt-8)
- Chart header with title "Patient Activity Trends" + time period selector (7D/30D/90D/1Y tabs)
- Chart area: min-h-96 for substantial visual presence
- Use Chart.js or Recharts library for line/area chart implementation
- X-axis: Time periods, Y-axis: Patient visits/activities
- Multiple data series: New Patients, Follow-ups, Treatment Completions

### Summary Metric Cards (Bottom Section)
- Grid: grid-cols-1 md:grid-cols-3 gap-6 (mt-8)
- Smaller than top stat cards but same visual language
- Metrics: Average Session Duration, Patient Satisfaction Score, Appointment Fill Rate
- Include icon for each metric category

### Recent Activity Table
- Clean table design with hover states on rows
- Columns: Patient Name (with avatar), Type (badge component), Date/Time, Provider, Status (colored badge)
- Show 8-10 recent entries
- Table header: sticky with subtle background separation
- Cell padding: px-6 py-4 for comfortable density
- Action column: "View Details" link in teal/green accent

### Additional Dashboard Elements
- Page header area: Welcome message "Good morning, Dr. [Name]" + date (mb-8)
- Quick action buttons: "+ New Patient", "Schedule Appointment" (teal/green primary buttons, positioned top-right)
- Notifications bell icon with badge count (top-right corner)

## Interaction Patterns

**Micro-interactions:**
- Stat card hover: subtle lift (transform translate-y-1) + shadow increase
- Table row hover: background tint change
- Chart tooltips on hover showing exact values
- Smooth transitions (transition-all duration-200)

**No floating elements:** All components grounded with proper spacing and hierarchy

**Loading States:**
- Skeleton loaders for stat cards and chart during data fetch
- Shimmer animation for table rows

## Images
No images required for this dashboard interface. All visualizations handled through charts, icons, and data displays. User avatars in sidebar and table use initials-based placeholders or uploaded profile photos.