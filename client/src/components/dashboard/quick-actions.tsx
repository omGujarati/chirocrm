import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export default function QuickActions() {
  const actions = [
    {
      icon: "fas fa-user-plus",
      label: "Add New Patient",
      onClick: () => {
        const event = new CustomEvent('openAddPatientModal');
        window.dispatchEvent(event);
      },
      testId: "button-quick-add-patient"
    },
    {
      icon: "fas fa-file-signature",
      label: "Send Consent Forms",
      onClick: () => window.location.href = "/consent-forms",
      testId: "button-quick-consent-forms"
    },
    {
      icon: "fas fa-calendar-plus",
      label: "Schedule Appointment",
      onClick: () => window.location.href = "/schedule",
      testId: "button-quick-schedule"
    },
    {
      icon: "fas fa-download",
      label: "Export Reports",
      onClick: () => {
        // TODO: Implement export functionality
        // Non-PHI development logging
        if (import.meta.env.MODE === 'development') {
          console.log("Export reports functionality to be implemented");
        }
      },
      testId: "button-quick-export"
    },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Quick Actions</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {actions.map((action) => (
          <Button
            key={action.label}
            variant="ghost"
            className="w-full justify-start bg-accent hover:bg-accent/80"
            onClick={action.onClick}
            data-testid={action.testId}
          >
            <i className={`${action.icon} mr-3 text-muted-foreground`}></i>
            {action.label}
          </Button>
        ))}
      </CardContent>
    </Card>
  );
}
