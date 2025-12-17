import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { useQuery } from "@tanstack/react-query";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { CalendarIcon, CalendarPlus, EditIcon } from "lucide-react";
import ScheduleConsultationModal from "@/components/modals/schedule-consultation-modal";
import { XIcon } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";

export default function Schedule() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading } = useAuth();
  const [isScheduleModalOpen, setIsScheduleModalOpen] = useState(false);
  const [editingAppointment, setEditingAppointment] = useState<any | null>(
    null
  );

  // Automatic redirect to login removed - App.tsx routing handles authentication redirects

  const { data: appointments = [], isLoading: appointmentsLoading } = useQuery<
    any[]
  >({
    queryKey: ["/api/appointments"],
    enabled: isAuthenticated, // SECURITY: Only fetch when authenticated
    retry: false,
  });

  // Fetch patient data when editing an appointment
  const { data: editingPatient } = useQuery({
    queryKey: ["/api/patients", editingAppointment?.patientId],
    queryFn: async () => {
      if (!editingAppointment?.patientId) return null;
      const response = await apiRequest(
        "GET",
        `/api/patients/${editingAppointment.patientId}`
      );
      const data = await response.json();
      // Handle paginated response
      return data.patients ? data.patients[0] : data;
    },
    enabled: !!editingAppointment?.patientId && isAuthenticated,
    retry: false,
  });

  const handleEditAppointment = (appointment: any) => {
    setEditingAppointment(appointment);
    setIsScheduleModalOpen(true);
  };

  const handleCloseModal = () => {
    setIsScheduleModalOpen(false);
    setEditingAppointment(null);
  };

  if (isLoading || !isAuthenticated) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex bg-background">
      <Sidebar />

      <main className="flex-1 flex flex-col overflow-hidden">
        <Header
          title="Appointment Scheduling"
          subtitle="Manage patient appointments and availability"
        />

        <div className="flex-1 overflow-auto p-6">
          <div className="mb-6 flex justify-between items-center">
            <div>
              <h2 className="text-xl font-semibold">Upcoming Appointments</h2>
              <p className="text-muted-foreground">
                Total: {appointments.length} appointments
              </p>
            </div>
            <Button
              data-testid="button-schedule-appointment"
              onClick={() => {
                setEditingAppointment(null);
                setIsScheduleModalOpen(true);
              }}
            >
              <CalendarPlus className="w-4 h-4 mr-2" />
              Schedule Appointment
            </Button>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Calendar View</CardTitle>
            </CardHeader>
            <CardContent>
              {appointmentsLoading ? (
                <div className="text-center py-8">
                  <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                  <p className="text-muted-foreground">
                    Loading appointments...
                  </p>
                </div>
              ) : appointments.length === 0 ? (
                <div className="flex flex-col items-center justify-center text-center py-8">
                  <CalendarIcon className="w-10 h-10 text-muted-foreground mb-4" />
                  <p className="text-muted-foreground">
                    No appointments scheduled
                  </p>
                  <p className="text-sm text-muted-foreground mt-2">
                    Note: Patients must have signed consent forms before
                    scheduling
                  </p>
                </div>
              ) : (
                <div className="space-y-4">
                  {appointments.map((appointment: any) => (
                    <div
                      key={appointment.id}
                      className="flex items-center justify-between p-4 border border-border rounded-lg"
                      data-testid={`appointment-item-${appointment.id}`}
                    >
                      <div className="flex items-center space-x-4">
                        <div className="w-10 h-10 bg-primary/10 rounded-full flex items-center justify-center">
                          <CalendarIcon className="w-4 h-4 text-primary" />
                        </div>
                        <div>
                          <h4 className="font-medium">
                            {new Date(
                              appointment.scheduledAt
                            ).toLocaleDateString()}{" "}
                            at{" "}
                            {new Date(
                              appointment.scheduledAt
                            ).toLocaleTimeString()}
                          </h4>
                          <p className="text-sm text-muted-foreground">
                            Duration: {appointment.duration} minutes
                          </p>
                          <p className="text-xs text-muted-foreground">
                            Status: {appointment.status}
                          </p>
                        </div>
                      </div>

                      <div className="flex space-x-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          title="Edit"
                          onClick={() => handleEditAppointment(appointment)}
                        >
                          <EditIcon className="w-4 h-4" />
                        </Button>
                        <Button variant="ghost" size="sm" title="Cancel">
                          <XIcon className="w-4 h-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </main>

      <ScheduleConsultationModal
        open={isScheduleModalOpen}
        onOpenChange={handleCloseModal}
        showPatients={!editingAppointment}
        patient={
          editingPatient
            ? (() => {
                const scheduledDate = editingAppointment?.scheduledAt
                  ? new Date(editingAppointment.scheduledAt)
                  : null;

                // Format time as HH:MM
                const formatTime = (date: Date) => {
                  const hours = date.getHours().toString().padStart(2, "0");
                  const minutes = date.getMinutes().toString().padStart(2, "0");
                  return `${hours}:${minutes}`;
                };

                return {
                  id: editingPatient.id,
                  firstName: editingPatient.firstName,
                  lastName: editingPatient.lastName,
                  status: editingPatient.status,
                  consultationDate: scheduledDate
                    ? scheduledDate.toISOString().split("T")[0]
                    : editingPatient.consultationDate,
                  consultationTime: scheduledDate
                    ? formatTime(scheduledDate)
                    : editingPatient.consultationTime,
                  consultationLocation:
                    editingAppointment?.notes ||
                    editingPatient.consultationLocation,
                };
              })()
            : undefined
        }
      />
    </div>
  );
}
