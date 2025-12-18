import { useState, useEffect, useRef } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { z } from "zod";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useQuery } from "@tanstack/react-query";

interface ScheduleConsultationModalProps {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  patient?: {
    id: string;
    firstName: string;
    lastName: string;
    status: string;
    consultationDate?: string | null;
    consultationTime?: string | null;
    consultationLocation?: string | null;
  };
  appointment?: {
    id: string;
    patientId: string;
    scheduledAt: string;
    duration: number;
    status: string;
    notes?: string | null;
  };
  showPatients?: boolean;
}

const baseFormSchema = z.object({
  consultationDate: z.coerce.date().refine(
    (date) => {
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      const selectedDate = new Date(date);
      selectedDate.setHours(0, 0, 0, 0);
      return selectedDate >= today;
    },
    {
      message: "Consultation date must be today or in the future",
    }
  ),
  consultationTime: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/, {
    message: "Time must be in HH:MM format",
  }),
  consultationLocation: z.string().min(1, "Location is required"),
  patientId: z.string().optional(),
});

type FormData = z.infer<typeof baseFormSchema>;

export default function ScheduleConsultationModal({
  open,
  onOpenChange,
  patient,
  appointment,
  showPatients = false,
}: ScheduleConsultationModalProps) {
  const [isOpen, setIsOpen] = useState(open || false);
  const [selectedPatientId, setSelectedPatientId] = useState<string>(
    patient?.id || appointment?.patientId || ""
  );
  const { toast } = useToast();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const lastProcessedPatientId = useRef<string | null>(null);

  // Determine if we're editing an appointment
  const isEditingAppointment = !!appointment;

  // Fetch patients when showPatients is true
  const { data: patientsData } = useQuery({
    queryKey: ["/api/patients", "for-scheduling"],
    queryFn: async () => {
      try {
        // Fetch all patients with high limit for dropdown
        const url = `/api/patients?page=1&limit=100`;
        const response = await apiRequest("GET", url);
        const data = await response.json();

        // Handle backward compatibility: if response is an array (old format), convert it
        if (Array.isArray(data)) {
          return {
            patients: data,
            pagination: {
              page: 1,
              limit: data.length,
              total: data.length,
              totalPages: 1,
            },
          };
        }

        // New format - ensure it has the expected structure
        if (!data.patients || !data.pagination) {
          console.error("Invalid response format:", data);
          throw new Error(
            "Invalid response format from server. Expected { patients: [], pagination: {} }"
          );
        }
        return data;
      } catch (error: any) {
        console.error("Error fetching patients:", error);
        throw new Error(error.message || "Failed to fetch patients");
      }
    },
    enabled: showPatients && isOpen,
    retry: false,
  });

  const patients = patientsData?.patients || [];
  const selectedPatient = showPatients
    ? patients.find((p: any) => p.id === selectedPatientId) || patient
    : patient;

  // Fetch patient data when editing appointment (if not already provided)
  const { data: appointmentPatient } = useQuery({
    queryKey: ["/api/patients", appointment?.patientId],
    queryFn: async () => {
      if (!appointment?.patientId) return null;
      const response = await apiRequest(
        "GET",
        `/api/patients/${appointment.patientId}`
      );
      const data = await response.json();
      return data.patients ? data.patients[0] : data;
    },
    enabled: isEditingAppointment && !!appointment?.patientId && !patient,
    retry: false,
  });

  // Use appointmentPatient if patient is not provided
  const effectivePatient = patient || appointmentPatient;

  useEffect(() => {
    if (open !== undefined) {
      setIsOpen(open);
    }
    // Reset the ref when modal opens/closes
    if (!open) {
      lastProcessedPatientId.current = null;
    }
  }, [open]);

  const form = useForm<FormData>({
    resolver: zodResolver(baseFormSchema),
    defaultValues: {
      patientId: effectivePatient?.id || appointment?.patientId || "",
      consultationDate: appointment?.scheduledAt
        ? new Date(appointment.scheduledAt)
        : effectivePatient?.consultationDate
        ? new Date(effectivePatient.consultationDate)
        : undefined,
      consultationTime: appointment?.scheduledAt
        ? new Date(appointment.scheduledAt).toLocaleTimeString("en-US", {
            hour12: false,
            hour: "2-digit",
            minute: "2-digit",
          })
        : effectivePatient?.consultationTime || "",
      consultationLocation:
        appointment?.notes || effectivePatient?.consultationLocation || "",
    },
  });

  // Reset form when patient or appointment prop changes
  useEffect(() => {
    if (isEditingAppointment && appointment) {
      const scheduledDate = new Date(appointment.scheduledAt);
      form.reset({
        patientId: appointment.patientId,
        consultationDate: scheduledDate,
        consultationTime: scheduledDate.toLocaleTimeString("en-US", {
          hour12: false,
          hour: "2-digit",
          minute: "2-digit",
        }),
        consultationLocation: appointment.notes || "",
      });
      setSelectedPatientId(appointment.patientId);
    } else if (!showPatients && effectivePatient) {
      form.reset({
        patientId: effectivePatient.id,
        consultationDate: effectivePatient.consultationDate
          ? new Date(effectivePatient.consultationDate)
          : undefined,
        consultationTime: effectivePatient.consultationTime || "",
        consultationLocation: effectivePatient.consultationLocation || "",
      });
      setSelectedPatientId(effectivePatient.id);
    }
  }, [
    effectivePatient?.id,
    appointment?.id,
    showPatients,
    isEditingAppointment,
  ]);

  // Update form when selectedPatientId changes (only in showPatients mode)
  useEffect(() => {
    // Prevent infinite loop by checking if we've already processed this patient ID
    if (lastProcessedPatientId.current === selectedPatientId) {
      return;
    }

    if (showPatients && selectedPatientId) {
      const selectedPat = patients.find((p: any) => p.id === selectedPatientId);
      if (selectedPat) {
        lastProcessedPatientId.current = selectedPatientId;
        form.reset({
          patientId: selectedPat.id,
          consultationDate: selectedPat.consultationDate
            ? new Date(selectedPat.consultationDate)
            : undefined,
          consultationTime: selectedPat.consultationTime || "",
          consultationLocation: selectedPat.consultationLocation || "",
        });
      }
    } else if (showPatients && !selectedPatientId) {
      lastProcessedPatientId.current = "";
      form.reset({
        patientId: "",
        consultationDate: undefined,
        consultationTime: "",
        consultationLocation: "",
      });
    }
  }, [selectedPatientId, showPatients, patients]);

  const scheduleConsultationMutation = useMutation({
    mutationFn: async (data: FormData) => {
      // Extract appointment patientId before type narrowing
      const appointmentPatientId = appointment?.patientId || "";

      // If editing an appointment, use appointment update endpoint
      if (isEditingAppointment && appointment) {
        // Combine date and time into scheduledAt timestamp
        const [hours, minutes] = data.consultationTime.split(":").map(Number);
        const scheduledDate = new Date(data.consultationDate);
        scheduledDate.setHours(hours, minutes, 0, 0);

        const response = await apiRequest(
          "PUT",
          `/api/appointments/${appointment.id}`,
          {
            scheduledAt: scheduledDate.toISOString(),
            duration: appointment.duration || 60,
            notes: data.consultationLocation || null,
          }
        );
        return response.json();
      }

      // Otherwise, use patient schedule endpoint
      const patientIdToUse = showPatients
        ? data.patientId || ""
        : effectivePatient?.id || appointmentPatientId || "";
      if (!patientIdToUse) throw new Error("No patient selected");

      if (showPatients && !data.patientId) {
        throw new Error("Please select a patient");
      }

      const response = await apiRequest(
        "PUT",
        `/api/patients/${patientIdToUse}/schedule`,
        {
          consultationDate: data.consultationDate.toISOString(),
          consultationTime: data.consultationTime,
          consultationLocation: data.consultationLocation,
        }
      );
      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/patients"] });
      queryClient.invalidateQueries({ queryKey: ["/api/appointments"] });
      toast({
        title: "Success",
        description:
          data.message ||
          (isEditingAppointment
            ? "Appointment updated successfully"
            : "Consultation scheduled successfully"),
      });
      setIsOpen(false);
      onOpenChange?.(false);
      form.reset();
      setSelectedPatientId(
        effectivePatient?.id || appointment?.patientId || ""
      );
    },
    onError: (error: any) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Unauthorized",
          description: "You are not logged in",
          variant: "destructive",
        });
        return;
      }

      toast({
        title: "Error",
        description: error.message || "Failed to schedule consultation",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: FormData) => {
    if (showPatients && !data.patientId) {
      form.setError("patientId", {
        type: "manual",
        message: "Please select a patient",
      });
      return;
    }
    scheduleConsultationMutation.mutate(data);
  };

  const handleClose = () => {
    setIsOpen(false);
    onOpenChange?.(false);
    form.reset();
    setSelectedPatientId(effectivePatient?.id || appointment?.patientId || "");
  };

  // Check if user can schedule based on role and patient status
  const canSchedule = (pat: typeof selectedPatient) => {
    if (!user || !pat) return false;

    // Admin can always schedule
    if (user.role === "admin") return true;

    // Staff can only schedule when patient status is 'consent_signed' or 'schedulable'
    if (user.role === "staff" || user.role === "attorney") {
      return pat.status === "consent_signed" || pat.status === "schedulable";
    }

    return false;
  };

  // When showPatients is true, we need a patient selected
  // When showPatients is false, we need the patient prop
  // If editing an appointment, always show the modal
  if (showPatients) {
    // Modal should show, but validation happens in form
    // Don't return null, just show the form
  } else if (isEditingAppointment) {
    // When editing appointment, always show modal (even if patient is still loading)
  } else if (!effectivePatient || !canSchedule(effectivePatient)) {
    return null;
  }

  const isUpdateMode =
    isEditingAppointment ||
    (selectedPatient
      ? !!(
          selectedPatient.consultationDate &&
          selectedPatient.consultationTime &&
          selectedPatient.consultationLocation
        )
      : false);

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent
        className="w-[95vw] max-w-[95vw] sm:max-w-md md:max-w-md max-h-[95vh] overflow-auto rounded-lg p-4 sm:p-6 sm:m-0 flex flex-col"
        data-testid="modal-schedule-consultation"
      >
        <DialogHeader>
          <DialogTitle data-testid="title-schedule-consultation">
            {isEditingAppointment
              ? "Edit"
              : isUpdateMode
              ? "Update"
              : "Schedule"}{" "}
            {isEditingAppointment ? "Appointment" : "Consultation"}
            {(selectedPatient || effectivePatient) &&
              ` for ${(selectedPatient || effectivePatient)?.firstName} ${
                (selectedPatient || effectivePatient)?.lastName
              }`}
          </DialogTitle>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
            <div className="space-y-4">
              {showPatients && (
                <FormField
                  control={form.control}
                  name="patientId"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Select Patient *</FormLabel>
                      <Select
                        onValueChange={(value) => {
                          field.onChange(value);
                          setSelectedPatientId(value);
                        }}
                        value={field.value}
                      >
                        <FormControl>
                          <SelectTrigger data-testid="select-patient-for-schedule">
                            <SelectValue placeholder="Choose a patient" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {patients
                            .filter(
                              (p: any) =>
                                p.status === "consent_signed" ||
                                p.status === "schedulable"
                            )
                            .map((p: any) => (
                              <SelectItem key={p.id} value={p.id}>
                                {p.firstName} {p.lastName} ({p.email})
                              </SelectItem>
                            ))}
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              )}
              <FormField
                control={form.control}
                name="consultationDate"
                render={({ field }) => {
                  // Helper function to format date in local timezone (YYYY-MM-DD)
                  const formatDateLocal = (date: Date): string => {
                    const year = date.getFullYear();
                    const month = String(date.getMonth() + 1).padStart(2, "0");
                    const day = String(date.getDate()).padStart(2, "0");
                    return `${year}-${month}-${day}`;
                  };

                  const today = formatDateLocal(new Date());
                  const fieldValue = field.value
                    ? field.value instanceof Date
                      ? formatDateLocal(field.value)
                      : formatDateLocal(new Date(field.value))
                    : "";

                  return (
                    <FormItem>
                      <FormLabel>Consultation Date *</FormLabel>
                      <FormControl>
                        <Input
                          type="date"
                          min={today}
                          value={fieldValue}
                          onChange={(e) => {
                            const dateValue = e.target.value;
                            if (dateValue) {
                              // Create date at midnight in local timezone to avoid timezone issues
                              const [year, month, day] = dateValue
                                .split("-")
                                .map(Number);
                              const date = new Date(year, month - 1, day);
                              field.onChange(date);
                            } else {
                              field.onChange(undefined);
                            }
                          }}
                          onBlur={field.onBlur}
                          name={field.name}
                          data-testid="input-consultation-date"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  );
                }}
              />

              <FormField
                control={form.control}
                name="consultationTime"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Consultation Time *</FormLabel>
                    <FormControl>
                      <Input
                        type="time"
                        {...field}
                        placeholder="14:30"
                        data-testid="input-consultation-time"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="consultationLocation"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Consultation Location *</FormLabel>
                    <FormControl>
                      <Textarea
                        placeholder="Enter consultation location (office address, room number, or virtual meeting link)"
                        {...field}
                        rows={3}
                        data-testid="input-consultation-location"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <div className="flex justify-end space-x-2">
              <Button
                type="button"
                variant="outline"
                onClick={handleClose}
                data-testid="button-cancel-schedule"
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={scheduleConsultationMutation.isPending}
                data-testid="button-save-schedule"
              >
                {scheduleConsultationMutation.isPending
                  ? "Scheduling..."
                  : isUpdateMode
                  ? "Update"
                  : "Schedule"}
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
