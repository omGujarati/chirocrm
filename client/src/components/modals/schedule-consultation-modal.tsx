import { useState, useEffect } from "react";
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
  showPatients?: boolean;
}

const baseFormSchema = z.object({
  consultationDate: z.coerce.date().refine((date) => date > new Date(), {
    message: "Consultation date must be in the future"
  }),
  consultationTime: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/, {
    message: "Time must be in HH:MM format"
  }),
  consultationLocation: z.string().min(1, "Location is required"),
  patientId: z.string().optional(),
});

type FormData = z.infer<typeof baseFormSchema>;

export default function ScheduleConsultationModal({ 
  open, 
  onOpenChange, 
  patient,
  showPatients = false
}: ScheduleConsultationModalProps) {
  const [isOpen, setIsOpen] = useState(open || false);
  const [selectedPatientId, setSelectedPatientId] = useState<string>(patient?.id || "");
  const { toast } = useToast();
  const { user } = useAuth();
  const queryClient = useQueryClient();

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
          throw new Error("Invalid response format from server. Expected { patients: [], pagination: {} }");
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

  useEffect(() => {
    if (open !== undefined) {
      setIsOpen(open);
    }
  }, [open]);

  const form = useForm<FormData>({
    resolver: zodResolver(baseFormSchema),
    defaultValues: {
      patientId: patient?.id || "",
      consultationDate: patient?.consultationDate ? new Date(patient.consultationDate) : undefined,
      consultationTime: patient?.consultationTime || "",
      consultationLocation: patient?.consultationLocation || "",
    },
  });

  // Reset form when patient changes
  useEffect(() => {
    const currentPatient = showPatients && selectedPatientId 
      ? patients.find((p: any) => p.id === selectedPatientId) 
      : patient;
    
    if (currentPatient) {
      form.reset({
        patientId: currentPatient.id,
        consultationDate: currentPatient.consultationDate ? new Date(currentPatient.consultationDate) : undefined,
        consultationTime: currentPatient.consultationTime || "",
        consultationLocation: currentPatient.consultationLocation || "",
      });
      setSelectedPatientId(currentPatient.id);
    } else if (showPatients) {
      form.reset({
        patientId: "",
        consultationDate: undefined,
        consultationTime: "",
        consultationLocation: "",
      });
      setSelectedPatientId("");
    }
  }, [patient, selectedPatientId, showPatients, patients, form]);

  // Update selectedPatientId when form patientId changes
  const watchedPatientId = form.watch("patientId");
  useEffect(() => {
    if (showPatients && watchedPatientId) {
      setSelectedPatientId(watchedPatientId);
    }
  }, [watchedPatientId, showPatients]);

  const scheduleConsultationMutation = useMutation({
    mutationFn: async (data: FormData) => {
      const patientIdToUse = showPatients ? (data.patientId || "") : (patient?.id || "");
      if (!patientIdToUse) throw new Error("No patient selected");
      
      if (showPatients && !data.patientId) {
        throw new Error("Please select a patient");
      }
      
      const response = await apiRequest("PUT", `/api/patients/${patientIdToUse}/schedule`, {
        consultationDate: data.consultationDate.toISOString(),
        consultationTime: data.consultationTime,
        consultationLocation: data.consultationLocation,
      });
      return response.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/patients"] });
      queryClient.invalidateQueries({ queryKey: ["/api/appointments"] });
      toast({
        title: "Success",
        description: data.message || "Consultation scheduled successfully",
      });
      setIsOpen(false);
      onOpenChange?.(false);
      form.reset();
      setSelectedPatientId(patient?.id || "");
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
        message: "Please select a patient"
      });
      return;
    }
    scheduleConsultationMutation.mutate(data);
  };

  const handleClose = () => {
    setIsOpen(false);
    onOpenChange?.(false);
    form.reset();
    setSelectedPatientId(patient?.id || "");
  };

  // Check if user can schedule based on role and patient status
  const canSchedule = (pat: typeof selectedPatient) => {
    if (!user || !pat) return false;
    
    // Admin can always schedule
    if (user.role === 'admin') return true;
    
    // Staff can only schedule when patient status is 'consent_signed' or 'schedulable'
    if (user.role === 'staff' || user.role === 'attorney') {
      return pat.status === 'consent_signed' || pat.status === 'schedulable';
    }
    
    return false;
  };

  // When showPatients is true, we need a patient selected
  // When showPatients is false, we need the patient prop
  if (showPatients) {
    // Modal should show, but validation happens in form
    // Don't return null, just show the form
  } else if (!patient || !canSchedule(patient)) {
    return null;
  }

  const isUpdateMode = selectedPatient ? !!(selectedPatient.consultationDate && selectedPatient.consultationTime && selectedPatient.consultationLocation) : false;

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="w-[95vw] max-w-[95vw] sm:max-w-md md:max-w-md max-h-[95vh] overflow-auto rounded-lg p-4 sm:p-6 sm:m-0 flex flex-col" data-testid="modal-schedule-consultation">
        <DialogHeader>
          <DialogTitle data-testid="title-schedule-consultation">
            {isUpdateMode ? 'Update' : 'Schedule'} Consultation
            {selectedPatient && ` for ${selectedPatient.firstName} ${selectedPatient.lastName}`}
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
                          const selectedPat = patients.find((p: any) => p.id === value);
                          if (selectedPat) {
                            form.reset({
                              ...form.getValues(),
                              patientId: value,
                              consultationDate: selectedPat.consultationDate ? new Date(selectedPat.consultationDate) : undefined,
                              consultationTime: selectedPat.consultationTime || "",
                              consultationLocation: selectedPat.consultationLocation || "",
                            });
                          }
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
                            .filter((p: any) => 
                              p.status === 'consent_signed' || 
                              p.status === 'schedulable'
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
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Consultation Date *</FormLabel>
                    <FormControl>
                      <Input 
                        type="date" 
                        {...field} 
                        value={field.value ? new Date(field.value).toISOString().split('T')[0] : ''}
                        onChange={(e) => {
                          const date = e.target.value ? new Date(e.target.value) : undefined;
                          field.onChange(date);
                        }}
                        data-testid="input-consultation-date"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
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
                {scheduleConsultationMutation.isPending ? "Scheduling..." : (isUpdateMode ? "Update" : "Schedule")}
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}