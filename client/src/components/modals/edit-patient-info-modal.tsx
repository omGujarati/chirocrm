import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { apiRequest } from "@/lib/queryClient";
import { isUnauthorizedError } from "@/lib/authUtils";
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
import { Button } from "@/components/ui/button";
import { z } from "zod";
import { Save, User } from "lucide-react";

const patientInfoSchema = z.object({
  firstName: z.string().min(1, "First name is required"),
  lastName: z.string().min(1, "Last name is required"),
  email: z.string().email("Valid email is required"),
  phone: z.string().optional(),
  dateOfBirth: z.coerce.date().optional().nullable(),
  dateOfInjury: z.coerce.date().optional().nullable(),
});

type PatientInfoFormData = z.infer<typeof patientInfoSchema>;

interface EditPatientInfoModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  patient: {
    id: string;
    firstName: string;
    lastName: string;
    email: string;
    phone?: string | null;
    dateOfBirth?: string | Date | null;
    dateOfInjury?: string | Date | null;
  };
}

export default function EditPatientInfoModal({
  open,
  onOpenChange,
  patient,
}: EditPatientInfoModalProps) {
  const { toast } = useToast();
  const { user } = useAuth();
  const queryClient = useQueryClient();

  const form = useForm<PatientInfoFormData>({
    resolver: zodResolver(patientInfoSchema),
    defaultValues: {
      firstName: patient?.firstName || "",
      lastName: patient?.lastName || "",
      email: patient?.email || "",
      phone: patient?.phone || "",
      dateOfBirth: patient?.dateOfBirth
        ? new Date(patient.dateOfBirth)
        : undefined,
      dateOfInjury: patient?.dateOfInjury
        ? new Date(patient.dateOfInjury)
        : undefined,
    },
  });

  // Update form when patient changes
  useEffect(() => {
    if (patient && open) {
      form.reset({
        firstName: patient?.firstName || "",
        lastName: patient?.lastName || "",
        email: patient?.email || "",
        phone: patient?.phone || "",
        dateOfBirth: patient?.dateOfBirth
          ? new Date(patient.dateOfBirth)
          : undefined,
        dateOfInjury: patient?.dateOfInjury
          ? new Date(patient.dateOfInjury)
          : undefined,
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [patient, open]);

  // Update patient information mutation (admin/staff only)
  const updatePatientInfoMutation = useMutation({
    mutationFn: async (data: PatientInfoFormData) => {
      return await apiRequest("PUT", `/api/patients/${patient.id}`, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/patients"] });
      onOpenChange(false);
      form.reset();
      toast({
        title: "Success",
        description: "Patient information updated successfully",
      });
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
        description: error.message || "Failed to update patient information",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: PatientInfoFormData) => {
    updatePatientInfoMutation.mutate(data);
  };

  const handleOpenChange = (newOpen: boolean) => {
    if (!newOpen) {
      form.reset();
    }
    onOpenChange(newOpen);
  };

  // Only show for admin and staff
  if (user?.role !== "admin" && user?.role !== "staff") {
    return null;
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent
        className="w-[95vw] max-w-[95vw] sm:max-w-md md:max-w-lg max-h-[95vh] overflow-auto rounded-lg p-4 sm:p-6 sm:m-0"
        data-testid="modal-edit-patient-info"
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <User className="w-5 h-5" />
            Edit Patient Information
          </DialogTitle>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="firstName"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>First Name *</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="First name"
                        {...field}
                        data-testid="input-patient-first-name"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="lastName"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Last Name *</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="Last name"
                        {...field}
                        data-testid="input-patient-last-name"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>
            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Email *</FormLabel>
                  <FormControl>
                    <Input
                      type="email"
                      placeholder="patient@email.com"
                      {...field}
                      data-testid="input-patient-email"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="phone"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Phone</FormLabel>
                  <FormControl>
                    <Input
                      type="tel"
                      placeholder="+1 (555) 123-4567"
                      {...field}
                      value={field.value || ""}
                      data-testid="input-patient-phone"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="dateOfBirth"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Date of Birth</FormLabel>
                    <FormControl>
                      <Input
                        type="date"
                        value={
                          field.value
                            ? new Date(field.value).toISOString().split("T")[0]
                            : ""
                        }
                        max={new Date().toISOString().split("T")[0]}
                        onChange={(e) => {
                          const date = e.target.value
                            ? new Date(e.target.value)
                            : undefined;
                          field.onChange(date);
                        }}
                        data-testid="input-patient-dob"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="dateOfInjury"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Date of Injury</FormLabel>
                    <FormControl>
                      <Input
                        type="date"
                        value={
                          field.value
                            ? new Date(field.value).toISOString().split("T")[0]
                            : ""
                        }
                        max={new Date().toISOString().split("T")[0]}
                        onChange={(e) => {
                          const date = e.target.value
                            ? new Date(e.target.value)
                            : undefined;
                          field.onChange(date);
                        }}
                        data-testid="input-patient-date-of-injury"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => handleOpenChange(false)}
                disabled={updatePatientInfoMutation.isPending}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={updatePatientInfoMutation.isPending}
                data-testid="button-save-patient-info"
              >
                <Save className="w-4 h-4 mr-2" />
                Save Changes
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
