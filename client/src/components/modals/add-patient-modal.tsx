import { useState, useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQueryClient, useQuery } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { insertPatientSchema } from "@shared/schema";
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

interface AddPatientModalProps {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}

const formSchema = insertPatientSchema.omit({
  createdBy: true, // This will be set automatically by the backend based on authenticated user
  assignedAttorney: true, // This will be set automatically to the creator by the backend
}).extend({
  firstName: z.string().min(1, "First name is required"),
  lastName: z.string().min(1, "Last name is required"),
  email: z.string().email("Valid email is required"),
});

export default function AddPatientModal({ open, onOpenChange }: AddPatientModalProps) {
  const [isOpen, setIsOpen] = useState(open || false);
  const { toast } = useToast();
  const { user } = useAuth();
  const queryClient = useQueryClient();

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      firstName: "",
      lastName: "",
      email: "",
      phone: "",
      address: "",
      dateOfBirth: undefined,
      dateOfInjury: undefined,
      status: "pending_consent",
    },
  });

  const createPatientMutation = useMutation({
    mutationFn: async (data: z.infer<typeof formSchema>) => {
      // PHI removed from console logs for HIPAA compliance
      if (import.meta.env.MODE === 'development') {
        console.log("Patient creation mutation initiated");
      }
      await apiRequest("POST", "/api/patients", data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/patients"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/stats"] });
      toast({
        title: "Success",
        description: "Patient added successfully",
      });
      form.reset();
      handleClose();
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
      
      // Show specific server error message
      let errorMessage = "Failed to add patient";
      if (error.message?.includes("duplicate key")) {
        errorMessage = "A patient with this email address already exists";
      } else if (error.message) {
        errorMessage = error.message;
      }
      
      toast({
        title: "Error",
        description: errorMessage,
        variant: "destructive",
      });
    },
  });

  const handleClose = () => {
    setIsOpen(false);
    onOpenChange?.(false);
    form.reset();
  };

  const onSubmit = (data: z.infer<typeof formSchema>) => {
    // PHI removed from console logs for HIPAA compliance
    if (import.meta.env.MODE === 'development') {
      console.log("Form submission attempted");
      console.log("Form validation errors:", form.formState.errors);
    }
    createPatientMutation.mutate(data);
  };

  // Listen for global event to open modal
  useEffect(() => {
    const handleOpenModal = () => {
      setIsOpen(true);
      onOpenChange?.(true);
    };

    window.addEventListener('openAddPatientModal', handleOpenModal);
    return () => window.removeEventListener('openAddPatientModal', handleOpenModal);
  }, [onOpenChange]);

  // Update internal state when prop changes
  useEffect(() => {
    if (open !== undefined) {
      setIsOpen(open);
    }
  }, [open]);

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="w-[95vw] max-w-[95vw] sm:max-w-md md:max-w-lg max-h-[95vh] overflow-auto rounded-lg p-4 sm:p-6 sm:m-0" data-testid="modal-add-patient">
        <DialogHeader>
          <DialogTitle>Add New Patient</DialogTitle>
        </DialogHeader>
        
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <FormField
                control={form.control}
                name="firstName"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>First Name *</FormLabel>
                    <FormControl>
                      <Input 
                        placeholder="Enter first name" 
                        {...field} 
                        onChange={(e) => {
                          field.onChange(
                            e.target.value.charAt(0).toUpperCase() +
                              e.target.value.slice(1).toLowerCase()
                          );
                        }}
                        data-testid="input-first-name"
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
                        placeholder="Enter last name" 
                        {...field}
                        onChange={(e) => {
                          field.onChange(
                            e.target.value.charAt(0).toUpperCase() +
                              e.target.value.slice(1).toLowerCase()
                          );
                        }}
                        data-testid="input-last-name"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
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
                        data-testid="input-email"
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
                        data-testid="input-phone"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <FormField
                control={form.control}
                name="dateOfBirth"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Date of Birth</FormLabel>
                    <FormControl>
                      <Input 
                        type="date" 
                        {...field} 
                        value={field.value ? new Date(field.value).toISOString().split('T')[0] : ''}
                        onChange={(e) => {
                          const date = e.target.value ? new Date(e.target.value) : undefined;
                          field.onChange(date);
                        }}
                        data-testid="input-date-of-birth"
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
                        {...field} 
                        value={field.value ? new Date(field.value).toISOString().split('T')[0] : ''}
                        onChange={(e) => {
                          const date = e.target.value ? new Date(e.target.value) : undefined;
                          field.onChange(date);
                        }}
                        data-testid="input-date-of-injury"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>
            
            <FormField
              control={form.control}
              name="address"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Address</FormLabel>
                  <FormControl>
                    <Textarea 
                      rows={3}
                      placeholder="Enter patient address" 
                      {...field} 
                      value={field.value || ""}
                      data-testid="input-address"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            
            <FormField
              control={form.control}
              name="status"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Initial Status</FormLabel>
                  <Select onValueChange={field.onChange} defaultValue={field.value}>
                    <FormControl>
                      <SelectTrigger data-testid="select-initial-status">
                        <SelectValue placeholder="Select initial status" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="pending_consent">Pending Consent</SelectItem>
                      <SelectItem value="consent_sent">Consent Sent</SelectItem>
                      <SelectItem value="consent_signed">Consent Signed</SelectItem>
                      <SelectItem value="schedulable">Schedulable</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />
            
            <div className="flex items-center justify-end space-x-4 pt-4">
              <Button 
                type="button" 
                variant="outline" 
                onClick={handleClose}
                data-testid="button-cancel-add-patient"
              >
                Cancel
              </Button>
              <Button 
                type="submit" 
                disabled={createPatientMutation.isPending}
                onClick={(e) => {
                  // PHI removed from console logs for HIPAA compliance
                  if (import.meta.env.MODE === 'development') {
                    console.log("Submit button clicked");
                    console.log("Form valid?", form.formState.isValid);
                  }
                }}
                data-testid="button-submit-add-patient"
              >
                {createPatientMutation.isPending ? (
                  <>
                    <div className="w-4 h-4 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin mr-2"></div>
                    Adding...
                  </>
                ) : (
                  "Add Patient"
                )}
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
