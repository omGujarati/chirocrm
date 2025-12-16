import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
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
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { AlertTriangle } from "lucide-react";

interface DropPatientModalProps {
  patient?: {
    id: string;
    firstName: string;
    lastName: string;
    status: string;
  } | null;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}

const dropFormSchema = z.object({
  dropReason: z.string()
    .min(10, "Drop reason must be at least 10 characters")
    .max(1000, "Drop reason must be less than 1000 characters"),
});

export default function DropPatientModal({ patient, open, onOpenChange }: DropPatientModalProps) {
  const [isOpen, setIsOpen] = useState(open || false);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const form = useForm<z.infer<typeof dropFormSchema>>({
    resolver: zodResolver(dropFormSchema),
    defaultValues: {
      dropReason: "",
    },
  });

  const dropPatientMutation = useMutation({
    mutationFn: async (data: { dropReason: string }) => {
      if (!patient?.id) throw new Error("No patient selected");
      return apiRequest("POST", `/api/patients/${patient.id}/drop`, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/patients"] });
      toast({
        title: "Patient Dropped",
        description: `${patient?.firstName} ${patient?.lastName} has been dropped from your caseload.`,
      });
      handleClose();
    },
    onError: (error) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Unauthorized",
          description: "You are not logged in",
          variant: "destructive",
        });
        return;
      }
      
      const errorMessage = error instanceof Error ? error.message : "Failed to drop patient";
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

  const onSubmit = (data: z.infer<typeof dropFormSchema>) => {
    dropPatientMutation.mutate(data);
  };

  const handleOpenChange = (newOpen: boolean) => {
    setIsOpen(newOpen);
    onOpenChange?.(newOpen);
    if (!newOpen) {
      form.reset();
    }
  };

  return (
    <Dialog open={open !== undefined ? open : isOpen} onOpenChange={handleOpenChange}>
      <DialogContent className="w-[95vw] max-w-[95vw] sm:max-w-md md:max-w-md lg:max-w-lg xl:max-w-xl max-h-[95vh] overflow-auto rounded-lg p-4 sm:p-6 sm:m-0 flex flex-col" data-testid="modal-drop-patient">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-red-600">
            <AlertTriangle className="h-5 w-5" />
            Drop Patient from Caseload
          </DialogTitle>
        </DialogHeader>

        {patient && (
          <div className="mb-4 p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-md">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="h-4 w-4 text-yellow-600" />
              <span className="font-semibold text-yellow-800 dark:text-yellow-200">Warning</span>
            </div>
            <p className="text-sm text-yellow-700 dark:text-yellow-300 mb-2">
              You are about to drop <strong>{patient.firstName} {patient.lastName}</strong> from your caseload.
            </p>
            <p className="text-sm text-yellow-700 dark:text-yellow-300">
              This action will change their status to "dropped" and they will no longer appear in your active patient list.
              A reason is required for audit compliance.
            </p>
          </div>
        )}

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="dropReason"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-sm font-medium">
                    Reason for Dropping Patient <span className="text-red-500">*</span>
                  </FormLabel>
                  <FormControl>
                    <Textarea
                      {...field}
                      placeholder="Please provide a detailed reason for dropping this patient (e.g., no insurance coverage, patient non-compliance, case outside scope, etc.)"
                      className="min-h-[120px] resize-none"
                      data-testid="textarea-drop-reason"
                    />
                  </FormControl>
                  <div className="flex justify-between text-xs text-muted-foreground">
                    <FormMessage />
                    <span>{field.value?.length || 0}/1000 characters</span>
                  </div>
                </FormItem>
              )}
            />

            <div className="flex justify-end space-x-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={handleClose}
                disabled={dropPatientMutation.isPending}
                data-testid="button-cancel-drop"
              >
                Cancel
              </Button>
              <Button
                type="submit"
                variant="destructive"
                disabled={dropPatientMutation.isPending}
                data-testid="button-confirm-drop"
              >
                {dropPatientMutation.isPending ? "Dropping..." : "Drop Patient"}
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}