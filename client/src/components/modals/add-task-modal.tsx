import { useState, useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQueryClient, useQuery } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { insertTaskSchema } from "@shared/schema";
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

interface AddTaskModalProps {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}

const formSchema = insertTaskSchema
  .omit({
    createdBy: true, // This will be set automatically by the backend based on authenticated user
  })
  .extend({
    title: z.string().min(1, "Title is required"),
    assignedTo: z.string().min(1, "Assigned to is required"),
    patientId: z.string().optional().nullable(),
    dueDate: z.coerce.date().optional().nullable(),
  });

export default function AddTaskModal({
  open,
  onOpenChange,
}: AddTaskModalProps) {
  const [isOpen, setIsOpen] = useState(open || false);
  const { toast } = useToast();
  const { user } = useAuth();
  const queryClient = useQueryClient();

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      title: "",
      description: "",
      patientId: null,
      assignedTo: "",
      status: "pending",
      priority: "normal",
      dueDate: null,
    },
  });

  // Fetch users for assignedTo dropdown
  const { data: usersData } = useQuery<
    | Array<{
        id: string;
        firstName: string;
        lastName: string;
        email: string;
        role: string;
        isActive: boolean;
      }>
    | {
        users: Array<{
          id: string;
          firstName: string;
          lastName: string;
          email: string;
          role: string;
          isActive: boolean;
        }>;
        pagination: any;
      }
  >({
    queryKey: ["/api/users"],
    queryFn: async () => {
      const response = await fetch("/api/users?page=1&limit=100", {
        credentials: "include",
      });
      if (!response.ok) {
        return [];
      }
      const data = await response.json();
      // Handle both old format (array) and new format (paginated object)
      if (Array.isArray(data)) {
        return data;
      }
      if (data.users && Array.isArray(data.users)) {
        return data.users;
      }
      return [];
    },
    retry: false,
    enabled: isOpen,
  });

  // Fetch patients for patientId dropdown
  const { data: patientsData } = useQuery({
    queryKey: ["/api/patients", "for-task"],
    queryFn: async () => {
      try {
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
    enabled: isOpen,
    retry: false,
  });

  // Extract users array from response (handle both formats)
  const users = Array.isArray(usersData) ? usersData : usersData?.users || [];
  const assignableUsers =
    users?.filter((u) => u.isActive && u.role !== "admin") || [];

  const patients = patientsData?.patients || [];

  // Set default assignedTo to current user if available
  useEffect(() => {
    if (user && !form.getValues("assignedTo")) {
      form.setValue("assignedTo", user.id);
    }
  }, [user, form]);

  const createTaskMutation = useMutation({
    mutationFn: async (data: z.infer<typeof formSchema>) => {
      const taskData = {
        ...data,
        patientId: data.patientId || undefined,
        dueDate: data.dueDate
          ? new Date(data.dueDate).toISOString()
          : undefined,
      };
      await apiRequest("POST", "/api/tasks", taskData);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/tasks"] });
      toast({
        title: "Success",
        description: "Task created successfully",
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
      let errorMessage = "Failed to create task";
      if (error.message) {
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
    form.reset({
      title: "",
      description: "",
      patientId: null,
      assignedTo: user?.id || "",
      status: "pending",
      priority: "normal",
      dueDate: null,
    });
  };

  const onSubmit = (data: z.infer<typeof formSchema>) => {
    createTaskMutation.mutate(data);
  };

  // Update internal state when prop changes
  useEffect(() => {
    if (open !== undefined) {
      setIsOpen(open);
    }
  }, [open]);

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent
        className="w-[95vw] max-w-[95vw] sm:max-w-md md:max-w-lg max-h-[95vh] overflow-auto rounded-lg p-4 sm:p-6 sm:m-0"
        data-testid="modal-add-task"
      >
        <DialogHeader>
          <DialogTitle>Add New Task</DialogTitle>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
            <FormField
              control={form.control}
              name="title"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Title *</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="Enter task title"
                      {...field}
                      data-testid="input-task-title"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Description</FormLabel>
                  <FormControl>
                    <Textarea
                      rows={3}
                      placeholder="Enter task description"
                      {...field}
                      value={field.value || ""}
                      data-testid="input-task-description"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <FormField
                control={form.control}
                name="assignedTo"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Assign To *</FormLabel>
                    <Select
                      onValueChange={field.onChange}
                      value={field.value || ""}
                    >
                      <FormControl>
                        <SelectTrigger data-testid="select-assigned-to">
                          <SelectValue placeholder="Select user" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {assignableUsers.map((user) => (
                          <SelectItem key={user.id} value={user.id}>
                            {user.firstName} {user.lastName} ({user.role})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="patientId"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Patient (Optional)</FormLabel>
                    <Select
                      onValueChange={(value) =>
                        field.onChange(value === "none" ? null : value)
                      }
                      value={field.value || "none"}
                    >
                      <FormControl>
                        <SelectTrigger data-testid="select-patient">
                          <SelectValue placeholder="Select patient" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="none">None</SelectItem>
                        {patients.map((patient: any) => (
                          <SelectItem key={patient.id} value={patient.id}>
                            {patient.firstName} {patient.lastName}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <FormField
                control={form.control}
                name="priority"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Priority</FormLabel>
                    <Select
                      onValueChange={field.onChange}
                      defaultValue={field.value}
                    >
                      <FormControl>
                        <SelectTrigger data-testid="select-priority">
                          <SelectValue placeholder="Select priority" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="low">Low</SelectItem>
                        <SelectItem value="normal">Normal</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="urgent">Urgent</SelectItem>
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="status"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Status</FormLabel>
                    <Select
                      onValueChange={field.onChange}
                      defaultValue={field.value}
                    >
                      <FormControl>
                        <SelectTrigger data-testid="select-status">
                          <SelectValue placeholder="Select status" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="pending">Pending</SelectItem>
                        <SelectItem value="in_progress">In Progress</SelectItem>
                        <SelectItem value="completed">Completed</SelectItem>
                        <SelectItem value="cancelled">Cancelled</SelectItem>
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <FormField
              control={form.control}
              name="dueDate"
              render={({ field }) => {
                // Format date for datetime-local input (YYYY-MM-DDTHH:mm)
                const formatDateForInput = (date: Date | null): string => {
                  if (!date) return "";
                  const year = date.getFullYear();
                  const month = String(date.getMonth() + 1).padStart(2, "0");
                  const day = String(date.getDate()).padStart(2, "0");
                  const hours = String(date.getHours()).padStart(2, "0");
                  const minutes = String(date.getMinutes()).padStart(2, "0");
                  return `${year}-${month}-${day}T${hours}:${minutes}`;
                };

                return (
                  <FormItem>
                    <FormLabel>Due Date (Optional)</FormLabel>
                    <FormControl>
                      <Input
                        type="datetime-local"
                        value={
                          field.value
                            ? formatDateForInput(new Date(field.value))
                            : ""
                        }
                        onChange={(e) => {
                          const date = e.target.value
                            ? new Date(e.target.value)
                            : null;
                          field.onChange(date);
                        }}
                        data-testid="input-due-date"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                );
              }}
            />

            <div className="flex items-center justify-end space-x-4 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={handleClose}
                data-testid="button-cancel-add-task"
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={createTaskMutation.isPending}
                data-testid="button-submit-add-task"
              >
                {createTaskMutation.isPending ? (
                  <>
                    <div className="w-4 h-4 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin mr-2"></div>
                    Creating...
                  </>
                ) : (
                  "Create Task"
                )}
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
