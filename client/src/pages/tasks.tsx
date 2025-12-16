import { useEffect, useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { TaskWithRelations } from "@shared/schema";
import { apiRequest } from "@/lib/queryClient";
import { isUnauthorizedError } from "@/lib/authUtils";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Plus, ListCheckIcon } from "lucide-react";
import { CheckIcon } from "lucide-react";
import AddTaskModal from "@/components/modals/add-task-modal";

export default function Tasks() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading } = useAuth();
  const [isAddTaskModalOpen, setIsAddTaskModalOpen] = useState(false);
  const queryClient = useQueryClient();

  // Automatic redirect to login removed - App.tsx routing handles authentication redirects

  const { data: tasks = [], isLoading: tasksLoading } = useQuery<
    TaskWithRelations[]
  >({
    queryKey: ["/api/tasks"],
    enabled: isAuthenticated, // SECURITY: Only fetch when authenticated
    retry: false,
  });

  const completeTaskMutation = useMutation({
    mutationFn: async (taskId: string) => {
      await apiRequest("PUT", `/api/tasks/${taskId}`, {
        status: "completed",
        completedAt: new Date().toISOString(),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/tasks"] });
      toast({
        title: "Success",
        description: "Task marked as completed",
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

      let errorMessage = "Failed to complete task";
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

  const handleCompleteTask = (taskId: string) => {
    completeTaskMutation.mutate(taskId);
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

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case "urgent":
        return "bg-red-500";
      case "high":
        return "bg-orange-500";
      case "normal":
        return "bg-blue-500";
      case "low":
        return "bg-gray-500";
      default:
        return "bg-blue-500";
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed":
        return "bg-green-100 text-green-800 border-green-200";
      case "in_progress":
        return "bg-blue-100 text-blue-800 border-blue-200";
      case "pending":
        return "bg-yellow-100 text-yellow-800 border-yellow-200";
      case "cancelled":
        return "bg-gray-100 text-gray-800 border-gray-200";
      default:
        return "bg-gray-100 text-gray-800 border-gray-200";
    }
  };

  return (
    <div className="min-h-screen flex bg-background">
      <Sidebar />

      <main className="flex-1 flex flex-col overflow-hidden">
        <Header
          title="Task Management"
          subtitle="Manage and track patient care tasks"
        />

        <div className="flex-1 overflow-auto p-6">
          <div className="mb-6 flex justify-between items-center">
            <div>
              <h2 className="text-xl font-semibold">All Tasks</h2>
              <p className="text-muted-foreground">
                Total: {tasks.length} tasks
              </p>
            </div>
            <Button
              data-testid="button-add-task"
              onClick={() => setIsAddTaskModalOpen(true)}
            >
              <Plus className="w-4 h-4 mr-2" />
              Add Task
            </Button>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Task Queue</CardTitle>
            </CardHeader>
            <CardContent>
              {tasksLoading ? (
                <div className="text-center py-8">
                  <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                  <p className="text-muted-foreground">Loading tasks...</p>
                </div>
              ) : tasks.length === 0 ? (
                <div className="text-center py-8">
                  <ListCheckIcon className="w-10 h-10 text-muted-foreground mb-4" />
                  <p className="text-muted-foreground">No tasks found</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {tasks.map((task) => (
                    <div
                      key={task.id}
                      className="flex items-start space-x-3 p-4 border border-border rounded-lg hover:bg-accent/50 transition-colors"
                      data-testid={`task-item-${task.id}`}
                    >
                      <div
                        className={`flex-shrink-0 w-3 h-3 mt-2 rounded-full ${getPriorityColor(
                          task.priority
                        )}`}
                      ></div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <h4 className="font-medium text-foreground">
                              {task.title}
                            </h4>
                            {task.description && (
                              <p className="text-sm text-muted-foreground mt-1">
                                {task.description}
                              </p>
                            )}
                            <div className="flex items-center space-x-4 mt-2">
                              <p className="text-xs text-muted-foreground">
                                Assigned to: {task.assignedTo?.firstName}{" "}
                                {task.assignedTo?.lastName}
                              </p>
                              {task.patient && (
                                <p className="text-xs text-muted-foreground">
                                  Patient: {task.patient.firstName}{" "}
                                  {task.patient.lastName}
                                </p>
                              )}
                              {task.dueDate && (
                                <p className="text-xs text-muted-foreground">
                                  Due:{" "}
                                  {new Date(task.dueDate).toLocaleDateString()}
                                </p>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center space-x-2 ml-4">
                            <Badge
                              className={`text-xs font-medium border ${getStatusColor(
                                task.status
                              )}`}
                            >
                              {task.status.replace("_", " ")}
                            </Badge>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleCompleteTask(task.id)}
                              disabled={
                                task.status === "completed" ||
                                completeTaskMutation.isPending
                              }
                              data-testid={`button-complete-${task.id}`}
                              title={
                                task.status === "completed"
                                  ? "Task already completed"
                                  : "Mark as completed"
                              }
                            >
                              <CheckIcon className="w-4 h-4" />
                            </Button>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </main>
      <AddTaskModal
        open={isAddTaskModalOpen}
        onOpenChange={setIsAddTaskModalOpen}
      />
    </div>
  );
}
