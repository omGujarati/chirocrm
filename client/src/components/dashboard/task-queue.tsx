import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/useAuth";
import {
  ArrowRightIcon,
  CheckIcon,
  ListCheckIcon,
  LockIcon,
} from "lucide-react";

export default function TaskQueue() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { isAuthenticated } = useAuth();

  const { data: tasks = [], isLoading } = useQuery({
    queryKey: ["/api/tasks"],
    enabled: isAuthenticated, // SECURITY: Only fetch when authenticated
    retry: false,
  });

  // Don't render any task data if not authenticated
  if (!isAuthenticated) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Task Queue</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8">
            <LockIcon className="w-10 h-10 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">Please log in to view tasks</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const completeTaskMutation = useMutation({
    mutationFn: async (taskId: string) => {
      await apiRequest("PUT", `/api/tasks/${taskId}`, {
        status: "completed",
        completedAt: new Date(),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/tasks"] });
      toast({
        title: "Success",
        description: "Task marked as completed",
      });
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
      toast({
        title: "Error",
        description: "Failed to complete task",
        variant: "destructive",
      });
    },
  });

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case "urgent":
        return "bg-red-400";
      case "high":
        return "bg-orange-400";
      case "normal":
        return "bg-yellow-400";
      case "low":
        return "bg-green-400";
      default:
        return "bg-yellow-400";
    }
  };

  // Show only pending and in_progress tasks, limit to 5 for dashboard
  const pendingTasks = (tasks as any[])
    .filter(
      (task: any) => task.status === "pending" || task.status === "in_progress"
    )
    .slice(0, 5);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Task Queue</CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="flex items-start space-x-3">
                <div className="w-2 h-2 mt-2 bg-muted rounded-full animate-pulse"></div>
                <div className="flex-1 space-y-2">
                  <div className="h-4 bg-muted rounded animate-pulse w-3/4"></div>
                  <div className="h-3 bg-muted rounded animate-pulse w-1/2"></div>
                </div>
              </div>
            ))}
          </div>
        ) : pendingTasks.length === 0 ? (
          <div className="text-center py-8">
            <ListCheckIcon className="w-10 h-10 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">No pending tasks</p>
          </div>
        ) : (
          <div className="space-y-4">
            {pendingTasks.map((task: any) => (
              <div
                key={task.id}
                className="flex items-start space-x-3"
                data-testid={`task-queue-item-${task.id}`}
              >
                <div
                  className={`flex-shrink-0 w-2 h-2 mt-2 rounded-full ${getPriorityColor(
                    task.priority
                  )}`}
                ></div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground">
                    {task.title}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    Assigned to: {task.assignedTo?.firstName}{" "}
                    {task.assignedTo?.lastName}
                  </p>
                  {task.dueDate && (
                    <p className="text-xs text-muted-foreground">
                      Due: {new Date(task.dueDate).toLocaleDateString()}
                    </p>
                  )}
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => completeTaskMutation.mutate(task.id)}
                  disabled={completeTaskMutation.isPending}
                  title="Mark as Complete"
                  data-testid={`button-complete-task-${task.id}`}
                >
                  <CheckIcon className="w-4 h-4" />
                </Button>
              </div>
            ))}
          </div>
        )}

        {pendingTasks.length > 0 && (
          <div className="pt-4 border-t border-border">
            <button
              className="w-full text-sm text-muted-foreground hover:text-foreground"
              onClick={() => (window.location.href = "/tasks")}
              data-testid="button-view-all-tasks"
            >
              View All Tasks <ArrowRightIcon className="w-4 h-4 ml-2" />
            </button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
