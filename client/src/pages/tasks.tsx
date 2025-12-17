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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import {
  Pagination,
  PaginationContent,
  PaginationEllipsis,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination";
import { Plus, ListCheckIcon, RotateCcw } from "lucide-react";
import { CheckIcon } from "lucide-react";
import AddTaskModal from "@/components/modals/add-task-modal";

interface PaginatedTasksResponse {
  tasks: TaskWithRelations[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export default function Tasks() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading } = useAuth();
  const [isAddTaskModalOpen, setIsAddTaskModalOpen] = useState(false);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(5);
  const queryClient = useQueryClient();

  // Automatic redirect to login removed - App.tsx routing handles authentication redirects

  const {
    data: tasksData,
    isLoading: tasksLoading,
    error,
  } = useQuery<PaginatedTasksResponse>({
    queryKey: ["/api/tasks", page, limit],
    queryFn: async () => {
      try {
        const url = `/api/tasks?page=${page}&limit=${limit}`;
        const response = await apiRequest("GET", url);
        const data = await response.json();

        // Handle backward compatibility: if response is an array (old format), convert it
        if (Array.isArray(data)) {
          // Old format - return all tasks as if they're on one page
          return {
            tasks: data,
            pagination: {
              page: 1,
              limit: data.length,
              total: data.length,
              totalPages: 1,
            },
          };
        }

        // New format - ensure it has the expected structure
        if (!data.tasks || !data.pagination) {
          console.error("Invalid response format:", data);
          throw new Error(
            "Invalid response format from server. Expected { tasks: [], pagination: {} }"
          );
        }
        return data;
      } catch (error: any) {
        console.error("Error fetching tasks:", error);
        throw new Error(error.message || "Failed to fetch tasks");
      }
    },
    enabled: isAuthenticated, // SECURITY: Only fetch when authenticated
    retry: false,
  });

  // Extract tasks and pagination from response
  const tasks = tasksData?.tasks || [];
  const pagination = tasksData?.pagination;

  // Handle page adjustments when pagination changes
  useEffect(() => {
    if (
      pagination &&
      pagination.totalPages > 0 &&
      page > pagination.totalPages
    ) {
      // If current page is beyond available pages, go to last available page
      setPage(pagination.totalPages);
    }
  }, [pagination, page]);

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

  const handlePageChange = (newPage: number) => {
    setPage(newPage);
    // Scroll to top of the list
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleLimitChange = (newLimit: string) => {
    setLimit(Number(newLimit));
    setPage(1); // Reset to first page when changing limit
  };

  const handleReset = () => {
    setPage(1);
    setLimit(5);
  };

  // Show reset button if pagination differs from defaults
  const showResetButton = page !== 1 || limit !== 5;

  const renderPaginationControls = () => {
    if (!pagination || pagination.totalPages <= 1) return null;

    const { page: currentPage, totalPages } = pagination;
    const pages: (number | "ellipsis")[] = [];

    // Calculate which page numbers to show
    if (totalPages <= 7) {
      // Show all pages if 7 or fewer
      for (let i = 1; i <= totalPages; i++) {
        pages.push(i);
      }
    } else {
      // Always show first page
      pages.push(1);

      if (currentPage <= 3) {
        // Near the start
        for (let i = 2; i <= 4; i++) {
          pages.push(i);
        }
        pages.push("ellipsis");
        pages.push(totalPages);
      } else if (currentPage >= totalPages - 2) {
        // Near the end
        pages.push("ellipsis");
        for (let i = totalPages - 3; i <= totalPages; i++) {
          pages.push(i);
        }
      } else {
        // In the middle
        pages.push("ellipsis");
        for (let i = currentPage - 1; i <= currentPage + 1; i++) {
          pages.push(i);
        }
        pages.push("ellipsis");
        pages.push(totalPages);
      }
    }

    return (
      <Pagination>
        <PaginationContent>
          <PaginationItem>
            <PaginationPrevious
              href="#"
              onClick={(e) => {
                e.preventDefault();
                if (currentPage > 1) {
                  handlePageChange(currentPage - 1);
                }
              }}
              className={
                currentPage === 1
                  ? "pointer-events-none opacity-50"
                  : "cursor-pointer"
              }
            />
          </PaginationItem>

          {pages.map((pageNum, index) => {
            if (pageNum === "ellipsis") {
              return (
                <PaginationItem key={`ellipsis-${index}`}>
                  <PaginationEllipsis />
                </PaginationItem>
              );
            }
            return (
              <PaginationItem key={pageNum}>
                <PaginationLink
                  href="#"
                  onClick={(e) => {
                    e.preventDefault();
                    handlePageChange(pageNum);
                  }}
                  isActive={pageNum === currentPage}
                  className="cursor-pointer"
                >
                  {pageNum}
                </PaginationLink>
              </PaginationItem>
            );
          })}

          <PaginationItem>
            <PaginationNext
              href="#"
              onClick={(e) => {
                e.preventDefault();
                if (currentPage < totalPages) {
                  handlePageChange(currentPage + 1);
                }
              }}
              className={
                currentPage === totalPages
                  ? "pointer-events-none opacity-50"
                  : "cursor-pointer"
              }
            />
          </PaginationItem>
        </PaginationContent>
      </Pagination>
    );
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
                {pagination
                  ? `Total: ${pagination.total} tasks`
                  : `Total: ${tasks.length} tasks`}
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
              <div className="flex items-center justify-between">
                <CardTitle>Task Queue</CardTitle>
                {showResetButton && (
                  <Button
                    variant="outline"
                    onClick={handleReset}
                    className="flex items-center gap-2"
                    data-testid="button-reset-filters"
                  >
                    <RotateCcw className="w-4 h-4" />
                    Reset
                  </Button>
                )}
              </div>
            </CardHeader>
            <CardContent>
              {tasksLoading ? (
                <div className="flex flex-col items-center justify-center text-center py-8">
                  <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                  <p className="text-muted-foreground">Loading tasks...</p>
                </div>
              ) : tasks.length === 0 ? (
                <div className="flex flex-col items-center justify-center text-center py-8">
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

                  {/* Pagination Controls */}
                  {pagination && (
                    <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-4 border-t">
                      {/* Page Size Selector */}
                      <div className="flex items-center gap-2">
                        <Label
                          htmlFor="page-size"
                          className="text-sm whitespace-nowrap"
                        >
                          Show:
                        </Label>
                        <Select
                          value={limit.toString()}
                          onValueChange={handleLimitChange}
                        >
                          <SelectTrigger id="page-size" className="w-[80px]">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="5">5</SelectItem>
                            <SelectItem value="10">10</SelectItem>
                            <SelectItem value="50">50</SelectItem>
                            <SelectItem value="100">100</SelectItem>
                          </SelectContent>
                        </Select>
                        <span className="text-sm text-muted-foreground whitespace-nowrap">
                          per page
                        </span>
                      </div>

                      {/* Pagination Info */}
                      <div className="text-sm text-muted-foreground text-center sm:text-left">
                        <span className="hidden sm:inline">
                          Showing {(pagination.page - 1) * pagination.limit + 1}{" "}
                          to{" "}
                          {Math.min(
                            pagination.page * pagination.limit,
                            pagination.total
                          )}{" "}
                          of {pagination.total} tasks
                        </span>
                        <span className="sm:hidden">
                          Page {pagination.page} of {pagination.totalPages}
                        </span>
                      </div>

                      {/* Pagination Buttons */}
                      <div className="w-full sm:w-auto">
                        {renderPaginationControls()}
                      </div>
                    </div>
                  )}
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
