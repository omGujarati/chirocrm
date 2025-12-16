import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { queryClient, apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  UserPlus,
  Trash2,
  UserX,
  UserCheck,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  Eye,
  EyeOff,
  MoreVertical,
  RotateCcw,
  Edit2,
} from "lucide-react";
import { AddUserModal } from "@/components/modals/add-user-modal";
import { EditUserModal } from "@/components/modals/edit-user-modal";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
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

interface User {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  role: string;
  isActive: boolean;
  verificationStatus?: "pending_verification" | "verified" | "rejected" | null;
  rejectionReason?: string | null;
}

interface PaginatedUsersResponse {
  users: User[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export default function Users() {
  const { isAuthenticated, isLoading, user } = useAuth();
  const { toast } = useToast();
  const [showAddUserModal, setShowAddUserModal] = useState(false);
  const [rejectionDialogOpen, setRejectionDialogOpen] = useState(false);
  const [selectedUserForRejection, setSelectedUserForRejection] =
    useState<User | null>(null);
  const [rejectionReason, setRejectionReason] = useState("");
  const [userActionsDialogOpen, setUserActionsDialogOpen] = useState(false);
  const [selectedUserForActions, setSelectedUserForActions] =
    useState<User | null>(null);
  const [showEditUserModal, setShowEditUserModal] = useState(false);
  const [selectedUserForEdit, setSelectedUserForEdit] = useState<User | null>(
    null
  );
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(5);

  const {
    data: usersData,
    isLoading: isLoadingUsers,
    error: usersError,
  } = useQuery<PaginatedUsersResponse>({
    queryKey: ["/api/users", page, limit],
    queryFn: async () => {
      const url = `/api/users?page=${page}&limit=${limit}`;
      const response = await fetch(url, {
        credentials: "include",
      });
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(
          `Failed to fetch users: ${response.status} ${errorText}`
        );
      }
      const data = await response.json();

      // Handle backward compatibility: if response is an array (old format), convert it
      if (Array.isArray(data)) {
        // Old format - return all users as if they're on one page
        return {
          users: data,
          pagination: {
            page: 1,
            limit: data.length,
            total: data.length,
            totalPages: 1,
          },
        };
      }

      // New format - ensure it has the expected structure
      if (!data.users || !data.pagination) {
        console.error("Invalid response format:", data);
        throw new Error(
          "Invalid response format from server. Expected { users: [], pagination: {} }"
        );
      }
      return data;
    },
    enabled: isAuthenticated && user?.role === "admin",
    retry: false,
  });

  const users = usersData?.users || [];
  const pagination = usersData?.pagination;

  // Mutation for updating user status
  const statusMutation = useMutation({
    mutationFn: async ({
      userId,
      isActive,
    }: {
      userId: string;
      isActive: boolean;
    }) => {
      const response = await apiRequest(
        "PATCH",
        `/api/users/${userId}/status`,
        { isActive }
      );
      return response.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
      toast({
        title: "Success",
        description: data.message,
      });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to update user status",
        variant: "destructive",
      });
    },
  });

  // Mutation for deleting user
  const deleteMutation = useMutation({
    mutationFn: async (userId: string) => {
      const response = await apiRequest("DELETE", `/api/users/${userId}`);
      return response.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
      toast({
        title: "Success",
        description: data.message,
      });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to delete user",
        variant: "destructive",
      });
    },
  });

  // Mutation for updating verification status
  const updateVerificationStatusMutation = useMutation({
    mutationFn: async ({
      userId,
      verificationStatus,
      rejectionReason,
    }: {
      userId: string;
      verificationStatus: "pending_verification" | "verified" | "rejected";
      rejectionReason?: string | null;
    }) => {
      const response = await apiRequest(
        "PATCH",
        `/api/users/${userId}/verification-status`,
        {
          verificationStatus,
          rejectionReason: rejectionReason || null,
        }
      );
      return response.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
      toast({
        title: "Success",
        description: data.message,
      });
      setRejectionDialogOpen(false);
      setRejectionReason("");
      setSelectedUserForRejection(null);
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to update verification status",
        variant: "destructive",
      });
    },
  });

  const handleVerificationStatusChange = (
    userData: User,
    newStatus: "pending_verification" | "verified" | "rejected"
  ) => {
    if (newStatus === "rejected") {
      // Show dialog for rejection reason
      setSelectedUserForRejection(userData);
      setRejectionReason(userData.rejectionReason || "");
      setRejectionDialogOpen(true);
    } else {
      // Approve or set to pending directly
      updateVerificationStatusMutation.mutate({
        userId: userData.id,
        verificationStatus: newStatus,
      });
    }
  };

  const handleConfirmRejection = () => {
    if (selectedUserForRejection) {
      updateVerificationStatusMutation.mutate({
        userId: selectedUserForRejection.id,
        verificationStatus: "rejected",
        rejectionReason: rejectionReason || null,
      });
    }
  };

  const handleToggleStatus = (userId: string, currentStatus: boolean) => {
    statusMutation.mutate({ userId, isActive: !currentStatus });
  };

  const handleDeleteUser = (userId: string) => {
    deleteMutation.mutate(userId);
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

  if (user?.role !== "admin") {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-semibold mb-2">Access Denied</h2>
          <p className="text-muted-foreground">
            You don't have permission to view this page.
          </p>
          <Button
            onClick={() => (window.location.href = "/dashboard")}
            className="mt-4"
          >
            Back to Dashboard
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex bg-background">
      <Sidebar />

      <main className="flex-1 flex flex-col overflow-hidden relative z-0">
        <Header
          title="User Management"
          subtitle="Manage system users and their permissions"
        />

        <div className="flex-1 overflow-auto p-6 relative z-0">
          <div className="space-y-6">
            {/* Pending Verifications Alert */}
            {users &&
              users.filter(
                (u) =>
                  u.role === "attorney" &&
                  u.verificationStatus === "pending_verification"
              ).length > 0 && (
                <Card className="border-yellow-200 bg-yellow-50 dark:bg-yellow-900/20">
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Clock className="w-5 h-5 text-yellow-600" />
                      <span>Pending Attorney Verifications</span>
                      <Badge variant="secondary" className="ml-2">
                        {
                          users.filter(
                            (u) =>
                              u.role === "attorney" &&
                              u.verificationStatus === "pending_verification"
                          ).length
                        }
                      </Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-muted-foreground">
                      There are{" "}
                      {
                        users.filter(
                          (u) =>
                            u.role === "attorney" &&
                            u.verificationStatus === "pending_verification"
                        ).length
                      }{" "}
                      attorney account(s) waiting for verification.
                    </p>
                  </CardContent>
                </Card>
              )}

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
                <CardTitle>System Users</CardTitle>
                <div className="flex items-center gap-2">
                  {showResetButton && (
                    <Button
                      variant="outline"
                      onClick={handleReset}
                      className="flex items-center gap-2"
                      data-testid="button-reset-pagination"
                    >
                      <RotateCcw className="w-4 h-4" />
                      Reset
                    </Button>
                  )}
                  <Button
                    onClick={() => setShowAddUserModal(true)}
                    data-testid="button-add-user"
                  >
                    <UserPlus className="w-4 h-4 mr-2" />
                    Add User
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                {usersError && (
                  <div className="flex items-center justify-center py-8">
                    <div className="text-center">
                      <p className="text-destructive mb-2">
                        Error loading users
                      </p>
                      <p className="text-sm text-muted-foreground">
                        {usersError instanceof Error
                          ? usersError.message
                          : "Unknown error"}
                      </p>
                    </div>
                  </div>
                )}
                {isLoadingUsers ? (
                  <div className="flex items-center justify-center py-8">
                    <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
                    <span className="ml-2 text-muted-foreground">
                      Loading users...
                    </span>
                  </div>
                ) : (
                  !usersError && (
                    <div className="space-y-4">
                      {users?.map((userData) => (
                        <div
                          key={userData.id}
                          className="relative flex flex-col md:flex-row md:items-center md:justify-between gap-4 p-4 border rounded-lg bg-card hover:bg-muted/50 transition-colors overflow-hidden"
                          data-testid={`user-row-${userData.id}`}
                        >
                          {/* Status Stripe - Top Left Corner */}
                          <div
                            className={`absolute top-0 left-0 w-1 h-full ${
                              userData.isActive ? "bg-green-500" : "bg-gray-400"
                            }`}
                            aria-label={
                              userData.isActive ? "Active" : "Inactive"
                            }
                          />

                          {/* User Info Section */}
                          <div className="flex items-center space-x-4 min-w-0 flex-1 pl-2">
                            <div className="w-10 h-10 bg-muted rounded-full flex items-center justify-center flex-shrink-0">
                              <span className="text-sm font-medium">
                                {userData.firstName?.charAt(0)?.toUpperCase()}
                                {userData.lastName?.charAt(0)?.toUpperCase()}
                              </span>
                            </div>
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2 flex-wrap">
                                <h4
                                  className="font-medium truncate"
                                  data-testid={`text-name-${userData.id}`}
                                >
                                  {userData.firstName
                                    ?.charAt(0)
                                    ?.toUpperCase() +
                                    userData.firstName?.slice(1)}{" "}
                                  {userData.lastName?.charAt(0)?.toUpperCase() +
                                    userData.lastName?.slice(1)}
                                </h4>
                                <Badge
                                  variant={
                                    userData.role === "admin"
                                      ? "default"
                                      : userData.role === "staff"
                                      ? "secondary"
                                      : "outline"
                                  }
                                  data-testid={`badge-role-${userData.id}`}
                                  className="flex-shrink-0 text-xs"
                                >
                                  {userData.role === "admin"
                                    ? "Admin"
                                    : userData.role === "staff"
                                    ? "Staff"
                                    : userData.role === "attorney"
                                    ? "Attorney"
                                    : userData.role}
                                </Badge>
                              </div>
                              <p
                                className="text-sm text-muted-foreground truncate"
                                data-testid={`text-email-${userData.id}`}
                              >
                                {userData.email}
                              </p>
                              {/* Verification Status Badge - Only for self-registered attorneys */}
                              {userData.role === "attorney" &&
                                userData.verificationStatus && (
                                  <div className="mt-1">
                                    {/* <Badge 
                                  variant={userData.verificationStatus === 'verified' ? "outline" : 
                                          userData.verificationStatus === 'rejected' ? "destructive" : "secondary"}
                                  className={`text-xs flex-shrink-0 inline-flex items-center ${
                                    userData.verificationStatus === 'verified' ? "text-green-600 border-green-600" : 
                                    userData.verificationStatus === 'pending_verification' ? "text-yellow-600 border-yellow-600" : ""
                                  }`}
                                  data-testid={`badge-verification-${userData.id}`}
                                >
                                  {userData.verificationStatus === 'verified' ? (
                                    <>
                                      <CheckCircle2 className="w-3 h-3 mr-1" />
                                      Verified
                                    </>
                                  ) : userData.verificationStatus === 'rejected' ? (
                                    <>
                                      <XCircle className="w-3 h-3 mr-1" />
                                      Rejected
                                    </>
                                  ) : (
                                    <>
                                      <Clock className="w-3 h-3 mr-1" />
                                      Pending Verification
                                    </>
                                  )}
                                </Badge> */}
                                  </div>
                                )}
                            </div>
                          </div>

                          {/* Actions Section */}
                          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 flex-shrink-0 justify-end">
                            {/* Actions */}
                            <div className="flex items-center gap-1 flex-shrink-0">
                              {/* Prevent actions on self */}
                              {userData.id !== user?.id && (
                                <>
                                  {/* Desktop actions - hidden on mobile */}
                                  <div className="hidden md:flex items-center gap-1">
                                    {/* Edit User Button */}
                                    <Button
                                      variant="outline"
                                      size="sm"
                                      onClick={() => {
                                        setSelectedUserForEdit(userData);
                                        setShowEditUserModal(true);
                                      }}
                                      data-testid={`button-edit-${userData.id}`}
                                      title="Edit User Details"
                                    >
                                      <Edit2 size={14} />
                                    </Button>

                                    {/* Verification status selector - Only for self-registered attorneys */}
                                    {userData.role === "attorney" &&
                                      userData.verificationStatus !== null &&
                                      userData.verificationStatus !==
                                        undefined && (
                                        <Select
                                          value={
                                            userData.verificationStatus ||
                                            "pending_verification"
                                          }
                                          onValueChange={(
                                            value:
                                              | "pending_verification"
                                              | "verified"
                                              | "rejected"
                                          ) =>
                                            handleVerificationStatusChange(
                                              userData,
                                              value
                                            )
                                          }
                                          disabled={
                                            updateVerificationStatusMutation.isPending
                                          }
                                        >
                                          <SelectTrigger
                                            className="w-[140px]"
                                            data-testid={`select-verification-${userData.id}`}
                                          >
                                            <SelectValue />
                                          </SelectTrigger>
                                          <SelectContent>
                                            <SelectItem value="pending_verification">
                                              Pending
                                            </SelectItem>
                                            <SelectItem value="verified">
                                              Approve
                                            </SelectItem>
                                            <SelectItem value="rejected">
                                              Reject
                                            </SelectItem>
                                          </SelectContent>
                                        </Select>
                                      )}

                                    <Button
                                      variant="outline"
                                      size="sm"
                                      onClick={() =>
                                        handleToggleStatus(
                                          userData.id,
                                          userData.isActive
                                        )
                                      }
                                      disabled={
                                        statusMutation.isPending ||
                                        (userData.role === "attorney" &&
                                          userData.verificationStatus ===
                                            "rejected")
                                      }
                                      data-testid={`button-toggle-${userData.id}`}
                                      title={
                                        userData.role === "attorney" &&
                                        userData.verificationStatus ===
                                          "rejected"
                                          ? "Cannot activate/deactivate rejected accounts"
                                          : ""
                                      }
                                    >
                                      {statusMutation.isPending
                                        ? "Updating..."
                                        : userData.isActive
                                        ? "Deactivate"
                                        : "Activate"}
                                    </Button>

                                    <AlertDialog>
                                      <AlertDialogTrigger asChild>
                                        <Button
                                          variant="destructive"
                                          size="sm"
                                          disabled={deleteMutation.isPending}
                                          data-testid={`button-delete-${userData.id}`}
                                        >
                                          Delete
                                        </Button>
                                      </AlertDialogTrigger>
                                      <AlertDialogContent>
                                        <AlertDialogHeader>
                                          <AlertDialogTitle>
                                            Delete User
                                          </AlertDialogTitle>
                                          <AlertDialogDescription>
                                            Are you sure you want to delete{" "}
                                            <strong>
                                              {userData.firstName}{" "}
                                              {userData.lastName}
                                            </strong>
                                            ? This action cannot be undone and
                                            will permanently remove the user and
                                            all associated data.
                                          </AlertDialogDescription>
                                        </AlertDialogHeader>
                                        <AlertDialogFooter>
                                          <AlertDialogCancel>
                                            Cancel
                                          </AlertDialogCancel>
                                          <AlertDialogAction
                                            onClick={() =>
                                              handleDeleteUser(userData.id)
                                            }
                                            className="bg-destructive hover:bg-destructive/90"
                                          >
                                            Delete User
                                          </AlertDialogAction>
                                        </AlertDialogFooter>
                                      </AlertDialogContent>
                                    </AlertDialog>
                                  </div>

                                  {/* Mobile actions - "..." button */}
                                  <div className="md:hidden">
                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      onClick={() => {
                                        setSelectedUserForActions(userData);
                                        setUserActionsDialogOpen(true);
                                      }}
                                      data-testid={`button-more-${userData.id}`}
                                    >
                                      <MoreVertical className="h-4 w-4" />
                                    </Button>
                                  </div>
                                </>
                              )}

                              {userData.id === user?.id && (
                                <span className="text-sm text-muted-foreground px-2 whitespace-nowrap">
                                  (Your Account)
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}

                      {(!users || users.length === 0) && (
                        <div className="text-center py-8 text-muted-foreground">
                          No users found
                        </div>
                      )}

                      {/* Pagination Controls */}
                      {pagination && pagination.total > 0 && (
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
                              <SelectTrigger
                                id="page-size"
                                className="w-[80px]"
                              >
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
                              Showing{" "}
                              {(pagination.page - 1) * pagination.limit + 1} to{" "}
                              {Math.min(
                                pagination.page * pagination.limit,
                                pagination.total
                              )}{" "}
                              of {pagination.total} users
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
                  )
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Quick Stats</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-4 gap-4">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-blue-600">
                      {users?.filter((u) => u.role === "admin").length || 0}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Administrators
                    </div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-green-600">
                      {users?.filter((u) => u.role === "staff").length || 0}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Staff Members
                    </div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-purple-600">
                      {users?.filter((u) => u.role === "attorney").length || 0}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Attorneys
                    </div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-yellow-600">
                      {users?.filter(
                        (u) =>
                          u.role === "attorney" &&
                          u.verificationStatus === "pending_verification"
                      ).length || 0}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Pending Verification
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </main>

      <AddUserModal
        isOpen={showAddUserModal}
        onClose={() => setShowAddUserModal(false)}
      />

      <EditUserModal
        isOpen={showEditUserModal}
        onClose={() => {
          setShowEditUserModal(false);
          setSelectedUserForEdit(null);
        }}
        user={selectedUserForEdit}
      />

      {/* User Actions Dialog for Mobile */}
      <Dialog
        open={userActionsDialogOpen}
        onOpenChange={setUserActionsDialogOpen}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              {selectedUserForActions &&
                `${selectedUserForActions.firstName} ${selectedUserForActions.lastName}`}
            </DialogTitle>
            <DialogDescription>
              Manage user account settings and status
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            {selectedUserForActions && (
              <>
                {/* Edit User Button */}
                <Button
                  variant="outline"
                  className="w-full"
                  onClick={() => {
                    setSelectedUserForEdit(selectedUserForActions);
                    setUserActionsDialogOpen(false);
                    setShowEditUserModal(true);
                  }}
                  data-testid={`mobile-button-edit-${selectedUserForActions.id}`}
                >
                  <Edit2 size={14} className="mr-2" />
                  Edit User Details
                </Button>

                {/* Verification status selector - Only for self-registered attorneys */}
                {selectedUserForActions.role === "attorney" &&
                  selectedUserForActions.verificationStatus !== null &&
                  selectedUserForActions.verificationStatus !== undefined && (
                    <div className="space-y-2">
                      <Label>Verification Status</Label>
                      <Select
                        value={
                          selectedUserForActions.verificationStatus ||
                          "pending_verification"
                        }
                        onValueChange={(
                          value:
                            | "pending_verification"
                            | "verified"
                            | "rejected"
                        ) => {
                          handleVerificationStatusChange(
                            selectedUserForActions,
                            value
                          );
                          if (value !== "rejected") {
                            setUserActionsDialogOpen(false);
                          }
                        }}
                        disabled={updateVerificationStatusMutation.isPending}
                      >
                        <SelectTrigger
                          data-testid={`mobile-select-verification-${selectedUserForActions.id}`}
                        >
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="pending_verification">
                            Pending
                          </SelectItem>
                          <SelectItem value="verified">Approve</SelectItem>
                          <SelectItem value="rejected">Reject</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  )}

                {/* Activate/Deactivate button */}
                <Button
                  variant="outline"
                  className="w-full"
                  onClick={() => {
                    handleToggleStatus(
                      selectedUserForActions.id,
                      selectedUserForActions.isActive
                    );
                    setUserActionsDialogOpen(false);
                  }}
                  disabled={
                    statusMutation.isPending ||
                    (selectedUserForActions.role === "attorney" &&
                      selectedUserForActions.verificationStatus === "rejected")
                  }
                  data-testid={`mobile-button-toggle-${selectedUserForActions.id}`}
                >
                  {statusMutation.isPending
                    ? "Updating..."
                    : selectedUserForActions.isActive
                    ? "Deactivate Account"
                    : "Activate Account"}
                </Button>

                {/* Delete button */}
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button
                      variant="destructive"
                      className="w-full"
                      disabled={deleteMutation.isPending}
                      data-testid={`mobile-button-delete-${selectedUserForActions.id}`}
                    >
                      Delete User
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>Delete User</AlertDialogTitle>
                      <AlertDialogDescription>
                        Are you sure you want to delete{" "}
                        <strong>
                          {selectedUserForActions.firstName}{" "}
                          {selectedUserForActions.lastName}
                        </strong>
                        ? This action cannot be undone and will permanently
                        remove the user and all associated data.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction
                        onClick={() => {
                          handleDeleteUser(selectedUserForActions.id);
                          setUserActionsDialogOpen(false);
                        }}
                        className="bg-destructive hover:bg-destructive/90"
                      >
                        Delete User
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              </>
            )}
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setUserActionsDialogOpen(false);
                setSelectedUserForActions(null);
              }}
            >
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rejection Reason Dialog */}
      <Dialog open={rejectionDialogOpen} onOpenChange={setRejectionDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reject Attorney Account</DialogTitle>
            <DialogDescription>
              {selectedUserForRejection && (
                <>
                  Please provide a reason for rejecting{" "}
                  {selectedUserForRejection.firstName}{" "}
                  {selectedUserForRejection.lastName}'s account. This field is
                  optional.
                </>
              )}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="rejection-reason">
                Rejection Reason (Optional)
              </Label>
              <Textarea
                id="rejection-reason"
                placeholder="Enter reason for rejection..."
                value={rejectionReason}
                onChange={(e) => setRejectionReason(e.target.value)}
                rows={4}
              />
            </div>
            {selectedUserForRejection?.rejectionReason && (
              <div className="text-sm text-muted-foreground">
                <strong>Current reason:</strong>{" "}
                {selectedUserForRejection.rejectionReason}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setRejectionDialogOpen(false);
                setRejectionReason("");
                setSelectedUserForRejection(null);
              }}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleConfirmRejection}
              disabled={updateVerificationStatusMutation.isPending}
            >
              {updateVerificationStatusMutation.isPending ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Rejecting...
                </>
              ) : (
                "Reject Account"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
