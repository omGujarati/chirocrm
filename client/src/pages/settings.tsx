import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { LogOut, User, Edit2, Eye, EyeOff } from "lucide-react";
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

const profileSchema = z
  .object({
    firstName: z.string().min(1, "First name is required"),
    lastName: z.string().min(1, "Last name is required"),
    email: z.string().email("Valid email is required"),
    currentPassword: z.string().optional(),
    newPassword: z.string().optional(),
    confirmPassword: z.string().optional(),
  })
  .refine(
    (data) => {
      // If newPassword is provided, currentPassword is required
      if (data.newPassword && !data.currentPassword) {
        return false;
      }
      return true;
    },
    {
      message: "Current password is required to change password",
      path: ["currentPassword"],
    }
  )
  .refine(
    (data) => {
      // If newPassword is provided, it must be at least 8 characters
      if (data.newPassword && data.newPassword.length < 8) {
        return false;
      }
      return true;
    },
    {
      message: "New password must be at least 8 characters",
      path: ["newPassword"],
    }
  )
  .refine(
    (data) => {
      // If newPassword is provided, confirmPassword must match
      if (data.newPassword && data.newPassword !== data.confirmPassword) {
        return false;
      }
      return true;
    },
    {
      message: "Passwords don't match",
      path: ["confirmPassword"],
    }
  );

type ProfileFormData = z.infer<typeof profileSchema>;

export default function Settings() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading, user, refetchUser } = useAuth();
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const form = useForm<ProfileFormData>({
    resolver: zodResolver(profileSchema),
    defaultValues: {
      firstName: user?.firstName || "",
      lastName: user?.lastName || "",
      email: user?.email || "",
      currentPassword: "",
      newPassword: "",
      confirmPassword: "",
    },
  });

  // Update form when user data changes
  useEffect(() => {
    if (user) {
      form.reset({
        firstName: user.firstName || "",
        lastName: user.lastName || "",
        email: user.email || "",
        currentPassword: "",
        newPassword: "",
        confirmPassword: "",
      });
    }
  }, [user, form]);

  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
      window.location.href = "/";
    } catch (error) {
      console.error("Logout failed:", error);
      window.location.href = "/";
    }
  };

  const handleEditProfile = () => {
    setIsEditModalOpen(true);
  };

  const handleCloseEditModal = () => {
    setIsEditModalOpen(false);
    form.reset({
      firstName: user?.firstName || "",
      lastName: user?.lastName || "",
      email: user?.email || "",
      currentPassword: "",
      newPassword: "",
      confirmPassword: "",
    });
  };

  const onSubmit = async (data: ProfileFormData) => {
    setIsSubmitting(true);
    try {
      const updatePayload: any = {
        firstName: data.firstName,
        lastName: data.lastName,
        email: data.email,
      };

      // Only include password fields if newPassword is provided
      if (data.newPassword) {
        updatePayload.currentPassword = data.currentPassword;
        updatePayload.newPassword = data.newPassword;
      }

      const response = await apiRequest(
        "PUT",
        "/api/auth/profile",
        updatePayload
      );
      const result = await response.json();

      toast({
        title: "Success",
        description: result.message || "Profile updated successfully",
      });

      // Refetch user data to update the UI
      await refetchUser();
      handleCloseEditModal();
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to update profile",
        variant: "destructive",
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleManageUsers = () => {
    toast({
      title: "User Management",
      description: "Opening user management interface...",
    });
    window.location.href = "/users";
  };

  const handleExportData = () => {
    toast({
      title: "Data Export",
      description: "Preparing system backup and patient data export...",
    });
    // Implement data export functionality
    console.log("Export data functionality - to be implemented");
  };

  const handleApiConfig = () => {
    toast({
      title: "API Configuration",
      description: "Opening API configuration panel...",
    });
    // Implement API configuration modal/page
    console.log("API configuration functionality - to be implemented");
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

  return (
    <div className="min-h-screen flex bg-background">
      <Sidebar />

      <main className="flex-1 flex flex-col overflow-hidden">
        <Header
          title="Settings"
          subtitle="Manage your account and system preferences"
        />

        <div className="flex-1 overflow-auto p-6">
          <div className="w-full space-y-6">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle>User Profile</CardTitle>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleEditProfile}
                    data-testid="button-edit-profile"
                  >
                    <Edit2 className="w-4 h-4" />
                    <span className="hidden sm:inline">Edit Profile</span>
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center space-x-4">
                  <div className="w-16 h-16 bg-muted rounded-full flex items-center justify-center">
                    {user?.profileImageUrl ? (
                      <img
                        src={user.profileImageUrl}
                        alt="Profile"
                        className="w-16 h-16 rounded-full object-cover"
                      />
                    ) : (
                      <User className="w-8 h-8 text-muted-foreground" />
                    )}
                  </div>
                  <div>
                    <h3 className="font-semibold text-lg">
                      {user?.firstName} {user?.lastName}
                    </h3>
                    <p className="text-muted-foreground">{user?.email}</p>
                    <div className="flex items-center space-x-2 mt-1">
                      <Badge
                        variant={
                          user?.role === "admin" ? "default" : "secondary"
                        }
                      >
                        {user?.role === "admin" ? "Administrator" : "Staff"}
                      </Badge>
                      {user?.isActive && (
                        <Badge
                          variant="outline"
                          className="text-green-600 border-green-600"
                        >
                          Active
                        </Badge>
                      )}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>System Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <h4 className="font-medium">Environment</h4>
                    <p className="text-sm text-muted-foreground">
                      {process.env.NODE_ENV === "development"
                        ? "Development"
                        : "Production"}
                    </p>
                  </div>
                  <div>
                    <h4 className="font-medium">HIPAA Compliance</h4>
                    <p className="text-sm text-green-600">Active</p>
                  </div>
                  <div>
                    <h4 className="font-medium">DocuSign Integration</h4>
                    <p className="text-sm text-muted-foreground">
                      {String(import.meta.env.VITE_DOCUSIGN_ENABLED) === "true"
                        ? "Enabled"
                        : "Configured"}
                    </p>
                  </div>
                  <div>
                    <h4 className="font-medium">Email Notifications</h4>
                    <p className="text-sm text-muted-foreground">
                      {String(import.meta.env.VITE_SENDGRID_ENABLED) === "true"
                        ? "Enabled"
                        : "Configured"}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {user?.role === "admin" && (
              <Card>
                <CardHeader>
                  <CardTitle>Admin Settings</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium">User Management</h4>
                      <p className="text-sm text-muted-foreground">
                        Manage staff accounts and permissions
                      </p>
                    </div>
                    <Button
                      variant="outline"
                      onClick={handleManageUsers}
                      data-testid="button-manage-users"
                    >
                      Manage Users
                    </Button>
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium">System Backup</h4>
                      <p className="text-sm text-muted-foreground">
                        Export patient data and system configuration
                      </p>
                    </div>
                    <Button
                      variant="outline"
                      onClick={handleExportData}
                      data-testid="button-backup"
                    >
                      Export Data
                    </Button>
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium">API Configuration</h4>
                      <p className="text-sm text-muted-foreground">
                        Configure DocuSign and SendGrid settings
                      </p>
                    </div>
                    <Button
                      variant="outline"
                      onClick={handleApiConfig}
                      data-testid="button-api-config"
                    >
                      Configure APIs
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}

            <Card>
              <CardHeader>
                <CardTitle>Account Actions</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between p-4 border border-destructive/20 rounded-lg bg-destructive/5">
                  <div>
                    <h4 className="font-medium text-destructive">Sign Out</h4>
                    <p className="text-sm text-muted-foreground">
                      End your current session
                    </p>
                  </div>
                  <Button
                    variant="destructive"
                    onClick={handleLogout}
                    data-testid="button-logout"
                  >
                    <LogOut className="w-4 h-4 mr-2" />
                    Sign Out
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </main>

      {/* Edit Profile Modal */}
      <Dialog open={isEditModalOpen} onOpenChange={setIsEditModalOpen}>
        <DialogContent className="w-[95vw] max-w-[95vw] sm:max-w-md max-h-[95vh] overflow-auto rounded-lg p-4 sm:p-6 sm:m-0">
          <DialogHeader>
            <DialogTitle>Edit Profile</DialogTitle>
          </DialogHeader>

          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="firstName"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>First Name</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="Enter first name"
                        {...field}
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
                    <FormLabel>Last Name</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="Enter last name"
                        {...field}
                        data-testid="input-last-name"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="email"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Email</FormLabel>
                    <FormControl>
                      <Input
                        type="email"
                        placeholder="Enter email address"
                        {...field}
                        data-testid="input-email"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <div className="pt-4 border-t">
                <p className="text-sm text-muted-foreground mb-4">
                  Leave password fields empty if you don't want to change your
                  password.
                </p>

                <FormField
                  control={form.control}
                  name="currentPassword"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Current Password</FormLabel>
                      <FormControl>
                        <div className="relative">
                          <Input
                            type={showCurrentPassword ? "text" : "password"}
                            placeholder="Enter current password"
                            {...field}
                            data-testid="input-current-password"
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                            onClick={() =>
                              setShowCurrentPassword(!showCurrentPassword)
                            }
                          >
                            {showCurrentPassword ? (
                              <EyeOff className="h-4 w-4 text-muted-foreground" />
                            ) : (
                              <Eye className="h-4 w-4 text-muted-foreground" />
                            )}
                          </Button>
                        </div>
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="newPassword"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>New Password</FormLabel>
                      <FormControl>
                        <div className="relative">
                          <Input
                            type={showNewPassword ? "text" : "password"}
                            placeholder="Enter new password (min 8 characters)"
                            {...field}
                            data-testid="input-new-password"
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                            onClick={() => setShowNewPassword(!showNewPassword)}
                          >
                            {showNewPassword ? (
                              <EyeOff className="h-4 w-4 text-muted-foreground" />
                            ) : (
                              <Eye className="h-4 w-4 text-muted-foreground" />
                            )}
                          </Button>
                        </div>
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="confirmPassword"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Confirm New Password</FormLabel>
                      <FormControl>
                        <div className="relative">
                          <Input
                            type={showConfirmPassword ? "text" : "password"}
                            placeholder="Confirm new password"
                            {...field}
                            data-testid="input-confirm-password"
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                            onClick={() =>
                              setShowConfirmPassword(!showConfirmPassword)
                            }
                          >
                            {showConfirmPassword ? (
                              <EyeOff className="h-4 w-4 text-muted-foreground" />
                            ) : (
                              <Eye className="h-4 w-4 text-muted-foreground" />
                            )}
                          </Button>
                        </div>
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <div className="flex justify-end space-x-2 pt-4">
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleCloseEditModal}
                  disabled={isSubmitting}
                  data-testid="button-cancel-edit"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={isSubmitting}
                  data-testid="button-save-profile"
                >
                  {isSubmitting ? "Saving..." : "Save Changes"}
                </Button>
              </div>
            </form>
          </Form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
