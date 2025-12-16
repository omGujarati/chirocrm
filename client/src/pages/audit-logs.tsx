import { useEffect } from "react";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { useQuery } from "@tanstack/react-query";
import { AuditLog } from "@shared/schema";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { HistoryIcon, LockIcon, ShieldIcon } from "lucide-react";

export default function AuditLogs() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading, user } = useAuth();

  // Automatic redirect to login removed - App.tsx routing handles authentication redirects

  const { data: auditLogs = [], isLoading: logsLoading } = useQuery<AuditLog[]>(
    {
      queryKey: ["/api/audit-logs"],
      retry: false,
    }
  );

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

  // Check if user has admin role
  if (user?.role !== "admin") {
    return (
      <div className="min-h-screen flex bg-background">
        <Sidebar />

        <main className="flex-1 flex flex-col overflow-hidden">
          <Header title="Audit Logs" subtitle="HIPAA compliance tracking" />

          <div className="flex-1 flex items-center justify-center">
            <Card className="w-full max-w-md mx-4">
              <CardContent className="pt-6">
                <div className="text-center">
                  <LockIcon className="w-10 h-10 text-muted-foreground mb-4" />
                  <h3 className="text-lg font-semibold text-foreground mb-2">
                    Access Restricted
                  </h3>
                  <p className="text-muted-foreground">
                    Only administrators can view audit logs.
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </main>
      </div>
    );
  }

  const getActionColor = (action: string) => {
    switch (action) {
      case "created":
        return "bg-green-100 text-green-800 border-green-200";
      case "updated":
        return "bg-blue-100 text-blue-800 border-blue-200";
      case "deleted":
        return "bg-red-100 text-red-800 border-red-200";
      case "viewed":
        return "bg-gray-100 text-gray-800 border-gray-200";
      case "consent_sent":
        return "bg-yellow-100 text-yellow-800 border-yellow-200";
      case "consent_signed":
        return "bg-purple-100 text-purple-800 border-purple-200";
      default:
        return "bg-gray-100 text-gray-800 border-gray-200";
    }
  };

  return (
    <div className="min-h-screen flex bg-background">
      <Sidebar />

      <main className="flex-1 flex flex-col overflow-hidden">
        <Header
          title="Audit Logs"
          subtitle="HIPAA compliance tracking and activity monitoring"
        />

        <div className="flex-1 overflow-auto p-6">
          <div className="mb-6">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <ShieldIcon className="w-4 h-4 text-primary" />
                <span className="text-sm font-medium">
                  HIPAA Compliance Active
                </span>
              </div>
              <div className="text-sm text-muted-foreground">
                Total Events: {auditLogs.length}
              </div>
            </div>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Activity Timeline</CardTitle>
            </CardHeader>
            <CardContent>
              {logsLoading ? (
                <div className="text-center py-8">
                  <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                  <p className="text-muted-foreground">Loading audit logs...</p>
                </div>
              ) : auditLogs.length === 0 ? (
                <div className="text-center py-8">
                  <HistoryIcon className="w-10 h-10 text-muted-foreground mb-4" />
                  <p className="text-muted-foreground">No audit logs found</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {auditLogs.map((log) => (
                    <div
                      key={log.id}
                      className="flex items-start space-x-4 p-4 border border-border rounded-lg"
                      data-testid={`audit-log-${log.id}`}
                    >
                      <div className="flex-shrink-0 w-2 h-2 mt-2 bg-primary rounded-full"></div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center space-x-2 mb-1">
                              <Badge
                                className={`text-xs font-medium border ${getActionColor(
                                  log.action
                                )}`}
                              >
                                {log.action}
                              </Badge>
                              <span className="text-sm font-medium">
                                {log.resourceType}
                              </span>
                              <span className="text-xs text-muted-foreground">
                                ID: {log.resourceId}
                              </span>
                            </div>
                            <p className="text-sm text-muted-foreground">
                              User ID: {log.userId}
                            </p>
                            {log.patientId && (
                              <p className="text-sm text-muted-foreground">
                                Patient ID: {log.patientId}
                              </p>
                            )}
                            {log.details != null && (
                              <div className="mt-2 text-xs bg-muted p-2 rounded">
                                <pre>
                                  {JSON.stringify(log.details, null, 2)}
                                </pre>
                              </div>
                            )}
                          </div>
                          <div className="text-right">
                            <p className="text-xs text-muted-foreground">
                              {log.createdAt
                                ? new Date(log.createdAt).toLocaleString()
                                : "N/A"}
                            </p>
                            {log.ipAddress && (
                              <p className="text-xs text-muted-foreground">
                                IP: {log.ipAddress}
                              </p>
                            )}
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
    </div>
  );
}
