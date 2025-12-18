import { useEffect } from "react";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import StatusBadge from "@/components/ui/status-badge";
import { CheckCircleIcon, ClockIcon, FileSignatureIcon } from "lucide-react";

interface PaginatedPatientsResponse {
  patients: any[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export default function ConsentForms() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading } = useAuth();

  // Automatic redirect to login removed - App.tsx routing handles authentication redirects

  const { data: patientsData, isLoading: patientsLoading } =
    useQuery<PaginatedPatientsResponse>({
      queryKey: ["/api/patients", "consent-forms"],
      queryFn: async () => {
        try {
          // Fetch with high limit to get all patients for consent forms view
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
      enabled: isAuthenticated, // SECURITY: Only fetch when authenticated
      retry: false,
    });

  // Extract patients array from paginated response
  const patients = patientsData?.patients || [];

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

  const pendingConsent = (patients as any[]).filter(
    (p: any) => p.status === "pending_consent" || p.status === "consent_sent"
  );

  const signedConsent = (patients as any[]).filter(
    (p: any) => p.status === "consent_signed" || p.status === "schedulable"
  );

  return (
    <div className="min-h-screen flex bg-background">
      <Sidebar />

      <main className="flex-1 flex flex-col overflow-hidden">
        <Header
          title="Consent Form Management"
          subtitle="Track consent form status and DocuSign integration"
        />

        <div className="flex-1 overflow-auto p-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <ClockIcon className="w-4 h-4 text-yellow-500 mr-2" />
                  Pending Consent ({pendingConsent.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                {patientsLoading ? (
                  <div className="text-center py-4">
                    <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>
                    <p className="text-sm text-muted-foreground">Loading...</p>
                  </div>
                ) : pendingConsent.length === 0 ? (
                  <div className="flex flex-col items-center justify-center text-center py-8">
                    <CheckCircleIcon className="w-10 h-10 text-green-500 mb-4" />
                    <p className="text-muted-foreground">
                      All consent forms are up to date!
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {pendingConsent.map((patient: any) => (
                      <div
                        key={patient.id}
                        className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 p-3 border border-border rounded-lg"
                        data-testid={`pending-consent-${patient.id}`}
                      >
                        <div className="flex-1 min-w-0">
                          <h4 className="font-medium truncate">
                            {patient.firstName} {patient.lastName}
                          </h4>
                          <p className="text-sm text-muted-foreground truncate">
                            {patient.email}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            Added:{" "}
                            {new Date(patient.createdAt).toLocaleDateString()}
                          </p>
                        </div>
                        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-2 sm:gap-2 flex-shrink-0">
                          <StatusBadge status={patient.status} />
                          {patient.status === "consent_sent" && (
                            <span className="text-xs text-blue-600 whitespace-nowrap">
                              Sent via DocuSign
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <CheckCircleIcon className="w-4 h-4 text-green-500 mr-2" />
                  Signed Consent ({signedConsent.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                {patientsLoading ? (
                  <div className="text-center py-4">
                    <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>
                    <p className="text-sm text-muted-foreground">Loading...</p>
                  </div>
                ) : signedConsent.length === 0 ? (
                  <div className="flex flex-col items-center justify-center text-center py-8">
                    <FileSignatureIcon className="w-10 h-10 text-muted-foreground mb-4" />
                    <p className="text-muted-foreground">
                      No signed consent forms yet
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {signedConsent.map((patient: any) => (
                      <div
                        key={patient.id}
                        className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 p-3 border border-border rounded-lg"
                        data-testid={`signed-consent-${patient.id}`}
                      >
                        <div className="flex-1 min-w-0">
                          <h4 className="font-medium truncate">
                            {patient.firstName} {patient.lastName}
                          </h4>
                          <p className="text-sm text-muted-foreground truncate">
                            {patient.email}
                          </p>
                          {patient.consentSignedAt && (
                            <p className="text-xs text-muted-foreground">
                              Signed:{" "}
                              {new Date(
                                patient.consentSignedAt
                              ).toLocaleDateString()}
                            </p>
                          )}
                        </div>
                        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-2 sm:gap-2 flex-shrink-0">
                          <StatusBadge status={patient.status} />
                          {patient.status === "schedulable" && (
                            <span className="text-xs text-purple-600 whitespace-nowrap">
                              Ready to schedule
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
}
