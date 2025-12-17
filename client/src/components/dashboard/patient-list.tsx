import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import StatusBadge from "@/components/ui/status-badge";
import { useState } from "react";
import { useAuth } from "@/hooks/useAuth";
import {
  ArrowRightIcon,
  CalendarPlusIcon,
  EditIcon,
  EyeIcon,
  LockIcon,
  SendIcon,
  UserIcon,
  UsersIcon,
} from "lucide-react";

export default function PatientList() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { isAuthenticated } = useAuth();
  const [statusFilter, setStatusFilter] = useState("all");
  // Track language selection for each patient
  const [patientLanguageSelection, setPatientLanguageSelection] = useState<
    Record<string, "en" | "es">
  >({});

  const { data: patientsData, isLoading } = useQuery({
    queryKey: [
      "/api/patients",
      "dashboard",
      statusFilter !== "all" ? statusFilter : "all",
    ],
    queryFn: async () => {
      try {
        const statusParam =
          statusFilter !== "all" ? `&status=${statusFilter}` : "";
        // Fetch with limit of 10 for dashboard preview
        const url = `/api/patients?page=1&limit=10${statusParam}`;
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

  // Don't render any patient data if not authenticated
  if (!isAuthenticated) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Recent Patients</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8">
            <LockIcon className="w-10 h-10 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">
              Please log in to view patients
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const sendConsentMutation = useMutation({
    mutationFn: async ({
      patientId,
      language,
    }: {
      patientId: string;
      language: "en" | "es";
    }) => {
      await apiRequest("POST", `/api/patients/${patientId}/send-consent`, {
        language,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/patients"] });
      toast({
        title: "Success",
        description: "Consent form sent successfully",
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
        description: "Failed to send consent form",
        variant: "destructive",
      });
    },
  });

  // Show only the first 4 patients for dashboard view
  const displayPatients = (patients as any[]).slice(0, 4);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Recent Patients</CardTitle>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger
              className="w-40"
              data-testid="select-patient-status-filter"
            >
              <SelectValue placeholder="All Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="pending_consent">Pending Consent</SelectItem>
              <SelectItem value="consent_sent">Consent Sent</SelectItem>
              <SelectItem value="consent_signed">Consent Signed</SelectItem>
              <SelectItem value="schedulable">Schedulable</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="flex items-center space-x-4 p-4">
                <div className="w-10 h-10 bg-muted rounded-full animate-pulse"></div>
                <div className="flex-1 space-y-2">
                  <div className="h-4 bg-muted rounded animate-pulse w-1/3"></div>
                  <div className="h-3 bg-muted rounded animate-pulse w-1/2"></div>
                </div>
              </div>
            ))}
          </div>
        ) : displayPatients.length === 0 ? (
          <div className="flex flex-col items-center justify-center text-center py-8">
            <UsersIcon className="w-10 h-10 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">No patients found</p>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {displayPatients.map((patient: any) => (
              <div
                key={patient.id}
                className="p-6 hover:bg-accent/50 transition-colors"
                data-testid={`patient-list-item-${patient.id}`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className="w-10 h-10 bg-muted rounded-full flex items-center justify-center">
                      <UserIcon className="w-4 h-4 text-muted-foreground" />
                    </div>
                    <div>
                      <h4 className="font-medium text-foreground">
                        {patient.firstName} {patient.lastName}
                      </h4>
                      <p className="text-sm text-muted-foreground">
                        {patient.email}
                      </p>
                      {patient.phone && (
                        <p className="text-xs text-muted-foreground">
                          {patient.phone}
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center space-x-3">
                    <StatusBadge status={patient.status} />
                    <span className="text-xs text-muted-foreground">
                      {new Date(patient.createdAt).toLocaleDateString()}
                    </span>

                    <div className="flex space-x-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        title="Edit Patient"
                        data-testid={`button-edit-patient-${patient.id}`}
                      >
                        <EditIcon className="w-4 h-4" />
                      </Button>

                      {(patient.status === "pending_consent" ||
                        (patient.status === "consent_sent" &&
                          patient.consentLanguage)) && (
                        <div className="flex items-center gap-1">
                          {patient.status === "pending_consent" ? (
                            <>
                              <Select
                                value={
                                  patientLanguageSelection[patient.id] || "en"
                                }
                                onValueChange={(value: "en" | "es") => {
                                  setPatientLanguageSelection((prev) => ({
                                    ...prev,
                                    [patient.id]: value as "en" | "es",
                                  }));
                                }}
                              >
                                <SelectTrigger className="h-8 w-24 text-xs">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="en">English</SelectItem>
                                  <SelectItem value="es">Español</SelectItem>
                                </SelectContent>
                              </Select>
                              <Button
                                variant="ghost"
                                size="sm"
                                title="Send Consent"
                                onClick={() => {
                                  const language =
                                    patientLanguageSelection[patient.id] ||
                                    "en";
                                  sendConsentMutation.mutate({
                                    patientId: patient.id,
                                    language,
                                  });
                                }}
                                disabled={sendConsentMutation.isPending}
                                data-testid={`button-send-consent-${patient.id}`}
                              >
                                <SendIcon className="w-4 h-4" />
                              </Button>
                            </>
                          ) : (
                            <>
                              <Select
                                value={patient.consentLanguage || "en"}
                                onValueChange={(value: "en" | "es") => {
                                  if (value !== patient.consentLanguage) {
                                    sendConsentMutation.mutate({
                                      patientId: patient.id,
                                      language: value,
                                    });
                                  }
                                }}
                                disabled={sendConsentMutation.isPending}
                              >
                                <SelectTrigger className="h-8 w-24 text-xs">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="en">English</SelectItem>
                                  <SelectItem value="es">Español</SelectItem>
                                </SelectContent>
                              </Select>
                            </>
                          )}
                        </div>
                      )}

                      {(patient.status === "consent_signed" ||
                        patient.status === "schedulable") && (
                        <Button
                          variant="ghost"
                          size="sm"
                          title="Schedule Appointment"
                          data-testid={`button-schedule-appointment-${patient.id}`}
                        >
                          <CalendarPlusIcon className="w-4 h-4" />
                        </Button>
                      )}

                      <Button
                        variant="ghost"
                        size="sm"
                        title="View Details"
                        data-testid={`button-view-details-${patient.id}`}
                      >
                        <EyeIcon className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {displayPatients.length > 0 && (
          <div className="px-6 py-4 border-t border-border">
            <button
              className="w-full text-sm text-muted-foreground hover:text-foreground"
              onClick={() => (window.location.href = "/patients")}
              data-testid="button-view-all-patients"
            >
              View All Patients <ArrowRightIcon className="w-4 h-4 ml-2" />
            </button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
