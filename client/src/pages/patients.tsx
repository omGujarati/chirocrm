import { useEffect, useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import StatusBadge from "@/components/ui/status-badge";
import {
  Pagination,
  PaginationContent,
  PaginationEllipsis,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination";
import ScheduleConsultationModal from "@/components/modals/schedule-consultation-modal";
import PatientDetailModal from "@/components/modals/patient-detail-modal";
import DropPatientModal from "@/components/modals/drop-patient-modal";
import UploadRecordsModal from "@/components/modals/upload-records-modal";
import PatientRecordsModal from "@/components/modals/patient-records-modal";
import PatientNotesModal from "@/components/modals/patient-notes-modal";
import {
  Calendar,
  Edit,
  Eye,
  FolderOpen,
  Send,
  StickyNote,
  Upload,
  UserX,
  MoreVertical,
  Plus,
  RotateCcw,
  UsersIcon,
  ClockIcon,
  SendIcon,
  CheckCircleIcon,
  CalendarCheckIcon,
  ShareIcon,
  UserIcon,
  FileTextIcon,
  MailIcon,
} from "lucide-react";

interface PaginatedPatientsResponse {
  patients: any[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export default function Patients() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading, user } = useAuth();
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [isScheduleModalOpen, setIsScheduleModalOpen] = useState(false);
  const [selectedPatientForScheduling, setSelectedPatientForScheduling] =
    useState<any>(null);
  const [isDetailModalOpen, setIsDetailModalOpen] = useState(false);
  const [selectedPatientForDetail, setSelectedPatientForDetail] =
    useState<any>(null);
  const [isDropModalOpen, setIsDropModalOpen] = useState(false);
  const [selectedPatientForDrop, setSelectedPatientForDrop] =
    useState<any>(null);
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
  const [selectedPatientForUpload, setSelectedPatientForUpload] =
    useState<any>(null);
  const [isRecordsModalOpen, setIsRecordsModalOpen] = useState(false);
  const [selectedPatientForRecords, setSelectedPatientForRecords] =
    useState<any>(null);
  const [isNotesModalOpen, setIsNotesModalOpen] = useState(false);
  const [selectedPatientForNotes, setSelectedPatientForNotes] =
    useState<any>(null);
  // Track language selection for each patient
  const [patientLanguageSelection, setPatientLanguageSelection] = useState<
    Record<string, "en" | "es">
  >({});
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(5);

  // Automatic redirect to login removed - App.tsx routing handles authentication redirects

  const {
    data: patientsData,
    isLoading: patientsLoading,
    error,
  } = useQuery<PaginatedPatientsResponse>({
    queryKey: [
      "/api/patients",
      statusFilter !== "all" ? statusFilter : "all",
      page,
      limit,
    ],
    queryFn: async () => {
      try {
        const statusParam =
          statusFilter !== "all" ? `&status=${statusFilter}` : "";
        const url = `/api/patients?page=${page}&limit=${limit}${statusParam}`;
        const response = await apiRequest("GET", url);
        const data = await response.json();

        // Handle backward compatibility: if response is an array (old format), convert it
        if (Array.isArray(data)) {
          // Old format - return all patients as if they're on one page
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

  // Extract patients and pagination from response
  const patients = patientsData?.patients || [];
  const pagination = patientsData?.pagination;

  // Handle page adjustments when pagination changes (e.g., after deletion)
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

  // FORCE clear patient cache on every render when not authenticated
  useEffect(() => {
    if (!isAuthenticated) {
      queryClient.removeQueries({ queryKey: ["/api/patients"] });
      queryClient.removeQueries({ queryKey: ["/api/dashboard/stats"] });
      console.log("[Patients] Forced cache clear - not authenticated");
    }
  }, [isAuthenticated, isLoading, queryClient]);

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

  // Admin-only mutation to override patient status
  const statusOverrideMutation = useMutation({
    mutationFn: async ({
      patientId,
      status,
    }: {
      patientId: string;
      status: string;
    }) => {
      const response = await apiRequest(
        "PATCH",
        `/api/patients/${patientId}/status`,
        { status }
      );
      return response.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/patients"] });
      toast({
        title: "Success",
        description: data.message || "Patient status updated successfully",
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
      toast({
        title: "Error",
        description: error.message || "Failed to update patient status",
        variant: "destructive",
      });
    },
  });

  const filteredPatients = (patients as any[]).filter((patient: any) => {
    const matchesSearch =
      searchTerm === "" ||
      patient.firstName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      patient.lastName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      patient.email.toLowerCase().includes(searchTerm.toLowerCase());

    return matchesSearch;
  });

  const handlePageChange = (newPage: number) => {
    setPage(newPage);
    // Scroll to top of the list
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleLimitChange = (newLimit: string) => {
    setLimit(Number(newLimit));
    setPage(1); // Reset to first page when changing limit
  };

  const handleStatusFilterChange = (newStatus: string) => {
    setStatusFilter(newStatus);
    setPage(1); // Reset to first page when changing status filter
  };

  const handleReset = () => {
    setSearchTerm("");
    setStatusFilter("all");
    setPage(1);
    setLimit(5);
  };

  // Show reset button if any filter or pagination differs from defaults
  const showResetButton =
    searchTerm !== "" || statusFilter !== "all" || page !== 1 || limit !== 5;

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

  return (
    <div className="min-h-screen flex bg-background">
      <Sidebar />

      <main className="flex-1 flex flex-col overflow-hidden relative z-0">
        <Header
          title="Patient Management"
          subtitle="Manage patient records and consent status"
        />

        <div className="flex-1 overflow-auto p-4 sm:p-6 relative z-0">
          <div className="mb-6 flex flex-col gap-4">
            <div className="w-full flex flex-col sm:flex-row gap-4 items-stretch sm:items-center justify-between">
              <div className="flex items-center gap-2 w-full">
                <Input
                  placeholder="Search patients..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="flex-1 sm:max-w-sm"
                  data-testid="input-search-patients"
                />

                <Select
                  value={statusFilter}
                  onValueChange={handleStatusFilterChange}
                >
                  <SelectTrigger
                    className="w-full sm:max-w-xs"
                    data-testid="select-status-filter"
                  >
                    <SelectValue placeholder="Filter by status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Status</SelectItem>
                    <SelectItem value="pending_consent">
                      Pending Consent
                    </SelectItem>
                    <SelectItem value="consent_sent">Consent Sent</SelectItem>
                    <SelectItem value="consent_signed">
                      Consent Signed
                    </SelectItem>
                    <SelectItem value="schedulable">Schedulable</SelectItem>
                    <SelectItem value="treatment_completed">
                      Treatment Completed
                    </SelectItem>
                    <SelectItem value="pending_records">
                      Pending Records
                    </SelectItem>
                    <SelectItem value="records_forwarded">
                      Records Forwarded
                    </SelectItem>
                    <SelectItem value="dropped">Dropped</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <Button
                onClick={() => {
                  const event = new CustomEvent("openAddPatientModal");
                  window.dispatchEvent(event);
                }}
                data-testid="button-add-patient"
                className="w-full sm:w-auto justify-end"
              >
                <Plus className="w-4 h-4 mr-2" />
                Add Patient
              </Button>
            </div>
          </div>

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>
                  Patients{" "}
                  {pagination
                    ? `(${pagination.total})`
                    : `(${filteredPatients.length})`}
                </CardTitle>
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
              {patientsLoading ? (
                <div className="text-center py-8">
                  <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                  <p className="text-muted-foreground">Loading patients...</p>
                </div>
              ) : filteredPatients.length === 0 ? (
                <div className="text-center py-8">
                  <UsersIcon className="w-10 h-10 text-muted-foreground mb-4" />
                  <p className="text-muted-foreground">No patients found</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {filteredPatients.map((patient: any) => {
                    // Determine which actions are available
                    const hasEdit = true;
                    const hasConsent =
                      patient.status === "pending_consent" ||
                      (patient.status === "consent_sent" &&
                        patient.consentLanguage);
                    const hasSchedule =
                      patient.status === "consent_signed" ||
                      patient.status === "schedulable";
                    const hasView = true;
                    const hasNotes = true;
                    const hasUpload =
                      user?.role === "staff" && patient.status !== "dropped";
                    const hasRecords =
                      user?.role === "staff" ||
                      user?.role === "attorney" ||
                      user?.role === "admin";
                    const hasDrop =
                      (user?.role === "attorney" || user?.role === "staff") &&
                      patient.status !== "dropped";
                    const hasAdminOverride = user?.role === "admin";

                    return (
                      <div
                        key={patient.id}
                        className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 p-4 border border-border rounded-lg hover:bg-accent/50 transition-colors"
                        data-testid={`patient-item-${patient.id}`}
                      >
                        <div className="flex items-center space-x-4 flex-1 min-w-0">
                          <div className="w-10 h-10 bg-muted rounded-full flex items-center justify-center flex-shrink-0">
                            <div className="w-10 h-10 bg-muted rounded-full flex items-center justify-center flex-shrink-0">
                              <span className="text-sm font-medium">
                                {patient.firstName?.charAt(0)?.toUpperCase()}
                                {patient.lastName?.charAt(0)?.toUpperCase()}
                              </span>
                            </div>
                          </div>
                          <div className="flex-1 min-w-0">
                            <h4 className="font-medium text-foreground">
                              {patient.firstName?.charAt(0)?.toUpperCase() +
                                patient.firstName?.slice(1)}{" "}
                              {patient.lastName?.charAt(0)?.toUpperCase() +
                                patient.lastName?.slice(1)}
                            </h4>
                            <p className="text-sm text-muted-foreground truncate">
                              {patient.email}
                            </p>
                            {patient.phone && (
                              <p className="text-xs text-muted-foreground">
                                {patient.phone}
                              </p>
                            )}
                            {patient.assignedAttorney && (
                              <div className="flex items-center gap-1 mt-1">
                                <p className="text-xs text-muted-foreground">
                                  Assignee: {patient.assignedAttorney.firstName}{" "}
                                  {patient.assignedAttorney.lastName}
                                </p>
                              </div>
                            )}
                          </div>
                        </div>

                        <div className="flex items-center justify-between sm:justify-end gap-3 flex-shrink-0">
                          <div className="flex items-center gap-2">
                            <StatusBadge status={patient.status} />
                            {hasAdminOverride && (
                              <DropdownMenu>
                                <DropdownMenuTrigger asChild>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    className="h-8 w-8 p-0 border border-dashed border-gray-400 hover:border-blue-500"
                                    title="Override Status (Admin Only)"
                                    data-testid={`button-status-override-${patient.id}`}
                                    onClick={(e) => e.stopPropagation()}
                                  >
                                    ⚙️
                                  </Button>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end">
                                  <div className="px-2 py-1.5 text-xs font-semibold text-muted-foreground">
                                    Admin Override
                                  </div>
                                  <DropdownMenuSeparator />
                                  <DropdownMenuItem
                                    onClick={() =>
                                      statusOverrideMutation.mutate({
                                        patientId: patient.id,
                                        status: "pending_consent",
                                      })
                                    }
                                    disabled={
                                      patient.status === "pending_consent" ||
                                      statusOverrideMutation.isPending
                                    }
                                  >
                                    <ClockIcon className="w-4 h-4 mr-2 text-yellow-500" />
                                    Pending Consent
                                  </DropdownMenuItem>
                                  <DropdownMenuItem
                                    onClick={() =>
                                      statusOverrideMutation.mutate({
                                        patientId: patient.id,
                                        status: "consent_sent",
                                      })
                                    }
                                    disabled={
                                      patient.status === "consent_sent" ||
                                      statusOverrideMutation.isPending
                                    }
                                  >
                                    <SendIcon className="w-4 h-4 mr-2 text-blue-500" />
                                    Consent Sent
                                  </DropdownMenuItem>
                                  <DropdownMenuItem
                                    onClick={() =>
                                      statusOverrideMutation.mutate({
                                        patientId: patient.id,
                                        status: "consent_signed",
                                      })
                                    }
                                    disabled={
                                      patient.status === "consent_signed" ||
                                      statusOverrideMutation.isPending
                                    }
                                  >
                                    <CheckCircleIcon className="w-4 h-4 mr-2 text-green-500" />
                                    Consent Signed
                                  </DropdownMenuItem>
                                  <DropdownMenuItem
                                    onClick={() =>
                                      statusOverrideMutation.mutate({
                                        patientId: patient.id,
                                        status: "schedulable",
                                      })
                                    }
                                    disabled={
                                      patient.status === "schedulable" ||
                                      statusOverrideMutation.isPending
                                    }
                                  >
                                    <CalendarCheckIcon className="w-4 h-4 mr-2 text-purple-500" />
                                    Schedulable
                                  </DropdownMenuItem>
                                  <DropdownMenuItem
                                    onClick={() =>
                                      statusOverrideMutation.mutate({
                                        patientId: patient.id,
                                        status: "treatment_completed",
                                      })
                                    }
                                    disabled={
                                      patient.status ===
                                        "treatment_completed" ||
                                      statusOverrideMutation.isPending
                                    }
                                  >
                                    <CheckCircleIcon className="w-4 h-4 mr-2 text-emerald-500" />
                                    Treatment Completed
                                  </DropdownMenuItem>
                                  <DropdownMenuItem
                                    onClick={() =>
                                      statusOverrideMutation.mutate({
                                        patientId: patient.id,
                                        status: "pending_records",
                                      })
                                    }
                                    disabled={
                                      patient.status === "pending_records" ||
                                      statusOverrideMutation.isPending
                                    }
                                  >
                                    <FileTextIcon className="w-4 h-4 mr-2 text-orange-500" />
                                    Pending Records
                                  </DropdownMenuItem>
                                  <DropdownMenuItem
                                    onClick={() =>
                                      statusOverrideMutation.mutate({
                                        patientId: patient.id,
                                        status: "records_forwarded",
                                      })
                                    }
                                    disabled={
                                      patient.status === "records_forwarded" ||
                                      statusOverrideMutation.isPending
                                    }
                                  >
                                    <ShareIcon className="w-4 h-4 mr-2 text-indigo-500" />
                                    Records Forwarded
                                  </DropdownMenuItem>
                                </DropdownMenuContent>
                              </DropdownMenu>
                            )}
                          </div>
                          <span className="text-xs text-muted-foreground hidden sm:inline">
                            {new Date(patient.createdAt).toLocaleDateString()}
                          </span>

                          {/* Desktop: Show all action buttons */}
                          <div className="hidden md:flex space-x-1 items-center">
                            {hasEdit && (
                              <Button
                                variant="ghost"
                                size="sm"
                                title="Edit Patient"
                                data-testid={`button-edit-${patient.id}`}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedPatientForDetail(patient);
                                  setIsDetailModalOpen(true);
                                }}
                              >
                                <Edit size={14} />
                              </Button>
                            )}

                            {hasConsent &&
                              patient.status === "pending_consent" && (
                                <>
                                  <Select
                                    value={
                                      patientLanguageSelection[patient.id] ||
                                      "en"
                                    }
                                    onValueChange={(value: "en" | "es") => {
                                      setPatientLanguageSelection((prev) => ({
                                        ...prev,
                                        [patient.id]: value as "en" | "es",
                                      }));
                                    }}
                                  >
                                    <SelectTrigger
                                      className="h-8 w-24 text-xs"
                                      onClick={(e) => e.stopPropagation()}
                                    >
                                      <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                      <SelectItem value="en">
                                        English
                                      </SelectItem>
                                      <SelectItem value="es">
                                        Español
                                      </SelectItem>
                                    </SelectContent>
                                  </Select>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    title="Send Consent"
                                    onClick={(e) => {
                                      e.stopPropagation();
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
                                    <Send size={14} />
                                  </Button>
                                </>
                              )}

                            {hasSchedule && (
                              <Button
                                variant="ghost"
                                size="sm"
                                title="Schedule Consultation"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedPatientForScheduling(patient);
                                  setIsScheduleModalOpen(true);
                                }}
                                data-testid={`button-schedule-${patient.id}`}
                              >
                                <Calendar size={14} />
                              </Button>
                            )}

                            {hasView && (
                              <Button
                                variant="ghost"
                                size="sm"
                                title="View Details"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedPatientForDetail(patient);
                                  setIsDetailModalOpen(true);
                                }}
                                data-testid={`button-view-${patient.id}`}
                              >
                                <Eye size={14} />
                              </Button>
                            )}

                            {hasNotes && (
                              <Button
                                variant="ghost"
                                size="sm"
                                title="Patient Notes"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedPatientForNotes(patient);
                                  setIsNotesModalOpen(true);
                                }}
                                data-testid={`button-notes-${patient.id}`}
                              >
                                <StickyNote size={14} />
                              </Button>
                            )}

                            {hasUpload && (
                              <Button
                                variant="ghost"
                                size="sm"
                                title="Upload Records"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedPatientForUpload(patient);
                                  setIsUploadModalOpen(true);
                                }}
                              >
                                <Upload size={14} />
                              </Button>
                            )}

                            {hasRecords && (
                              <Button
                                variant="ghost"
                                size="sm"
                                title="View Records"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedPatientForRecords(patient);
                                  setIsRecordsModalOpen(true);
                                }}
                                data-testid={`button-records-${patient.id}`}
                              >
                                <FolderOpen size={14} />
                              </Button>
                            )}

                            {hasDrop && (
                              <Button
                                variant="ghost"
                                size="sm"
                                title="Drop Patient"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedPatientForDrop(patient);
                                  setIsDropModalOpen(true);
                                }}
                                className="text-red-600 hover:text-red-700 hover:bg-red-50"
                              >
                                <UserX size={14} />
                              </Button>
                            )}
                          </div>

                          {/* Mobile: Show "..." menu */}
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="md:hidden h-8 w-8 p-0"
                                onClick={(e) => e.stopPropagation()}
                                aria-label="More options"
                              >
                                <MoreVertical size={16} />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="w-48">
                              {hasEdit && (
                                <DropdownMenuItem
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedPatientForDetail(patient);
                                    setIsDetailModalOpen(true);
                                  }}
                                >
                                  <Edit size={14} className="mr-2" />
                                  Edit Patient
                                </DropdownMenuItem>
                              )}
                              {hasConsent &&
                                patient.status === "pending_consent" && (
                                  <>
                                    <div className="px-2 py-1.5">
                                      <Select
                                        value={
                                          patientLanguageSelection[
                                            patient.id
                                          ] || "en"
                                        }
                                        onValueChange={(value: "en" | "es") => {
                                          setPatientLanguageSelection(
                                            (prev) => ({
                                              ...prev,
                                              [patient.id]: value as
                                                | "en"
                                                | "es",
                                            })
                                          );
                                        }}
                                      >
                                        <SelectTrigger className="h-8 w-full text-xs">
                                          <SelectValue />
                                        </SelectTrigger>
                                        <SelectContent>
                                          <SelectItem value="en">
                                            English
                                          </SelectItem>
                                          <SelectItem value="es">
                                            Español
                                          </SelectItem>
                                        </SelectContent>
                                      </Select>
                                    </div>
                                    <DropdownMenuItem
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        const language =
                                          patientLanguageSelection[
                                            patient.id
                                          ] || "en";
                                        sendConsentMutation.mutate({
                                          patientId: patient.id,
                                          language,
                                        });
                                      }}
                                      disabled={sendConsentMutation.isPending}
                                    >
                                      <Send size={14} className="mr-2" />
                                      Send Consent
                                    </DropdownMenuItem>
                                  </>
                                )}
                              {hasSchedule && (
                                <DropdownMenuItem
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedPatientForScheduling(patient);
                                    setIsScheduleModalOpen(true);
                                  }}
                                >
                                  <Calendar size={14} className="mr-2" />
                                  Schedule Consultation
                                </DropdownMenuItem>
                              )}
                              {hasView && (
                                <DropdownMenuItem
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedPatientForDetail(patient);
                                    setIsDetailModalOpen(true);
                                  }}
                                >
                                  <Eye size={14} className="mr-2" />
                                  View Details
                                </DropdownMenuItem>
                              )}
                              {hasNotes && (
                                <DropdownMenuItem
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedPatientForNotes(patient);
                                    setIsNotesModalOpen(true);
                                  }}
                                >
                                  <StickyNote size={14} className="mr-2" />
                                  Patient Notes
                                </DropdownMenuItem>
                              )}
                              {hasUpload && (
                                <DropdownMenuItem
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedPatientForUpload(patient);
                                    setIsUploadModalOpen(true);
                                  }}
                                >
                                  <Upload size={14} className="mr-2" />
                                  Upload Records
                                </DropdownMenuItem>
                              )}
                              {hasRecords && (
                                <DropdownMenuItem
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedPatientForRecords(patient);
                                    setIsRecordsModalOpen(true);
                                  }}
                                >
                                  <FolderOpen size={14} className="mr-2" />
                                  View Records
                                </DropdownMenuItem>
                              )}
                              {hasDrop && (
                                <DropdownMenuItem
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedPatientForDrop(patient);
                                    setIsDropModalOpen(true);
                                  }}
                                  className="text-red-600"
                                >
                                  <UserX size={14} className="mr-2" />
                                  Drop Patient
                                </DropdownMenuItem>
                              )}
                              <div className="px-2 py-1 text-xs text-muted-foreground border-t mt-1 pt-1">
                                {new Date(
                                  patient.createdAt
                                ).toLocaleDateString()}
                              </div>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      </div>
                    );
                  })}

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
                          of {pagination.total} patients
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

      <ScheduleConsultationModal
        open={isScheduleModalOpen}
        onOpenChange={setIsScheduleModalOpen}
        patient={selectedPatientForScheduling}
      />

      <PatientDetailModal
        open={isDetailModalOpen}
        onOpenChange={setIsDetailModalOpen}
        patient={selectedPatientForDetail}
      />

      <DropPatientModal
        open={isDropModalOpen}
        onOpenChange={setIsDropModalOpen}
        patient={selectedPatientForDrop}
      />

      <UploadRecordsModal
        isOpen={isUploadModalOpen}
        onClose={() => setIsUploadModalOpen(false)}
        patientId={selectedPatientForUpload?.id || ""}
        patientName={
          selectedPatientForUpload
            ? `${selectedPatientForUpload.firstName} ${selectedPatientForUpload.lastName}`
            : ""
        }
      />

      <PatientRecordsModal
        isOpen={isRecordsModalOpen}
        onClose={() => setIsRecordsModalOpen(false)}
        patientId={selectedPatientForRecords?.id || ""}
        patientName={
          selectedPatientForRecords
            ? `${selectedPatientForRecords.firstName} ${selectedPatientForRecords.lastName}`
            : ""
        }
      />

      <PatientNotesModal
        open={isNotesModalOpen}
        onOpenChange={setIsNotesModalOpen}
        patient={selectedPatientForNotes}
      />
    </div>
  );
}
