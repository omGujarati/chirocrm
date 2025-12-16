import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useAuth } from "@/hooks/useAuth";
import { formatDistanceToNow } from "date-fns";
import { useState, useEffect } from "react";
import {
  DownloadIcon,
  EyeIcon,
  FileIcon,
  FileText,
  Image as ImageIcon,
  FolderOpenIcon,
  InfoIcon,
  TrashIcon,
  XIcon,
} from "lucide-react";

interface PatientRecord {
  id: string;
  fileName: string;
  filePath?: string | null; // Legacy field - may be null for S3 storage
  fileSize?: number;
  mimeType?: string;
  description?: string;
  uploadedBy: string;
  createdAt: string;
  // S3 storage fields
  s3Key?: string | null; // S3 object key - bucket name comes from server env var
  storageType?: "local" | "s3";
}

interface PatientRecordsModalProps {
  isOpen: boolean;
  onClose: () => void;
  patientId: string;
  patientName: string;
}

export default function PatientRecordsModal({
  isOpen,
  onClose,
  patientId,
  patientName,
}: PatientRecordsModalProps) {
  const { toast } = useToast();
  const { user } = useAuth();
  const [previewRecord, setPreviewRecord] = useState<PatientRecord | null>(
    null
  );
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewApiUrl, setPreviewApiUrl] = useState<string | null>(null);
  const [previewToken, setPreviewToken] = useState<string | null>(null);
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);

  const { data: records = [], isLoading } = useQuery<PatientRecord[]>({
    queryKey: ["/api/patients", patientId, "records"],
    enabled: isOpen && !!patientId,
  });

  const deleteMutation = useMutation({
    mutationFn: async (recordId: string) => {
      return apiRequest(
        "DELETE",
        `/api/patients/${patientId}/records/${recordId}`
      );
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Record deleted successfully",
      });
      queryClient.invalidateQueries({
        queryKey: ["/api/patients", patientId, "records"],
      });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to delete record",
        variant: "destructive",
      });
    },
  });

  const formatFileSize = (bytes?: number) => {
    if (!bytes) return "Unknown size";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
    return `${Math.round(bytes / (1024 * 1024))} MB`;
  };

  const getFileIcon = (mimeType?: string) => {
    if (!mimeType) return FileIcon;
    if (mimeType.includes("pdf")) return FileText;
    if (mimeType.includes("image")) return ImageIcon;
    return FileIcon;
  };

  const isPreviewable = (mimeType?: string) => {
    if (!mimeType) return false;
    return mimeType.includes("pdf") || mimeType.includes("image");
  };

  const handlePreview = async (record: PatientRecord) => {
    if (!isPreviewable(record.mimeType)) {
      toast({
        title: "Preview not available",
        description: "Preview is only available for PDF and image files",
        variant: "destructive",
      });
      return;
    }

    setIsLoadingPreview(true);
    try {
      // First, get a time-limited preview token (15 minutes expiration)
      const tokenResponse = await fetch(
        `/api/patients/${patientId}/records/${record.id}/preview-token`,
        {
          method: "GET",
          credentials: "include", // Include cookies for authentication
        }
      );

      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.json().catch(() => ({}));
        throw new Error(errorData.message || "Failed to get preview token");
      }

      const { token } = await tokenResponse.json();

      // Fetch the file as a blob using the time-limited token
      const response = await fetch(
        `/api/patients/${patientId}/records/${
          record.id
        }/preview?token=${encodeURIComponent(token)}`,
        {
          method: "GET",
          credentials: "include", // Include cookies for authentication
        }
      );

      if (!response.ok) {
        // Try to get error message from response
        const contentType = response.headers.get("content-type") || "";
        if (contentType.includes("json")) {
          const errorData = await response.json().catch(() => ({}));
          throw new Error(
            errorData.message || `HTTP ${response.status}: Preview failed`
          );
        } else {
          const errorText = await response.text().catch(() => "");
          throw new Error(
            `HTTP ${response.status}: ${errorText || "Preview failed"}`
          );
        }
      }

      // Get content type from response headers
      const contentType = response.headers.get("content-type") || "";

      // Check if we got an error response (JSON or HTML instead of file)
      if (contentType.includes("application/json")) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(
          errorData.message || "Server returned error instead of file"
        );
      }

      if (contentType.includes("text/html")) {
        // Might be Vite's catch-all route - this shouldn't happen but handle it
        const htmlText = await response.text();
        if (htmlText.includes("<!DOCTYPE html") || htmlText.includes("<html")) {
          throw new Error(
            "Received HTML instead of file. Check server routing."
          );
        }
      }

      // Create blob URL from the response
      const blob = await response.blob();

      // Verify blob has content
      if (!blob || blob.size === 0) {
        throw new Error("Received empty file response");
      }

      // Verify blob is not an error response (only check if type is explicitly set)
      if (blob.type) {
        // If blob type is JSON, it's definitely an error
        if (blob.type.includes("application/json")) {
          const text = await blob.text();
          try {
            const errorData = JSON.parse(text);
            throw new Error(
              errorData.message || "Server returned error response"
            );
          } catch {
            throw new Error("Server returned JSON error response");
          }
        }

        // If blob type is HTML, it's probably an error page
        if (blob.type.includes("text/html")) {
          const text = await blob.text();
          if (text.includes("<!DOCTYPE") || text.includes("<html")) {
            throw new Error("Received HTML error page instead of file");
          }
        }
      }

      // If blob type is empty but we have a valid content-type header and size > 0, it's likely valid
      // Don't reject based on missing blob.type alone

      const blobUrl = window.URL.createObjectURL(blob);
      // Also create direct API URL for iframe with token (bypasses blob URL restrictions)
      const apiUrl = `/api/patients/${patientId}/records/${
        record.id
      }/preview?token=${encodeURIComponent(token)}`;

      setPreviewRecord(record);
      setPreviewUrl(blobUrl);
      setPreviewApiUrl(apiUrl);
      setPreviewToken(token);
    } catch (error: any) {
      console.error("Preview error:", error);
      toast({
        title: "Error",
        description: error.message || "Failed to load preview",
        variant: "destructive",
      });
    } finally {
      setIsLoadingPreview(false);
    }
  };

  const handleClosePreview = () => {
    // Clean up blob URL to prevent memory leaks
    if (previewUrl) {
      window.URL.revokeObjectURL(previewUrl);
      setPreviewUrl(null);
    }
    setPreviewApiUrl(null);
    setPreviewToken(null);
    setPreviewRecord(null);
    setIsLoadingPreview(false);
  };

  // Cleanup blob URL on unmount or when modal closes
  useEffect(() => {
    return () => {
      if (previewUrl) {
        window.URL.revokeObjectURL(previewUrl);
      }
    };
  }, [previewUrl]);

  // Cleanup when main modal closes
  useEffect(() => {
    if (!isOpen) {
      handleClosePreview();
    }
  }, [isOpen]);

  const handleDownload = async (record: PatientRecord) => {
    try {
      // Use the secure download endpoint
      const response = await fetch(
        `/api/patients/${patientId}/records/${record.id}/download`,
        {
          method: "GET",
          credentials: "include", // Include cookies for authentication
        }
      );

      if (!response.ok) {
        const errorData = await response
          .json()
          .catch(() => ({ message: "Download failed" }));
        throw new Error(errorData.message || `HTTP ${response.status}`);
      }

      // Get the blob from the response
      const blob = await response.blob();

      // Create a temporary URL and trigger download
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = record.fileName;
      document.body.appendChild(a);
      a.click();

      // Cleanup
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      toast({
        title: "Success",
        description: `${record.fileName} downloaded successfully`,
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to download file",
        variant: "destructive",
      });
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent
        className="w-[95vw] max-w-[95vw] sm:max-w-md md:max-w-2xl max-h-[95vh] overflow-auto rounded-lg p-4 sm:p-6 sm:m-0 flex flex-col"
        data-testid="modal-patient-records"
      >
        <DialogHeader>
          <DialogTitle>Patient Records</DialogTitle>
          <p className="text-sm text-muted-foreground">
            Medical records for {patientName}
          </p>
        </DialogHeader>

        <div className="space-y-4">
          {isLoading ? (
            <div className="text-center py-8">
              <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
              <p className="text-muted-foreground">Loading records...</p>
            </div>
          ) : records.length === 0 ? (
            <div className="flex flex-col items-center justify-center text-center py-8">
              <FolderOpenIcon className="w-10 h-10 text-muted-foreground mb-4" />
              <p className="text-muted-foreground">No records uploaded yet</p>
            </div>
          ) : (
            <div className="space-y-3">
              {records.map((record) => (
                <Card
                  key={record.id}
                  className="hover:bg-accent/50 transition-colors"
                >
                  <CardContent className="p-3 sm:p-4">
                    <div className="flex items-start gap-2 sm:gap-3">
                      {/* Icon - smaller on mobile */}
                      <div className="flex-shrink-0">
                        {(() => {
                          const IconComponent = getFileIcon(record.mimeType);
                          return (
                            <IconComponent className="w-8 h-8 sm:w-10 sm:h-10 text-muted-foreground mt-0.5 sm:mt-1" />
                          );
                        })()}
                      </div>

                      {/* File info - takes remaining space and truncates */}
                      <div className="flex-1 min-w-0 overflow-hidden">
                        <h4
                          className="font-medium text-sm truncate pr-2"
                          title={record.fileName}
                        >
                          {record.fileName}
                        </h4>

                        <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 mt-1">
                          <Badge variant="secondary" className="text-xs">
                            {formatFileSize(record.fileSize)}
                          </Badge>
                          <span className="text-xs text-muted-foreground whitespace-nowrap">
                            {formatDistanceToNow(new Date(record.createdAt), {
                              addSuffix: true,
                            })}
                          </span>
                        </div>

                        {record.description && (
                          <p className="text-xs text-muted-foreground mt-2 line-clamp-2">
                            {record.description}
                          </p>
                        )}
                      </div>

                      {/* Action buttons - flex-shrink-0 to prevent squishing */}
                      <div className="flex items-center gap-0.5 sm:gap-1 flex-shrink-0">
                        {isPreviewable(record.mimeType) && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handlePreview(record)}
                            title="Preview"
                            className="h-8 w-8 p-0 sm:h-9 sm:w-9"
                            disabled={isLoadingPreview}
                            data-testid={`button-preview-${record.id}`}
                          >
                            {isLoadingPreview ? (
                              <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                            ) : (
                              <EyeIcon className="w-4 h-4" />
                            )}
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDownload(record)}
                          title="Download"
                          className="h-8 w-8 p-0 sm:h-9 sm:w-9"
                          data-testid={`button-download-${record.id}`}
                        >
                          <DownloadIcon className="w-4 h-4" />
                        </Button>

                        {user?.role === "admin" && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => deleteMutation.mutate(record.id)}
                            disabled={deleteMutation.isPending}
                            title="Delete (Admin only)"
                            className="h-8 w-8 p-0 sm:h-9 sm:w-9 text-red-600 hover:text-red-700 hover:bg-red-50"
                            data-testid={`button-delete-${record.id}`}
                          >
                            <TrashIcon className="w-4 h-4" />
                          </Button>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          <div className="bg-blue-50 border border-blue-200 rounded-md p-3">
            <div className="flex items-start">
              <InfoIcon className="w-4 h-4 text-blue-600 mr-2 mt-0.5" />
              <div className="text-sm">
                <p className="font-medium text-blue-800">Access Information</p>
                <p className="text-blue-700">
                  {user?.role === "attorney"
                    ? "As an attorney, you can view records for patients assigned to you."
                    : user?.role === "staff"
                    ? "As staff, you can view and upload records for patients you created."
                    : "As an administrator, you have full access to manage all patient records."}
                </p>
              </div>
            </div>
          </div>

          <div className="flex justify-end pt-4">
            <Button
              variant="outline"
              onClick={onClose}
              data-testid="button-close-records"
            >
              Close
            </Button>
          </div>
        </div>
      </DialogContent>

      {/* Preview Loading Overlay */}
      {isLoadingPreview && (
        <Dialog open={isLoadingPreview} onOpenChange={() => {}}>
          <DialogContent
            className="w-[95vw] max-w-[95vw] h-[95vh] max-h-[95vh] p-0 flex flex-col rounded-lg"
            data-testid="modal-preview-loading"
          >
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center">
                <div className="w-12 h-12 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                <p className="text-muted-foreground">Loading preview...</p>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      )}

      {/* Preview Modal */}
      {previewRecord && (previewUrl || previewApiUrl) && !isLoadingPreview && (
        <Dialog
          open={
            !!previewRecord &&
            (!!previewUrl || !!previewApiUrl) &&
            !isLoadingPreview
          }
          onOpenChange={(open) => !open && handleClosePreview()}
        >
          <DialogContent
            className="w-[95vw] max-w-[95vw] h-[95vh] max-h-[95vh] p-0 flex flex-col rounded-lg"
            data-testid="modal-record-preview"
          >
            <DialogHeader className="px-3 sm:px-6 pt-4 sm:pt-6 pb-3 sm:pb-4 border-b">
              <div className="flex items-center justify-between gap-2">
                <DialogTitle className="flex items-center gap-1.5 sm:gap-2 min-w-0 flex-1">
                  {(() => {
                    const IconComponent = getFileIcon(previewRecord.mimeType);
                    return <IconComponent className="w-4 h-4 flex-shrink-0" />;
                  })()}
                  <span className="truncate text-sm sm:text-base">
                    {previewRecord.fileName}
                  </span>
                </DialogTitle>
              </div>
            </DialogHeader>

            <div className="flex-1 overflow-hidden relative">
              {previewRecord.mimeType?.includes("pdf") ? (
                <div className="w-full h-full flex flex-col">
                  <div className="flex-1 relative">
                    {/* Use direct API URL instead of blob URL to avoid Chrome blocking */}
                    <iframe
                      src={previewApiUrl || previewUrl || undefined}
                      className="w-full h-full border-0"
                      title={`Preview of ${previewRecord.fileName}`}
                      data-testid="preview-iframe"
                      style={{ minHeight: "400px" }}
                      allow="fullscreen"
                    />
                  </div>
                  <div className="border-t p-2 sm:p-3 bg-gray-50 flex justify-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        if (previewApiUrl) {
                          window.open(previewApiUrl, "_blank");
                        } else if (previewUrl) {
                          window.open(previewUrl, "_blank");
                        }
                      }}
                      className="text-xs sm:text-sm"
                    >
                      <FileIcon className="w-3 h-3 sm:w-4 sm:h-4 mr-1.5 sm:mr-2" />
                      <span className="hidden sm:inline">Open in New Tab</span>
                      <span className="sm:hidden">Open</span>
                    </Button>
                  </div>
                </div>
              ) : previewRecord.mimeType?.includes("image") ? (
                <div className="w-full h-full flex items-center justify-center bg-gray-100 p-2 sm:p-4 overflow-auto">
                  <img
                    src={previewUrl || undefined}
                    alt={previewRecord.fileName}
                    className="max-w-full max-h-full object-contain"
                    data-testid="preview-image"
                    onError={(e) => {
                      console.error("Image preview error:", e);
                      toast({
                        title: "Error",
                        description: "Failed to load image preview",
                        variant: "destructive",
                      });
                    }}
                  />
                </div>
              ) : (
                <div className="w-full h-full flex items-center justify-center">
                  <p className="text-muted-foreground">
                    Preview not available for this file type
                  </p>
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      )}
    </Dialog>
  );
}
