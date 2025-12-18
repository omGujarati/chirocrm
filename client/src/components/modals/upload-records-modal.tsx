import { useRef, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { ShieldAlertIcon, UploadIcon } from "lucide-react";

interface UploadRecordsModalProps {
  isOpen: boolean;
  onClose: () => void;
  patientId: string;
  patientName: string;
}

export default function UploadRecordsModal({
  isOpen,
  onClose,
  patientId,
  patientName,
}: UploadRecordsModalProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [description, setDescription] = useState("");
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Keep client-side validation aligned with server-side multer fileFilter/limits
  const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024; // 50MB
  const ALLOWED_EXTENSIONS = new Set([
    "pdf",
    "doc",
    "docx",
    "jpg",
    "jpeg",
    "png",
    "tif",
    "tiff",
  ]);
  const ALLOWED_MIME_TYPES = new Set([
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "image/jpeg",
    "image/png",
    "image/tiff",
  ]);

  const resetFileInput = () => {
    setSelectedFile(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const validateSelectedFile = (file: File) => {
    const ext = file.name.split(".").pop()?.toLowerCase() ?? "";
    const sizeOk = file.size <= MAX_FILE_SIZE_BYTES;
    const extOk = ALLOWED_EXTENSIONS.has(ext);
    // Some browsers may provide an empty mimetype; accept based on extension in that case
    const mimeOk = file.type ? ALLOWED_MIME_TYPES.has(file.type) : true;

    if (!extOk || !mimeOk) {
      return `Invalid file type. Only PDF, DOC, DOCX, JPG/JPEG, PNG, and TIFF files are allowed.`;
    }
    if (!sizeOk) {
      return `File is too large. Maximum size is 50MB.`;
    }
    return null;
  };

  const uploadMutation = useMutation({
    mutationFn: async (formData: FormData) => {
      // Use fetch directly for file upload with FormData
      const response = await fetch(`/api/patients/${patientId}/records`, {
        method: "POST",
        credentials: "include", // Include cookies for authentication
        body: formData, // Don't set Content-Type header - let browser set it with boundary
      });

      if (!response.ok) {
        const errorData = await response
          .json()
          .catch(() => ({ message: "Upload failed" }));
        throw new Error(errorData.message || `HTTP ${response.status}`);
      }

      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Patient record uploaded successfully",
      });
      queryClient.invalidateQueries({
        queryKey: ["/api/patients", patientId, "records"],
      });
      queryClient.invalidateQueries({ queryKey: ["/api/patients"] });
      handleClose();
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to upload record",
        variant: "destructive",
      });
    },
  });

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const errorMessage = validateSelectedFile(file);
      if (errorMessage) {
        toast({
          title: "Invalid file",
          description: errorMessage,
          variant: "destructive",
        });
        resetFileInput();
        return;
      }
      setSelectedFile(file);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      toast({
        title: "Error",
        description: "Please select a file to upload",
        variant: "destructive",
      });
      return;
    }

    const errorMessage = validateSelectedFile(selectedFile);
    if (errorMessage) {
      toast({
        title: "Invalid file",
        description: errorMessage,
        variant: "destructive",
      });
      resetFileInput();
      return;
    }

    // Create FormData for secure file upload
    const formData = new FormData();
    formData.append("file", selectedFile);
    if (description.trim()) {
      formData.append("description", description.trim());
    }

    uploadMutation.mutate(formData);
  };

  const handleClose = () => {
    resetFileInput();
    setDescription("");
    onClose();
  };

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent
        className="w-[95vw] max-w-[95vw] sm:max-w-md md:max-w-md max-h-[95vh] overflow-auto rounded-lg p-4 sm:p-6 sm:m-0 flex flex-col"
        data-testid="modal-upload-records"
      >
        <DialogHeader>
          <DialogTitle>Upload Patient Records</DialogTitle>
          <p className="text-sm text-muted-foreground">
            Upload medical records for {patientName}
          </p>
        </DialogHeader>

        <div className="space-y-4">
          <div>
            <Label htmlFor="file-input">Select File</Label>
            <Input
              id="file-input"
              type="file"
              onChange={handleFileSelect}
              accept=".pdf,.doc,.docx,.jpg,.jpeg,.png,.tiff"
              ref={fileInputRef}
              data-testid="input-file-upload"
            />
            {selectedFile && (
              <p className="text-sm text-muted-foreground mt-1">
                Selected: {selectedFile.name} (
                {Math.round(selectedFile.size / 1024)} KB)
              </p>
            )}
          </div>

          <div>
            <Label htmlFor="description">Description (Optional)</Label>
            <Textarea
              id="description"
              placeholder="Brief description of the document..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={1000}
              data-testid="textarea-description"
            />
            <p className="text-xs text-muted-foreground mt-1">
              {description.length}/1000 characters
            </p>
          </div>

          <div className="bg-yellow-50 border border-yellow-200 rounded-md p-3">
            <div className="flex items-start">
              <ShieldAlertIcon className="w-4 h-4 text-yellow-600 mr-2 mt-0.5" />
              <div className="text-sm">
                <p className="font-medium text-yellow-800">HIPAA Notice</p>
                <p className="text-yellow-700">
                  This document will be securely stored and accessible only to
                  authorized staff and assigned attorneys.
                </p>
              </div>
            </div>
          </div>

          <div className="flex justify-end space-x-2 pt-4">
            <Button
              variant="outline"
              onClick={handleClose}
              disabled={uploadMutation.isPending}
              data-testid="button-cancel-upload"
            >
              Cancel
            </Button>
            <Button
              onClick={handleUpload}
              disabled={!selectedFile || uploadMutation.isPending}
              data-testid="button-confirm-upload"
            >
              {uploadMutation.isPending ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                  Uploading...
                </>
              ) : (
                <>
                  <UploadIcon className="w-4 h-4" />
                  Upload Record
                </>
              )}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
