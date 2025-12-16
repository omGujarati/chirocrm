import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { apiRequest } from "@/lib/queryClient";
import { isUnauthorizedError } from "@/lib/authUtils";
import { type PatientNote } from "@shared/schema";
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
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import StatusBadge from "@/components/ui/status-badge";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { 
  Save, 
  Edit2, 
  Trash2, 
  StickyNote, 
  User, 
  Mail, 
  Phone, 
  Calendar,
  FileText,
  Scale
} from "lucide-react";

const noteSchema = z.object({
  content: z.string().min(1, "Note content is required"),
  noteType: z.string().optional(),
});

type NoteFormData = z.infer<typeof noteSchema>;

interface PatientDetailModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  patient: any;
}

export default function PatientDetailModal({
  open,
  onOpenChange,
  patient,
}: PatientDetailModalProps) {
  const { toast } = useToast();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [editingNoteId, setEditingNoteId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "notes">("overview");
  const [isEditingAssignment, setIsEditingAssignment] = useState(false);
  const [selectedAssignment, setSelectedAssignment] = useState<string>("");
  const [isEditingEnvelopeId, setIsEditingEnvelopeId] = useState(false);
  const [envelopeId, setEnvelopeId] = useState<string>("");

  const form = useForm<NoteFormData>({
    resolver: zodResolver(noteSchema),
    defaultValues: {
      content: "",
      noteType: "general",
    },
  });

  // Fetch users for assignment dropdown
  const { data: usersData } = useQuery<Array<{ id: string; firstName: string; lastName: string; email: string; role: string; isActive: boolean }> | { users: Array<{ id: string; firstName: string; lastName: string; email: string; role: string; isActive: boolean }>; pagination: any }>({
    queryKey: ['/api/users'],
    queryFn: async () => {
      const response = await fetch('/api/users?page=1&limit=100', {
        credentials: "include",
      });
      if (!response.ok) {
        return [];
      }
      const data = await response.json();
      // Handle both old format (array) and new format (paginated object)
      if (Array.isArray(data)) {
        return data;
      }
      if (data.users && Array.isArray(data.users)) {
        return data.users;
      }
      return [];
    },
    retry: false,
    enabled: open && user?.role === 'admin',
  });

  // Extract users array from response (handle both formats)
  const users = Array.isArray(usersData) ? usersData : (usersData?.users || []);
  const assignableUsers = users?.filter(u => u.isActive && (u.role === 'attorney' || u.role === 'staff'));

  // Fetch patient notes
  const { data: notes = [], isLoading: notesLoading } = useQuery({
    queryKey: ["/api/patients", patient?.id, "notes"],
    enabled: !!patient?.id && open,
    retry: false,
  });

  const typedNotes = notes as PatientNote[];

  // Create note mutation
  const createNoteMutation = useMutation({
    mutationFn: async (data: NoteFormData) => {
      return await apiRequest("POST", `/api/patients/${patient.id}/notes`, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/patients", patient.id, "notes"] });
      form.reset();
      toast({
        title: "Success",
        description: "Note added successfully",
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
        description: "Failed to add note",
        variant: "destructive",
      });
    },
  });

  // Update note mutation
  const updateNoteMutation = useMutation({
    mutationFn: async ({ noteId, data }: { noteId: string; data: Partial<NoteFormData> }) => {
      return await apiRequest("PUT", `/api/patients/${patient.id}/notes/${noteId}`, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/patients", patient.id, "notes"] });
      setEditingNoteId(null);
      form.reset();
      toast({
        title: "Success",
        description: "Note updated successfully",
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
        description: "Failed to update note",
        variant: "destructive",
      });
    },
  });

  // Delete note mutation (admin only)
  const deleteNoteMutation = useMutation({
    mutationFn: async (noteId: string) => {
      return await apiRequest("DELETE", `/api/patients/${patient.id}/notes/${noteId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/patients", patient.id, "notes"] });
      toast({
        title: "Success",
        description: "Note deleted successfully",
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
        description: "Failed to delete note",
        variant: "destructive",
      });
    },
  });

  // Update patient assignment mutation (admin only)
  const updateAssignmentMutation = useMutation({
    mutationFn: async (assignedAttorney: string) => {
      return await apiRequest("PATCH", `/api/patients/${patient.id}/assignment`, { assignedAttorney });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/patients"] });
      setIsEditingAssignment(false);
      toast({
        title: "Success",
        description: "Patient assignment updated successfully",
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
        description: error.message || "Failed to update assignment",
        variant: "destructive",
      });
    },
  });

  const handleAssignmentUpdate = () => {
    updateAssignmentMutation.mutate(selectedAssignment);
  };

  // Update envelope ID mutation (admin only)
  const updateEnvelopeIdMutation = useMutation({
    mutationFn: async (docusignEnvelopeId: string) => {
      return await apiRequest("PATCH", `/api/patients/${patient.id}`, { docusignEnvelopeId: docusignEnvelopeId || null });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/patients"] });
      setIsEditingEnvelopeId(false);
      toast({
        title: "Success",
        description: "DocuSign Envelope ID updated successfully",
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
        description: error.message || "Failed to update envelope ID",
        variant: "destructive",
      });
    },
  });

  const handleEnvelopeIdUpdate = () => {
    updateEnvelopeIdMutation.mutate(envelopeId);
  };

  const onSubmit = (data: NoteFormData) => {
    if (editingNoteId) {
      updateNoteMutation.mutate({ noteId: editingNoteId, data });
    } else {
      createNoteMutation.mutate(data);
    }
  };

  const startEdit = (note: any) => {
    setEditingNoteId(note.id);
    form.setValue("content", note.content);
    form.setValue("noteType", note.noteType || "general");
  };

  const cancelEdit = () => {
    setEditingNoteId(null);
    form.reset();
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const getNoteTypeColor = (type: string) => {
    switch (type) {
      case "appointment": return "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200";
      case "treatment": return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200";
      case "legal": return "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200";
      case "insurance": return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200";
      default: return "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200";
    }
  };

  if (!patient) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="w-[95vw] max-w-[95vw] sm:max-w-md md:max-w-4xl max-h-[95vh] overflow-auto rounded-lg p-4 sm:p-6 sm:m-0 flex flex-col" data-testid="modal-patient-detail">
        <DialogHeader>
          <DialogTitle data-testid="text-patient-detail-title">
            <div className="flex items-center gap-3">
              <User className="w-6 h-6" />
              {patient.firstName} {patient.lastName}
              <StatusBadge status={patient.status} />
            </div>
          </DialogTitle>
        </DialogHeader>

        {/* Tab Navigation */}
        <div className="flex gap-4 border-b border-border">
          <button
            className={`px-4 py-2 font-medium transition-colors ${
              activeTab === "overview" 
                ? "text-primary border-b-2 border-primary" 
                : "text-muted-foreground hover:text-foreground"
            }`}
            onClick={() => setActiveTab("overview")}
            data-testid="tab-overview"
          >
            Overview
          </button>
          <button
            className={`px-4 py-2 font-medium transition-colors flex items-center gap-2 ${
              activeTab === "notes" 
                ? "text-primary border-b-2 border-primary" 
                : "text-muted-foreground hover:text-foreground"
            }`}
            onClick={() => setActiveTab("notes")}
            data-testid="tab-notes"
          >
            <StickyNote className="w-4 h-4" />
            Notes ({typedNotes.length})
          </button>
        </div>

        <div className="flex-1 overflow-hidden">
          {activeTab === "overview" && (
            <div className="h-full overflow-y-auto p-6">
              {/* Patient Information */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <User className="w-5 h-5" />
                      Patient Information
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center gap-3">
                      <Mail className="w-4 h-4 text-muted-foreground" />
                      <span data-testid="text-patient-email">{patient.email}</span>
                    </div>
                    {patient.phone && (
                      <div className="flex items-center gap-3">
                        <Phone className="w-4 h-4 text-muted-foreground" />
                        <span data-testid="text-patient-phone">{patient.phone}</span>
                      </div>
                    )}
                    {patient.dateOfBirth && (
                      <div className="flex items-center gap-3">
                        <Calendar className="w-4 h-4 text-muted-foreground" />
                        <span>DOB: {patient.dateOfBirth ? new Date(patient.dateOfBirth.toString()).toLocaleDateString() : 'Not provided'}</span>
                      </div>
                    )}
                    {patient.dateOfInjury && (
                      <div className="flex items-center gap-3">
                        <Calendar className="w-4 h-4 text-muted-foreground" />
                        <span>Date of Injury: {patient.dateOfInjury ? new Date(patient.dateOfInjury.toString()).toLocaleDateString() : 'Not provided'}</span>
                      </div>
                    )}
                    <div className="flex items-center gap-3">
                      <FileText className="w-4 h-4 text-muted-foreground" />
                      <span>Status: <StatusBadge status={patient.status} /></span>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Scale className="w-5 h-5" />
                      Case Information
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Created By</label>
                      <p data-testid="text-created-by">
                        {patient.createdBy?.firstName} {patient.createdBy?.lastName}
                      </p>
                    </div>
                    
                    <div>
                      <label className="text-sm font-medium text-muted-foreground flex items-center justify-between">
                        Assigned To
                        {user?.role === 'admin' && !isEditingAssignment && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setIsEditingAssignment(true);
                              setSelectedAssignment(patient.assignedAttorney?.id || 'none');
                            }}
                            className="h-6 px-2"
                            data-testid="button-edit-assignment"
                          >
                            <Edit2 className="w-3 h-3" />
                          </Button>
                        )}
                      </label>
                      
                      {isEditingAssignment && user?.role === 'admin' ? (
                        <div className="flex items-center gap-2 mt-1">
                          <Select 
                            value={selectedAssignment} 
                            onValueChange={setSelectedAssignment}
                          >
                            <SelectTrigger className="h-8" data-testid="select-update-assignment">
                              <SelectValue placeholder="Select user" />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="none">Unassigned</SelectItem>
                              {assignableUsers.map((assignUser) => (
                                <SelectItem key={assignUser.id} value={assignUser.id}>
                                  {assignUser.firstName} {assignUser.lastName} ({assignUser.role})
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                          <Button
                            size="sm"
                            onClick={handleAssignmentUpdate}
                            disabled={updateAssignmentMutation.isPending}
                            className="h-8"
                            data-testid="button-save-assignment"
                          >
                            <Save className="w-3 h-3" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => setIsEditingAssignment(false)}
                            className="h-8"
                            data-testid="button-cancel-assignment"
                          >
                            Cancel
                          </Button>
                        </div>
                      ) : (
                        <p data-testid="text-assigned-user">
                          {patient.assignedAttorney 
                            ? `${patient.assignedAttorney.firstName} ${patient.assignedAttorney.lastName} (${patient.assignedAttorney.role})`
                            : 'Unassigned'}
                        </p>
                      )}
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Created</label>
                      <p>{new Date(patient.createdAt).toLocaleString()}</p>
                    </div>
                    {patient.consentSignedAt && (
                      <div>
                        <label className="text-sm font-medium text-muted-foreground">Consent Signed</label>
                        <p>{patient.consentSignedAt ? new Date(patient.consentSignedAt.toString()).toLocaleString() : 'Not signed'}</p>
                      </div>
                    )}
                    
                    {/* DocuSign Envelope ID - Admin Only */}
                    {user?.role === 'admin' && (
                      <div>
                        <label className="text-sm font-medium text-muted-foreground flex items-center justify-between">
                          DocuSign Envelope ID
                          {!isEditingEnvelopeId && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setIsEditingEnvelopeId(true);
                                setEnvelopeId(patient.docusignEnvelopeId || '');
                              }}
                              className="h-6 px-2"
                              data-testid="button-edit-envelope-id"
                            >
                              <Edit2 className="w-3 h-3" />
                            </Button>
                          )}
                        </label>
                        
                        {isEditingEnvelopeId ? (
                          <div className="flex flex-col gap-2 mt-1">
                            <input
                              type="text"
                              value={envelopeId}
                              onChange={(e) => setEnvelopeId(e.target.value)}
                              placeholder="Paste DocuSign Envelope ID"
                              className="h-8 px-2 text-sm border border-input rounded-md bg-background"
                              data-testid="input-envelope-id"
                            />
                            <div className="flex items-center gap-2">
                              <Button
                                size="sm"
                                onClick={handleEnvelopeIdUpdate}
                                disabled={updateEnvelopeIdMutation.isPending}
                                className="h-8"
                                data-testid="button-save-envelope-id"
                              >
                                <Save className="w-3 h-3 mr-1" />
                                Save
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => setIsEditingEnvelopeId(false)}
                                className="h-8"
                                data-testid="button-cancel-envelope-id"
                              >
                                Cancel
                              </Button>
                            </div>
                          </div>
                        ) : (
                          <p data-testid="text-envelope-id" className="text-xs font-mono break-all">
                            {patient.docusignEnvelopeId || <span className="text-muted-foreground italic">Not set</span>}
                          </p>
                        )}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* Injury Details */}
              {patient.injuryDescription && (
                <Card className="mt-6">
                  <CardHeader>
                    <CardTitle>Injury Description</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm whitespace-pre-wrap" data-testid="text-injury-description">
                      {patient.injuryDescription}
                    </p>
                  </CardContent>
                </Card>
              )}
            </div>
          )}

          {activeTab === "notes" && (
            <div className="h-full flex gap-6 p-6">
              {/* Notes List */}
              <div className="flex-1 overflow-y-auto">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg flex items-center gap-2">
                      <StickyNote className="w-5 h-5" />
                      Patient Notes ({typedNotes.length})
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {notesLoading ? (
                      <div className="text-center py-8">
                        <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                        <p className="text-muted-foreground">Loading notes...</p>
                      </div>
                    ) : typedNotes.length === 0 ? (
                      <div className="text-center py-8">
                        <StickyNote className="w-16 h-16 text-muted-foreground mb-4 mx-auto" />
                        <p className="text-muted-foreground">No notes found for this patient</p>
                        <p className="text-sm text-muted-foreground mt-2">Add the first note using the form on the right</p>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {typedNotes.map((note: PatientNote) => (
                          <div 
                            key={note.id} 
                            className="border border-border rounded-lg p-4 hover:bg-accent/50 transition-colors"
                            data-testid={`note-item-${note.id}`}
                          >
                            <div className="flex items-start justify-between mb-2">
                              <div className="flex items-center gap-2">
                                <Badge 
                                  className={`text-xs ${getNoteTypeColor(note.noteType || 'general')}`}
                                  data-testid={`badge-note-type-${note.id}`}
                                >
                                  {note.noteType || 'general'}
                                </Badge>
                                <span className="text-xs text-muted-foreground" data-testid={`text-note-date-${note.id}`}>
                                  {note.createdAt ? new Date(note.createdAt).toLocaleString() : 'Unknown date'}
                                </span>
                              </div>
                              <div className="flex gap-1">
                                {note.createdBy === user?.id && (
                                  <Button 
                                    variant="ghost" 
                                    size="sm"
                                    onClick={() => startEdit(note)}
                                    className="h-6 w-6 p-0"
                                    data-testid={`button-edit-note-${note.id}`}
                                  >
                                    <Edit2 className="w-3 h-3" />
                                  </Button>
                                )}
                                {user?.role === 'admin' && (
                                  <Button 
                                    variant="ghost" 
                                    size="sm"
                                    onClick={() => deleteNoteMutation.mutate(note.id)}
                                    disabled={deleteNoteMutation.isPending}
                                    className="h-6 w-6 p-0 text-red-600 hover:text-red-700"
                                    data-testid={`button-delete-note-${note.id}`}
                                  >
                                    <Trash2 className="w-3 h-3" />
                                  </Button>
                                )}
                              </div>
                            </div>
                            <p className="text-sm text-foreground whitespace-pre-wrap" data-testid={`text-note-content-${note.id}`}>
                              {note.content}
                            </p>
                            {note.updatedAt && note.updatedAt !== note.createdAt && (
                              <p className="text-xs text-muted-foreground mt-2">
                                Last updated: {new Date(note.updatedAt).toLocaleString()}
                              </p>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* Add/Edit Note Form */}
              <div className="w-96">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">
                      {editingNoteId ? "Edit Note" : "Add New Note"}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Form {...form}>
                      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                        <FormField
                          control={form.control}
                          name="noteType"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Note Type</FormLabel>
                              <Select onValueChange={field.onChange} value={field.value}>
                                <FormControl>
                                  <SelectTrigger data-testid="select-note-type">
                                    <SelectValue placeholder="Select note type" />
                                  </SelectTrigger>
                                </FormControl>
                                <SelectContent>
                                  <SelectItem value="general">General</SelectItem>
                                  <SelectItem value="appointment">Appointment</SelectItem>
                                  <SelectItem value="treatment">Treatment</SelectItem>
                                  <SelectItem value="legal">Legal</SelectItem>
                                  <SelectItem value="insurance">Insurance</SelectItem>
                                </SelectContent>
                              </Select>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="content"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Note Content</FormLabel>
                              <FormControl>
                                <Textarea
                                  placeholder="Enter note content..."
                                  className="min-h-[120px]"
                                  data-testid="textarea-note-content"
                                  {...field}
                                />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <div className="flex gap-2">
                          <Button 
                            type="submit" 
                            disabled={createNoteMutation.isPending || updateNoteMutation.isPending}
                            data-testid="button-save-note"
                          >
                            <Save className="w-4 h-4 mr-2" />
                            {editingNoteId ? "Update Note" : "Add Note"}
                          </Button>
                          {editingNoteId && (
                            <Button 
                              type="button" 
                              variant="outline"
                              onClick={cancelEdit}
                              data-testid="button-cancel-edit"
                            >
                              Cancel
                            </Button>
                          )}
                        </div>
                      </form>
                    </Form>
                  </CardContent>
                </Card>
              </div>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}