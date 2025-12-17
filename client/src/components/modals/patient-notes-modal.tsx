import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { apiRequest } from "@/lib/queryClient";
import { isUnauthorizedError } from "@/lib/authUtils";
import { type PatientNote } from "@shared/schema";
import { Save, X, Edit2, Trash2, StickyNote } from "lucide-react";
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
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

const noteSchema = z.object({
  content: z.string().min(1, "Note content is required"),
  noteType: z.string().optional(),
});

type NoteFormData = z.infer<typeof noteSchema>;

interface PatientNotesModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  patient: any;
}

export default function PatientNotesModal({
  open,
  onOpenChange,
  patient,
}: PatientNotesModalProps) {
  const { toast } = useToast();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [editingNoteId, setEditingNoteId] = useState<string | null>(null);

  const form = useForm<NoteFormData>({
    resolver: zodResolver(noteSchema),
    defaultValues: {
      content: "",
      noteType: "general",
    },
  });

  // Fetch patient notes
  const { data: notes = [], isLoading: notesLoading } = useQuery({
    queryKey: ["/api/patients", patient?.id, "notes"],
    enabled: !!patient?.id && open,
    retry: false,
  });

  // Type the notes array properly
  const typedNotes = notes as PatientNote[];

  // Create note mutation
  const createNoteMutation = useMutation({
    mutationFn: async (data: NoteFormData) => {
      return await apiRequest(
        "POST",
        `/api/patients/${patient.id}/notes`,
        data
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["/api/patients", patient.id, "notes"],
      });
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
    mutationFn: async ({
      noteId,
      data,
    }: {
      noteId: string;
      data: Partial<NoteFormData>;
    }) => {
      return await apiRequest(
        "PUT",
        `/api/patients/${patient.id}/notes/${noteId}`,
        data
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["/api/patients", patient.id, "notes"],
      });
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
      return await apiRequest(
        "DELETE",
        `/api/patients/${patient.id}/notes/${noteId}`
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["/api/patients", patient.id, "notes"],
      });
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
      case "appointment":
        return "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200";
      case "treatment":
        return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200";
      case "legal":
        return "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200";
      case "insurance":
        return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200";
      default:
        return "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200";
    }
  };

  if (!patient) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="w-[95vw] max-w-[95vw] sm:max-w-md md:max-w-4xl max-h-[95vh] overflow-auto rounded-lg p-4 sm:p-6 sm:m-0 flex flex-col"
        data-testid="modal-patient-notes"
      >
        <DialogHeader>
          <DialogTitle data-testid="text-modal-title">
            Patient Notes - {patient.firstName} {patient.lastName}
          </DialogTitle>
        </DialogHeader>

        <div className="flex flex-col md:flex-row gap-6">
          {/* Notes List */}
          <div className="flex-1 overflow-y-auto">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">
                  Existing Notes ({typedNotes.length})
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
                    <p className="text-muted-foreground">
                      No notes found for this patient
                    </p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {typedNotes.map((note: any) => (
                      <div
                        key={note.id}
                        className="border border-border rounded-lg p-4 hover:bg-accent/50 transition-colors"
                        data-testid={`note-item-${note.id}`}
                      >
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <Badge
                              className={`text-xs ${getNoteTypeColor(
                                note.noteType || "general"
                              )}`}
                              data-testid={`badge-note-type-${note.id}`}
                            >
                              {note.noteType || "general"}
                            </Badge>
                            <span
                              className="text-xs text-muted-foreground"
                              data-testid={`text-note-date-${note.id}`}
                            >
                              {formatDate(note.createdAt)}
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
                            {user?.role === "admin" && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() =>
                                  deleteNoteMutation.mutate(note.id)
                                }
                                disabled={deleteNoteMutation.isPending}
                                className="h-6 w-6 p-0 text-red-600 hover:text-red-700"
                                data-testid={`button-delete-note-${note.id}`}
                              >
                                <Trash2 className="w-3 h-3" />
                              </Button>
                            )}
                          </div>
                        </div>
                        <p
                          className="text-sm text-foreground whitespace-pre-wrap"
                          data-testid={`text-note-content-${note.id}`}
                        >
                          {note.content}
                        </p>
                        {note.updatedAt &&
                          note.updatedAt !== note.createdAt && (
                            <p className="text-xs text-muted-foreground mt-2">
                              Last updated: {formatDate(note.updatedAt)}
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
          <div className="w-full md:w-96">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">
                  {editingNoteId ? "Edit Note" : "Add New Note"}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <Form {...form}>
                  <form
                    onSubmit={form.handleSubmit(onSubmit)}
                    className="space-y-4"
                  >
                    <FormField
                      control={form.control}
                      name="noteType"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Note Type</FormLabel>
                          <Select
                            onValueChange={field.onChange}
                            value={field.value}
                          >
                            <FormControl>
                              <SelectTrigger data-testid="select-note-type">
                                <SelectValue placeholder="Select note type" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="general">General</SelectItem>
                              <SelectItem value="appointment">
                                Appointment
                              </SelectItem>
                              <SelectItem value="treatment">
                                Treatment
                              </SelectItem>
                              <SelectItem value="legal">Legal</SelectItem>
                              <SelectItem value="insurance">
                                Insurance
                              </SelectItem>
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
                        disabled={
                          createNoteMutation.isPending ||
                          updateNoteMutation.isPending
                        }
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
      </DialogContent>
    </Dialog>
  );
}
