import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
  DropdownMenuLabel,
} from "@/components/ui/dropdown-menu";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { format } from "date-fns";
import { Bell, Search, Plus, Menu } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { useSidebar } from "@/hooks/useSidebar";

interface HeaderProps {
  title: string;
  subtitle: string;
}

export default function Header({ title, subtitle }: HeaderProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const { user } = useAuth();
  const { toggle } = useSidebar();

  const { data: alerts = [] } = useQuery<any[]>({
    queryKey: ["/api/alerts"],
    retry: false,
  });

  const unreadAlerts = alerts.filter((alert: any) => !alert.isRead);

  const markAsReadMutation = useMutation({
    mutationFn: (alertId: string) =>
      apiRequest("PUT", `/api/alerts/${alertId}/read`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
    },
  });

  const markAllAsReadMutation = useMutation({
    mutationFn: () => apiRequest("PUT", "/api/alerts/mark-all-read"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
    },
  });

  const handleMarkAsRead = (alertId: string) => {
    markAsReadMutation.mutate(alertId);
  };

  const handleMarkAllAsRead = () => {
    markAllAsReadMutation.mutate();
  };

  const getGreeting = () => {
    const hour = new Date().getHours();
    if (hour < 12) return "Good morning";
    if (hour < 18) return "Good afternoon";
    return "Good evening";
  };

  return (
    <header className="bg-white border-b border-border px-8 py-5 relative z-0">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <button
            onClick={toggle}
            className="lg:hidden p-2 rounded-lg hover:bg-accent text-muted-foreground"
            data-testid="button-menu-toggle"
            aria-label="Toggle sidebar"
          >
            <Menu className="w-5 h-5" />
          </button>
          <div>
            <h2 className="text-2xl font-semibold text-foreground">{title}</h2>
            <p className="text-sm text-muted-foreground mt-0.5">
              {getGreeting()}, {user?.firstName || "there"}! {subtitle}
            </p>
          </div>
        </div>

        {/* Header Actions */}
        <div className="flex items-center space-x-3">
          {/* Search */}
          <div className="relative hidden md:block">
            <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground" />
            <Input
              type="text"
              placeholder="Search patients..."
              className="pl-10 pr-4 py-2 w-64 bg-gray-50 border-gray-200 focus:bg-white transition-colors"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              data-testid="input-header-search"
            />
          </div>

          {/* Notifications */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="relative h-10 w-10 rounded-lg hover:bg-gray-100"
                data-testid="button-notifications"
              >
                <Bell className="w-5 h-5 text-muted-foreground" />
                {unreadAlerts.length > 0 && (
                  <span className="absolute -top-1 -right-1 h-5 w-5 bg-red-500 text-white text-xs font-medium rounded-full flex items-center justify-center">
                    {unreadAlerts.length}
                  </span>
                )}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              className="w-80"
              align="end"
              data-testid="dropdown-notifications"
            >
              <DropdownMenuLabel className="flex items-center justify-between py-3">
                <span className="text-base font-semibold">Notifications</span>
                {unreadAlerts.length > 0 && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-emerald-600 hover:text-emerald-700 hover:bg-emerald-50"
                    onClick={handleMarkAllAsRead}
                    disabled={markAllAsReadMutation.isPending}
                    data-testid="button-mark-all-read"
                  >
                    Mark all read
                  </Button>
                )}
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              {alerts.length === 0 ? (
                <div
                  className="p-6 text-center text-muted-foreground"
                  data-testid="text-no-notifications"
                >
                  <Bell className="w-10 h-10 mx-auto mb-2 opacity-20" />
                  <p>No notifications</p>
                </div>
              ) : (
                <div className="max-h-72 overflow-y-auto">
                  {alerts.map((alert: any) => (
                    <DropdownMenuItem
                      key={alert.id}
                      className={`flex flex-col items-start space-y-1 p-4 cursor-pointer border-b border-gray-50 last:border-0 ${
                        !alert.isRead ? "bg-emerald-50/50" : ""
                      }`}
                      onClick={() =>
                        !alert.isRead && handleMarkAsRead(alert.id)
                      }
                      data-testid={`notification-item-${alert.id}`}
                    >
                      <div className="flex items-center justify-between w-full">
                        <span className="font-medium text-sm">
                          {alert.type}
                        </span>
                        <div className="flex items-center space-x-2">
                          {!alert.isRead && (
                            <span
                              className="w-2 h-2 bg-emerald-500 rounded-full"
                              data-testid="unread-indicator"
                            ></span>
                          )}
                          <span className="text-xs text-muted-foreground">
                            {format(new Date(alert.createdAt), "MMM d, h:mm a")}
                          </span>
                        </div>
                      </div>
                      <p className="text-sm text-muted-foreground line-clamp-2">
                        {alert.message}
                      </p>
                    </DropdownMenuItem>
                  ))}
                </div>
              )}
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Add Patient Button */}
          <div className="hidden md:block">
            <Button
              onClick={() => {
                const event = new CustomEvent("openAddPatientModal");
                window.dispatchEvent(event);
              }}
              className="bg-emerald-500 hover:bg-emerald-600 text-white shadow-sm"
              data-testid="button-header-add-patient"
            >
              <Plus className="w-4 h-4 mr-2" />
              Add Patient
            </Button>
          </div>
        </div>
      </div>
    </header>
  );
}
