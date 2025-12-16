import { useLocation } from "wouter";
import { useAuth } from "@/hooks/useAuth";
import { Link } from "wouter";
import { useSidebar } from "@/hooks/useSidebar";
import {
  LayoutDashboard,
  Users,
  ClipboardList,
  Calendar,
  FileSignature,
  History,
  Settings,
  LogOut,
  Heart,
  X,
} from "lucide-react";
import { useEffect } from "react";

export default function Sidebar() {
  const [location] = useLocation();
  const { user } = useAuth();
  const { isOpen, close } = useSidebar();

  const navigation = [
    ...(user?.role === "admin"
      ? [{ name: "Dashboard", href: "/", icon: LayoutDashboard }]
      : []),
    ...(user?.role === "admin"
      ? [{ name: "Users", href: "/users", icon: Users }]
      : []),
    { name: "Patients", href: "/patients", icon: Users },
    { name: "Tasks", href: "/tasks", icon: ClipboardList },
    { name: "Schedule", href: "/schedule", icon: Calendar },
    { name: "Consent Forms", href: "/consent-forms", icon: FileSignature },
    ...(user?.role === "admin"
      ? [{ name: "Audit Logs", href: "/audit-logs", icon: History }]
      : []),
    { name: "Settings", href: "/settings", icon: Settings },
  ];

  return (
    <>
      {/* Overlay for mobile */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/50 lg:hidden z-40"
          onClick={close}
        />
      )}

      <aside
        className={`w-64 bg-[hsl(222,47%,11%)] border-r border-[hsl(222,47%,20%)] h-screen overflow-y-auto top-0 left-0 sidebar-nav transition-transform duration-300 ease-in-out will-change-transform z-50 ${
          isOpen ? "translate-x-0" : "-translate-x-full"
        } fixed lg:sticky lg:translate-x-0`}
        aria-hidden={!isOpen}
      >
        <div className="flex flex-col h-full">
          {/* Logo Header */}
          <div className="flex items-center justify-between px-6 py-5 border-b border-[hsl(222,47%,20%)]">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-gradient-to-br from-emerald-400 to-emerald-600 rounded-xl flex items-center justify-center shadow-lg">
                <Heart className="w-5 h-5 text-white" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-white">ChiroCareCRM</h1>
                <p className="text-xs text-[hsl(210,17%,60%)]">
                  Patient Management
                </p>
              </div>
            </div>
            {/* Close button for mobile */}
            <button
              onClick={close}
              className="lg:hidden p-2 text-[hsl(210,17%,70%)] hover:text-white hover:bg-[hsl(222,47%,18%)] rounded-lg transition-colors"
              aria-label="Close sidebar"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Navigation Menu */}
          <nav className="flex-1 px-3 py-6 space-y-1">
            <p className="px-3 mb-3 text-xs font-semibold uppercase tracking-wider text-[hsl(210,17%,50%)]">
              General
            </p>
            {navigation.map((item) => {
              const isActive =
                location === item.href ||
                (item.href !== "/" && location.startsWith(item.href));
              const IconComponent = item.icon;

              return (
                <Link
                  key={item.name}
                  href={item.href}
                  onClick={close}
                  className={`flex items-center px-3 py-2.5 text-sm font-medium rounded-lg transition-all duration-200 ${
                    isActive
                      ? "bg-emerald-500/10 text-emerald-400 border-l-3 border-emerald-400"
                      : "text-[hsl(210,17%,70%)] hover:text-white hover:bg-[hsl(222,47%,18%)]"
                  }`}
                  data-testid={`nav-${item.name
                    .toLowerCase()
                    .replace(" ", "-")}`}
                >
                  <IconComponent
                    className={`w-5 h-5 mr-3 ${
                      isActive ? "text-emerald-400" : ""
                    }`}
                  />
                  {item.name}
                </Link>
              );
            })}
          </nav>

          {/* User Profile */}
          <div className="px-3 py-4 border-t border-[hsl(222,47%,20%)] bg-[hsl(222,47%,8%)]">
            <div className="flex items-center space-x-3 px-2">
              <div className="w-10 h-10 bg-gradient-to-br from-emerald-400 to-emerald-600 rounded-full flex items-center justify-center text-white font-semibold text-sm">
                {user?.firstName?.[0]?.toUpperCase()}
                {user?.lastName?.[0]?.toUpperCase()}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-white truncate">
                  {user?.firstName} {user?.lastName}
                </p>
                <p className="text-xs text-[hsl(210,17%,55%)] truncate">
                  {user?.email}
                </p>
              </div>
              <button
                className="p-2 text-[hsl(210,17%,55%)] hover:text-white hover:bg-[hsl(222,47%,18%)] rounded-lg transition-colors"
                onClick={async () => {
                  try {
                    await fetch("/api/auth/logout", { method: "POST" });
                    window.location.href = "/";
                  } catch (error) {
                    console.error("Logout failed:", error);
                    window.location.href = "/";
                  }
                }}
                title="Sign Out"
                data-testid="button-logout-sidebar"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
}
