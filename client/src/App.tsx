import { Switch, Route, Redirect } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useAuth } from "@/hooks/useAuth";
import { SidebarProvider } from "@/hooks/useSidebar";
import AuthLoadingScreen from "@/components/auth/auth-loading-screen";
import Landing from "@/pages/landing";
import Dashboard from "@/pages/dashboard";
import Patients from "@/pages/patients";
import Users from "@/pages/users";
import Tasks from "@/pages/tasks";
import Schedule from "@/pages/schedule";
import ConsentForms from "@/pages/consent-forms";
import Settings from "@/pages/settings";
import ChangePassword from "@/pages/change-password";
import NotFound from "@/pages/not-found";
import AddPatientModal from "@/components/modals/add-patient-modal";

function Router() {
  const { isAuthenticated, isLoading, user } = useAuth();

  if (isLoading) {
    return <AuthLoadingScreen />;
  }

  // SECURITY: Show Landing for unauthenticated users, but don't interfere with API routes
  if (!isAuthenticated) {
    return (
      <Switch>
        {/* Specific frontend routes that should show Landing when unauthenticated */}
        <Route path="/" component={Landing} />
        <Route path="/dashboard" component={Landing} />
        <Route path="/patients" component={Landing} />
        <Route path="/users" component={Landing} />
        <Route path="/tasks" component={Landing} />
        <Route path="/schedule" component={Landing} />
        <Route path="/consent-forms" component={Landing} />
        {/* Audit logs page removed */}
        <Route path="/settings" component={Landing} />
        {/* API routes are NOT handled by React router - they go to server */}
      </Switch>
    );
  }

  // Check if user must change password
  if (user?.mustChangePassword) {
    return (
      <Switch>
        <Route path="/change-password" component={ChangePassword} />
        <Route path="*">
          {() => {
            window.location.href = "/change-password";
            return null;
          }}
        </Route>
      </Switch>
    );
  }

  // Authenticated users see normal routing
  const isAdmin = user?.role === "admin";
  return (
    <>
      <Switch>
        {/* Admin-only landing/dashboard routes */}
        <Route path="/">
          {() => (isAdmin ? <Dashboard /> : <Redirect to="/patients" />)}
        </Route>
        <Route path="/dashboard">
          {() => (isAdmin ? <Dashboard /> : <Redirect to="/patients" />)}
        </Route>
        <Route path="/patients" component={Patients} />
        {/* Users page is admin-only; staff/attorney are redirected to Patients */}
        <Route path="/users">
          {() => (isAdmin ? <Users /> : <Redirect to="/patients" />)}
        </Route>
        <Route path="/tasks" component={Tasks} />
        <Route path="/schedule" component={Schedule} />
        <Route path="/consent-forms" component={ConsentForms} />
        <Route path="/settings" component={Settings} />
        <Route path="/change-password" component={ChangePassword} />
        <Route component={NotFound} />
      </Switch>
      {/* AddPatientModal available globally for Header button on all pages */}
      <AddPatientModal />
    </>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <SidebarProvider>
          <Toaster />
          <Router />
        </SidebarProvider>
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
