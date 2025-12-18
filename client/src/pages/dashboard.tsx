import { useAuth } from "@/hooks/useAuth";
import { useQuery } from "@tanstack/react-query";
import Sidebar from "@/components/layout/sidebar";
import Header from "@/components/layout/header";
import StatsCards from "@/components/dashboard/stats-cards";
import PatientActivityChart from "@/components/dashboard/patient-activity-chart";
import RecentActivity from "@/components/dashboard/recent-activity";

export default function Dashboard() {
  const { isAuthenticated, isLoading } = useAuth();

  const { data: stats, isLoading: statsLoading } = useQuery<{
    cards: Array<{
      key: "totalPatients" | "pendingConsent" | "consentSigned" | "schedulable";
      title: string;
      value: number;
      trendPercent: number;
      trendUp: boolean;
      trendLabel: string;
      color: "emerald" | "amber" | "blue" | "purple";
    }>;
  }>({
    queryKey: ["/api/dashboard/stats"],
    enabled: isAuthenticated,
    retry: false,
  });

  if (isLoading || !isAuthenticated) {
    return (
      <div className="min-h-screen bg-[hsl(220,14%,96%)] flex items-center justify-center">
        <div className="text-center">
          <div className="w-10 h-10 border-3 border-emerald-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-muted-foreground font-medium">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex bg-[hsl(220,14%,96%)]">
      <Sidebar />
      
      <main className="flex-1 flex flex-col overflow-hidden">
        <Header 
          title="Dashboard"
          subtitle="Here's what's happening with your patients today."
        />
        
        <div className="flex-1 overflow-auto p-8">
          {/* Stats Cards */}
          <StatsCards stats={stats} isLoading={statsLoading} />
          
          {/* Activity Chart */}
          <PatientActivityChart />
          
          {/* Recent Activity Table */}
          <RecentActivity />
        </div>
      </main>
    </div>
  );
}
