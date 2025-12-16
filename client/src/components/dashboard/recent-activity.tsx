import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";
import { Activity, Filter, ArrowUpDown, CheckCircle, Send, UserPlus, Edit, Info } from "lucide-react";

export default function RecentActivity() {
  const { data: auditLogs = [], isLoading } = useQuery<any[]>({
    queryKey: ["/api/audit-logs"],
    retry: false,
  });

  const getActivityIcon = (action: string) => {
    switch (action) {
      case 'consent_signed':
        return { icon: CheckCircle, color: 'text-emerald-600', bg: 'bg-emerald-100' };
      case 'consent_sent':
        return { icon: Send, color: 'text-blue-600', bg: 'bg-blue-100' };
      case 'created':
        return { icon: UserPlus, color: 'text-amber-600', bg: 'bg-amber-100' };
      case 'updated':
        return { icon: Edit, color: 'text-purple-600', bg: 'bg-purple-100' };
      default:
        return { icon: Info, color: 'text-gray-600', bg: 'bg-gray-100' };
    }
  };

  const getActivityDescription = (log: any) => {
    switch (log.action) {
      case 'consent_signed':
        return 'Patient signed consent form';
      case 'consent_sent':
        return 'Consent form sent to patient';
      case 'created':
        if (log.resourceType === 'patient') return 'New patient registered';
        if (log.resourceType === 'appointment') return 'Appointment scheduled';
        return `New ${log.resourceType} created`;
      case 'updated':
        return `${log.resourceType} updated`;
      default:
        return `${log.action} ${log.resourceType}`;
    }
  };

  const getStatusBadge = (action: string) => {
    switch (action) {
      case 'consent_signed':
        return <Badge className="bg-emerald-100 text-emerald-700 hover:bg-emerald-100 border-0">Completed</Badge>;
      case 'consent_sent':
        return <Badge className="bg-blue-100 text-blue-700 hover:bg-blue-100 border-0">Sent</Badge>;
      case 'created':
        return <Badge className="bg-amber-100 text-amber-700 hover:bg-amber-100 border-0">New</Badge>;
      case 'updated':
        return <Badge className="bg-purple-100 text-purple-700 hover:bg-purple-100 border-0">Updated</Badge>;
      default:
        return <Badge variant="secondary">{action}</Badge>;
    }
  };

  const recentActivities = auditLogs.slice(0, 6);

  return (
    <Card className="border-0 shadow-md bg-white">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Activity className="w-5 h-5 text-muted-foreground" />
            <CardTitle className="text-lg font-semibold">Recent Activity</CardTitle>
          </div>
          <div className="flex items-center space-x-2">
            <Button variant="outline" size="sm" className="text-muted-foreground">
              <Filter className="w-4 h-4 mr-2" />
              Filter
            </Button>
            <Button variant="outline" size="sm" className="text-muted-foreground">
              <ArrowUpDown className="w-4 h-4 mr-2" />
              Sort
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-4">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="flex items-center space-x-4 p-4 rounded-lg bg-gray-50">
                <div className="w-10 h-10 skeleton-shimmer rounded-full"></div>
                <div className="flex-1 space-y-2">
                  <div className="h-4 skeleton-shimmer rounded w-3/4"></div>
                  <div className="h-3 skeleton-shimmer rounded w-1/2"></div>
                </div>
              </div>
            ))}
          </div>
        ) : recentActivities.length === 0 ? (
          <div className="text-center py-12">
            <Activity className="w-12 h-12 text-muted-foreground/30 mx-auto mb-4" />
            <p className="text-muted-foreground">No recent activity</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-100">
                  <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Type</th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Description</th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                  <th className="text-left py-3 px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Date</th>
                </tr>
              </thead>
              <tbody>
                {recentActivities.map((log: any) => {
                  const { icon: IconComponent, color, bg } = getActivityIcon(log.action);
                  
                  return (
                    <tr 
                      key={log.id} 
                      className="border-b border-gray-50 hover:bg-gray-50/50 transition-colors"
                      data-testid={`activity-item-${log.id}`}
                    >
                      <td className="py-4 px-4">
                        <div className="flex items-center space-x-3">
                          <div className={`w-8 h-8 ${bg} rounded-lg flex items-center justify-center`}>
                            <IconComponent className={`w-4 h-4 ${color}`} />
                          </div>
                          <span className="font-medium text-sm capitalize">{log.resourceType}</span>
                        </div>
                      </td>
                      <td className="py-4 px-4">
                        <span className="text-sm text-foreground">{getActivityDescription(log)}</span>
                      </td>
                      <td className="py-4 px-4">
                        {getStatusBadge(log.action)}
                      </td>
                      <td className="py-4 px-4">
                        <span className="text-sm text-muted-foreground">
                          {format(new Date(log.createdAt), 'MMM d, yyyy h:mm a')}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
