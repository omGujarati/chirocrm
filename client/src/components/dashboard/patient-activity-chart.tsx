import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Legend,
} from "recharts";
import { TrendingUp, ArrowUpRight, ArrowDownRight } from "lucide-react";

type ActivityPoint = {
  name: string;
  newPatients: number;
  consents: number;
};

type ActivityResponse = {
  range: "weekly" | "monthly";
  data: ActivityPoint[];
  previousData?: ActivityPoint[];
};

interface MetricCardProps {
  label: string;
  value: string;
  change?: number;
  positive?: boolean;
}

function MetricCard({ label, value, change, positive }: MetricCardProps) {
  return (
    <div className="bg-gray-50 rounded-xl p-4">
      {typeof change === "number" && typeof positive === "boolean" ? (
        <div
          className={`w-10 h-10 rounded-lg flex items-center justify-center mb-3 ${
            positive ? "bg-emerald-100" : "bg-red-100"
          }`}
        >
          {positive ? (
            <ArrowUpRight className="w-5 h-5 text-emerald-600" />
          ) : (
            <ArrowDownRight className="w-5 h-5 text-red-500" />
          )}
        </div>
      ) : (
        <div className="w-10 h-10 rounded-lg flex items-center justify-center mb-3 bg-gray-200/60" />
      )}
      <p className="text-2xl font-bold text-foreground">{value}</p>
      <p className="text-sm text-muted-foreground mt-1">{label}</p>
      {typeof change === "number" && typeof positive === "boolean" ? (
        <p
          className={`text-sm font-medium mt-2 ${
            positive ? "text-emerald-600" : "text-red-500"
          }`}
        >
          {positive ? "+" : ""}
          {change}%
        </p>
      ) : null}
    </div>
  );
}

export default function PatientActivityChart() {
  const [timeRange, setTimeRange] = useState<'weekly' | 'monthly'>('monthly');

  const { data: activity, isLoading } = useQuery<ActivityResponse>({
    queryKey: ["/api/dashboard/activity", timeRange],
    queryFn: async () => {
      const res = await fetch(`/api/dashboard/activity?range=${timeRange}&compare=1`, {
        credentials: "include",
      });
      if (!res.ok) {
        throw new Error("Failed to fetch dashboard activity");
      }
      return (await res.json()) as ActivityResponse;
    },
  });

  const chartData = activity?.data ?? [];
  const prevChartData = activity?.previousData ?? [];
  const totalNewPatients = chartData.reduce((sum, p) => sum + (p.newPatients || 0), 0);
  const totalConsents = chartData.reduce((sum, p) => sum + (p.consents || 0), 0);
  const prevTotalNewPatients = prevChartData.reduce((sum, p) => sum + (p.newPatients || 0), 0);
  const prevTotalConsents = prevChartData.reduce((sum, p) => sum + (p.consents || 0), 0);
  const hasAnyData = chartData.some((p) => (p.newPatients || 0) > 0 || (p.consents || 0) > 0);

  function calcChangePct(current: number, previous: number): number {
    // Always return a number so the sidebar can render deterministically.
    // If previous is 0:
    // - current is 0 -> 0%
    // - current > 0 -> treat as +100% (baseline growth from 0)
    if (previous === 0) return current === 0 ? 0 : 100;
    const pct = ((current - previous) / previous) * 100;
    // One decimal is enough for small counts; MetricCard prints with % sign.
    return Math.round(pct * 10) / 10;
  }

  const newPatientsChange = calcChangePct(totalNewPatients, prevTotalNewPatients);
  const consentsChange = calcChangePct(totalConsents, prevTotalConsents);
  const newPatientsPositive = newPatientsChange >= 0;
  const consentsPositive = consentsChange >= 0;

  return (
    <Card className="border-0 shadow-md bg-white mb-8">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <TrendingUp className="w-5 h-5 text-muted-foreground" />
            <CardTitle className="text-lg font-semibold">Patient Activity</CardTitle>
          </div>
          <div className="flex items-center space-x-2">
            <div className="bg-gray-100 rounded-lg p-1 flex">
              <Button
                variant="ghost"
                size="sm"
                className={`px-4 py-1.5 text-sm rounded-md transition-all ${
                  timeRange === 'weekly' 
                    ? 'bg-white shadow-sm text-foreground' 
                    : 'text-muted-foreground hover:text-foreground'
                }`}
                onClick={() => setTimeRange('weekly')}
              >
                Weekly
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className={`px-4 py-1.5 text-sm rounded-md transition-all ${
                  timeRange === 'monthly' 
                    ? 'bg-white shadow-sm text-foreground' 
                    : 'text-muted-foreground hover:text-foreground'
                }`}
                onClick={() => setTimeRange('monthly')}
              >
                Monthly
              </Button>
            </div>
          </div>
        </div>
      </CardHeader>
      <CardContent className="pt-4">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Chart */}
          <div className="lg:col-span-3">
            <div className="h-80">
              {isLoading ? (
                <div className="h-full w-full skeleton-shimmer rounded-xl" />
              ) : !hasAnyData ? (
                <div className="h-full w-full flex items-center justify-center rounded-xl border border-dashed border-gray-200 bg-gray-50">
                  <p className="text-sm text-muted-foreground">No activity in this time range.</p>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={chartData}
                    margin={{ top: 10, right: 20, left: 0, bottom: 0 }}
                    barCategoryGap={timeRange === "weekly" ? "35%" : "25%"}
                    barGap={6}
                  >
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f0f0f0" />
                    <XAxis
                      dataKey="name"
                      axisLine={false}
                      tickLine={false}
                      tick={{ fill: "#6b7280", fontSize: 12 }}
                    />
                    <YAxis
                      axisLine={false}
                      tickLine={false}
                      tick={{ fill: "#6b7280", fontSize: 12 }}
                      allowDecimals={false}
                    />
                    <Tooltip
                      formatter={(value: any, name: any) => [Number(value).toLocaleString(), name]}
                      contentStyle={{
                        backgroundColor: "white",
                        border: "1px solid #e5e7eb",
                        borderRadius: "8px",
                        boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.1)",
                      }}
                    />
                    <Legend
                      verticalAlign="top"
                      height={24}
                      iconType="circle"
                      wrapperStyle={{ fontSize: 12, color: "#6b7280" }}
                    />
                    <Bar
                      dataKey="newPatients"
                      fill="#10b981"
                      radius={[4, 4, 0, 0]}
                      name="New Patients"
                      maxBarSize={40}
                    />
                    <Bar
                      dataKey="consents"
                      fill="#f59e0b"
                      radius={[4, 4, 0, 0]}
                      name="Consents Signed"
                      maxBarSize={40}
                    />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>
          
          {/* Metrics sidebar */}
          <div className="space-y-4">
            <MetricCard
              label="New Patients"
              value={isLoading ? "…" : totalNewPatients.toLocaleString()}
              change={newPatientsChange}
              positive={newPatientsPositive}
            />
            <MetricCard
              label="Consents Signed"
              value={isLoading ? "…" : totalConsents.toLocaleString()}
              change={consentsChange}
              positive={consentsPositive}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
