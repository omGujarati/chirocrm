import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from "recharts";
import { TrendingUp, ArrowUpRight, ArrowDownRight } from "lucide-react";

const generateMockData = () => {
  const data = [];
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  
  for (let i = 0; i < 12; i++) {
    data.push({
      name: months[i],
      newPatients: Math.floor(Math.random() * 20) + 10,
      followUps: Math.floor(Math.random() * 30) + 15,
      consents: Math.floor(Math.random() * 25) + 8,
    });
  }
  return data;
};

const data = generateMockData();

interface MetricCardProps {
  label: string;
  value: string;
  change: number;
  positive: boolean;
}

function MetricCard({ label, value, change, positive }: MetricCardProps) {
  return (
    <div className="bg-gray-50 rounded-xl p-4">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center mb-3 ${
        positive ? 'bg-emerald-100' : 'bg-red-100'
      }`}>
        {positive ? (
          <ArrowUpRight className="w-5 h-5 text-emerald-600" />
        ) : (
          <ArrowDownRight className="w-5 h-5 text-red-500" />
        )}
      </div>
      <p className="text-2xl font-bold text-foreground">{value}</p>
      <p className="text-sm text-muted-foreground mt-1">{label}</p>
      <p className={`text-sm font-medium mt-2 ${positive ? 'text-emerald-600' : 'text-red-500'}`}>
        {positive ? '+' : ''}{change}%
      </p>
    </div>
  );
}

export default function PatientActivityChart() {
  const [timeRange, setTimeRange] = useState<'weekly' | 'monthly'>('monthly');

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
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f0f0f0" />
                  <XAxis 
                    dataKey="name" 
                    axisLine={false}
                    tickLine={false}
                    tick={{ fill: '#6b7280', fontSize: 12 }}
                  />
                  <YAxis 
                    axisLine={false}
                    tickLine={false}
                    tick={{ fill: '#6b7280', fontSize: 12 }}
                  />
                  <Tooltip 
                    contentStyle={{
                      backgroundColor: 'white',
                      border: '1px solid #e5e7eb',
                      borderRadius: '8px',
                      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
                    }}
                  />
                  <Bar 
                    dataKey="newPatients" 
                    fill="#10b981" 
                    radius={[4, 4, 0, 0]}
                    name="New Patients"
                  />
                  <Bar 
                    dataKey="consents" 
                    fill="#f59e0b" 
                    radius={[4, 4, 0, 0]}
                    name="Consents Signed"
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
          
          {/* Metrics sidebar */}
          <div className="space-y-4">
            <MetricCard
              label="New Patients"
              value="156"
              change={45}
              positive={true}
            />
            <MetricCard
              label="Consents Signed"
              value="142"
              change={12.5}
              positive={true}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
