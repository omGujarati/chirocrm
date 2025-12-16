import { Card, CardContent } from "@/components/ui/card";
import { Users, Clock, CheckCircle, CalendarCheck, TrendingUp, TrendingDown } from "lucide-react";

interface StatsCardsProps {
  stats?: {
    totalPatients: number;
    pendingConsent: number;
    consentSigned: number;
    schedulable: number;
  };
  isLoading: boolean;
}

export default function StatsCards({ stats, isLoading }: StatsCardsProps) {
  const cards = [
    {
      title: "Total Patients",
      value: stats?.totalPatients || 0,
      icon: Users,
      trend: 15.8,
      trendUp: true,
      gradient: "from-emerald-500 to-emerald-600",
      iconBg: "bg-emerald-500/10",
      iconColor: "text-emerald-500",
      testId: "stat-total-patients"
    },
    {
      title: "Pending Consent",
      value: stats?.pendingConsent || 0,
      icon: Clock,
      trend: -5.2,
      trendUp: false,
      gradient: "from-amber-500 to-amber-600",
      iconBg: "bg-amber-500/10",
      iconColor: "text-amber-500",
      testId: "stat-pending-consent"
    },
    {
      title: "Consent Signed",
      value: stats?.consentSigned || 0,
      icon: CheckCircle,
      trend: 12.3,
      trendUp: true,
      gradient: "from-blue-500 to-blue-600",
      iconBg: "bg-blue-500/10",
      iconColor: "text-blue-500",
      testId: "stat-consent-signed"
    },
    {
      title: "Ready to Schedule",
      value: stats?.schedulable || 0,
      icon: CalendarCheck,
      trend: 8.5,
      trendUp: true,
      gradient: "from-purple-500 to-purple-600",
      iconBg: "bg-purple-500/10",
      iconColor: "text-purple-500",
      testId: "stat-schedulable"
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
      {cards.map((card) => {
        const IconComponent = card.icon;
        const TrendIcon = card.trendUp ? TrendingUp : TrendingDown;
        
        return (
          <Card 
            key={card.title} 
            className="hover-lift border-0 shadow-md bg-white overflow-hidden"
            data-testid={card.testId}
          >
            <CardContent className="p-6">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <p className="text-sm font-medium text-muted-foreground uppercase tracking-wide mb-2">
                    {card.title}
                  </p>
                  {isLoading ? (
                    <div className="h-10 w-20 skeleton-shimmer rounded-lg"></div>
                  ) : (
                    <p className="text-4xl font-bold text-foreground tracking-tight">
                      {card.value.toLocaleString()}
                    </p>
                  )}
                  <div className={`flex items-center mt-3 text-sm font-medium ${
                    card.trendUp ? 'text-emerald-600' : 'text-red-500'
                  }`}>
                    <TrendIcon className="w-4 h-4 mr-1" />
                    <span>{Math.abs(card.trend)}%</span>
                    <span className="text-muted-foreground ml-1 font-normal">vs last month</span>
                  </div>
                </div>
                <div className={`p-3 rounded-xl ${card.iconBg}`}>
                  <IconComponent className={`w-6 h-6 ${card.iconColor}`} />
                </div>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
