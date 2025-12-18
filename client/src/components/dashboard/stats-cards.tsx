import { Card, CardContent } from "@/components/ui/card";
import { Users, Clock, CheckCircle, CalendarCheck, TrendingUp, TrendingDown } from "lucide-react";

interface StatsCardsProps {
  stats?: {
    cards: Array<{
      key: "totalPatients" | "pendingConsent" | "consentSigned" | "schedulable";
      title: string;
      value: number;
      trendPercent: number;
      trendUp: boolean;
      trendLabel: string;
      color: "emerald" | "amber" | "blue" | "purple";
    }>;
  };
  isLoading: boolean;
}

export default function StatsCards({ stats, isLoading }: StatsCardsProps) {
  const metaByKey = {
    totalPatients: { icon: Users, testId: "stat-total-patients" },
    pendingConsent: { icon: Clock, testId: "stat-pending-consent" },
    consentSigned: { icon: CheckCircle, testId: "stat-consent-signed" },
    schedulable: { icon: CalendarCheck, testId: "stat-schedulable" },
  } as const;

  const classesByColor = {
    emerald: { iconBg: "bg-emerald-500/10", iconColor: "text-emerald-500" },
    amber: { iconBg: "bg-amber-500/10", iconColor: "text-amber-500" },
    blue: { iconBg: "bg-blue-500/10", iconColor: "text-blue-500" },
    purple: { iconBg: "bg-purple-500/10", iconColor: "text-purple-500" },
  } as const;

  const cards = (stats?.cards ?? []).map((c) => ({
    ...c,
    ...metaByKey[c.key],
    ...classesByColor[c.color],
  }));

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
                  <div
                    className={`flex items-center mt-3 text-sm font-medium ${
                      card.trendUp ? "text-emerald-600" : "text-red-500"
                    }`}
                  >
                    <TrendIcon className="w-4 h-4 mr-1" />
                    <span>{card.trendPercent}%</span>
                    <span className="text-muted-foreground ml-1 font-normal">{card.trendLabel}</span>
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
