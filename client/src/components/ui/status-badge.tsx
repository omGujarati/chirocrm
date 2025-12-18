import { Badge } from "@/components/ui/badge";

interface StatusBadgeProps {
  status: string;
}

export default function StatusBadge({ status }: StatusBadgeProps) {
  const getStatusDisplay = (status: string) => {
    switch (status) {
      case "pending_consent":
        return {
          label: "Pending Consent",
          className: "bg-yellow-100 text-yellow-800 border-yellow-200",
        };
      case "consent_sent":
        return {
          label: "Consent Sent",
          className: "bg-blue-100 text-blue-800 border-blue-200",
        };
      case "consent_signed":
        return {
          label: "Consent Signed",
          className: "bg-green-100 text-green-800 border-green-200",
        };
      case "schedulable":
        return {
          label: "Schedulable",
          className: "bg-purple-100 text-purple-800 border-purple-200",
        };
      case "treatment_completed":
        return {
          label: "Treatment Completed",
          className: "bg-emerald-100 text-emerald-800 border-emerald-200",
        };
      case "pending_records":
        return {
          label: "Pending Records",
          className: "bg-orange-100 text-orange-800 border-orange-200",
        };
      case "records_forwarded":
        return {
          label: "Records Forwarded",
          className: "bg-indigo-100 text-indigo-800 border-indigo-200",
        };
      case "records_verified":
        return {
          label: "Records Verified",
          className: "bg-teal-100 text-teal-800 border-teal-200",
        };
      case "case_closed":
        return {
          label: "Case Closed",
          className: "bg-slate-100 text-slate-800 border-slate-200",
        };
      case "dropped":
        return {
          label: "Dropped",
          className: "bg-red-100 text-red-800 border-red-200",
        };
      default:
        return {
          label: status,
          className: "bg-gray-100 text-gray-800 border-gray-200",
        };
    }
  };

  const { label, className } = getStatusDisplay(status);

  return (
    <Badge
      className={`px-2 py-1 text-xs font-medium rounded-full border ${className}`}
    >
      {label}
    </Badge>
  );
}
