import { Heart } from "lucide-react";

export default function AuthLoadingScreen() {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-6">
      {/* subtle brand-tinted backdrop */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-28 left-1/2 h-80 w-[44rem] -translate-x-1/2 rounded-full bg-primary/10 blur-3xl" />
        <div className="absolute -bottom-28 left-1/2 h-80 w-[44rem] -translate-x-1/2 rounded-full bg-primary/10 blur-3xl" />
      </div>

      <div className="relative w-full max-w-sm">
        <div className="rounded-2xl border bg-card/80 p-7 shadow-sm backdrop-blur">
          <div className="flex flex-col items-center text-center">
            <div className="gradient-primary grid h-14 w-14 place-items-center rounded-2xl shadow-sm">
             <Heart className="w-6 h-6 text-white" />
            </div>

            <div className="mt-4">
              <p className="text-base font-semibold tracking-tight">ChiroCareCRM</p>
              <p className="mt-1 text-sm text-muted-foreground">Restoring your session</p>
            </div>

            <div className="mt-6 flex items-center gap-3">
              <div
                className="h-5 w-5 animate-spin rounded-full border-2 border-primary/25 border-t-primary"
                aria-hidden="true"
              />
              <p className="text-sm text-muted-foreground">Loading…</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}


