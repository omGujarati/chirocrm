import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { AlertCircle, Clock, X } from "lucide-react";
import { Button } from "./ui/button";
import { Link } from "wouter";

export default function PendingVerification() {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <Card className="w-full max-w-md relative">
        <Button
          variant="ghost"
          size="icon"
          className="absolute right-2 top-2 h-8 w-8 rounded-sm opacity-70 ring-offset-background transition-opacity hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
          onClick={() => (window.location.href = "/")}
          aria-label="Close"
        >
          <X className="h-4 w-4" />
          <span className="sr-only">Close</span>
        </Button>
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-4">
            <div className="w-16 h-16 bg-yellow-100 dark:bg-yellow-900 rounded-lg flex items-center justify-center">
              <Clock className="w-8 h-8 text-yellow-600 dark:text-yellow-400" />
            </div>
          </div>
          <CardTitle className="text-2xl font-bold">
            Account Pending Verification
          </CardTitle>
          <CardDescription>Your registration is being reviewed</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-start space-x-3 p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg border border-yellow-200 dark:border-yellow-800">
            <AlertCircle className="w-5 h-5 text-yellow-600 dark:text-yellow-400 mt-0.5 flex-shrink-0" />
            <div className="flex-1">
              <p className="text-sm text-yellow-800 dark:text-yellow-200">
                Your account registration has been submitted and is currently
                pending verification by an administrator.
              </p>
            </div>
          </div>

          <div className="space-y-2 text-sm text-muted-foreground">
            <p>What happens next?</p>
            <ul className="list-disc list-inside space-y-1 ml-2">
              <li>An administrator will review your registration</li>
              <li>You will be notified once your account is verified</li>
              <li>Once verified, you can sign in and access the system</li>
            </ul>
          </div>

          <div className="flex justify-center">
            <Button
              variant="outline"
              className="px-20"
              onClick={() => (window.location.href = "/")}
            >
              <Link href="/">Go Back</Link>
            </Button>
          </div>

          <div className="pt-4 border-t">
            <p className="text-xs text-muted-foreground text-center">
              If you have any questions, please contact your administrator
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
