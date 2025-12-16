import { useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import {
  Loader2,
  Eye,
  EyeOff,
  Heart,
  SignalIcon,
  UserPlusIcon,
  LogIn,
} from "lucide-react";
import PendingVerification from "@/components/pending-verification";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export default function Landing() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showPendingVerification, setShowPendingVerification] = useState(false);
  const [isRegistering, setIsRegistering] = useState(false);

  // Registration form state
  const [regEmail, setRegEmail] = useState("");
  const [regPassword, setRegPassword] = useState("");
  const [regConfirmPassword, setRegConfirmPassword] = useState("");
  const [regFirstName, setRegFirstName] = useState("");
  const [regLastName, setRegLastName] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const { toast } = useToast();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await apiRequest("POST", "/api/auth/login", {
        email,
        password,
      });

      if (response.ok) {
        const data = await response.json();
        toast({
          title: "Login successful",
          description: `Welcome back, ${data.user?.firstName || "user"}!`,
        });
        // Redirect to dashboard
        window.location.href = "/";
      } else {
        const error = await response.json();

        // Check if account is pending verification
        if (error.code === "PENDING_VERIFICATION") {
          setShowPendingVerification(true);
          return;
        }

        // Check if account is rejected
        if (error.code === "ACCOUNT_REJECTED") {
          toast({
            variant: "destructive",
            title: "Account Rejected",
            description:
              error.message ||
              "Your account has been rejected. Please contact an administrator.",
          });
          return;
        }

        toast({
          variant: "destructive",
          title: "Login failed",
          description: error.message || "Invalid email or password",
        });
      }
    } catch (error: any) {
      console.log(error);

      // Try to extract error message from the thrown error
      // apiRequest throws errors in format "401: {...json...}" or "401: error text"
      let errorMessage = "Invalid email or password";
      let errorCode: string | undefined;

      if (error?.message) {
        const message = error.message;

        // Try to extract JSON from error message (format: "401: {...json...}")
        const statusAndJsonMatch = message.match(/^(\d+):\s*({[\s\S]*})$/);

        if (statusAndJsonMatch) {
          try {
            const errorData = JSON.parse(statusAndJsonMatch[2]);
            errorMessage = errorData.message || errorMessage;
            errorCode = errorData.code;
          } catch {
            // If JSON parsing fails, fall back to default message
          }
        } else {
          // Check if it's a status code with text (format: "401: error text")
          const statusMatch = message.match(/^(\d+):\s*(.+)$/);
          if (statusMatch) {
            const statusCode = statusMatch[1];
            const statusText = statusMatch[2];

            // Try to parse statusText as JSON
            try {
              const errorData = JSON.parse(statusText);
              errorMessage = errorData.message || errorMessage;
              errorCode = errorData.code;
            } catch {
              // If not JSON, use appropriate message based on status code
              if (statusCode === "401") {
                errorMessage = "Invalid email or password";
              } else if (
                statusText &&
                statusText.trim() &&
                statusText !== statusCode
              ) {
                errorMessage = statusText;
              }
            }
          } else if (message && !message.includes(":")) {
            // If it's a simple message without status code format
            errorMessage = message;
          }
        }
      }

      // Handle specific error codes
      if (errorCode === "PENDING_VERIFICATION") {
        setShowPendingVerification(true);
        return;
      }

      if (errorCode === "ACCOUNT_REJECTED") {
        toast({
          variant: "destructive",
          title: "Account Rejected",
          description:
            errorMessage ||
            "Your account has been rejected. Please contact an administrator.",
        });
        return;
      }

      toast({
        variant: "destructive",
        title: "Login failed",
        description: errorMessage,
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();

    // Validation
    if (regPassword !== regConfirmPassword) {
      toast({
        variant: "destructive",
        title: "Password mismatch",
        description: "Passwords do not match",
      });
      return;
    }

    if (regPassword.length < 8) {
      toast({
        variant: "destructive",
        title: "Invalid password",
        description: "Password must be at least 8 characters",
      });
      return;
    }

    setIsRegistering(true);

    try {
      const response = await apiRequest("POST", "/api/auth/register", {
        email: regEmail,
        password: regPassword,
        firstName: regFirstName,
        lastName: regLastName,
      });

      if (response.ok) {
        const data = await response.json();
        toast({
          title: "Registration successful",
          description: data.message || "Your account is pending verification.",
        });
        // Show pending verification screen
        setShowPendingVerification(true);
        // Reset form
        setRegEmail("");
        setRegPassword("");
        setRegConfirmPassword("");
        setRegFirstName("");
        setRegLastName("");
      } else {
        const error = await response.json();
        toast({
          variant: "destructive",
          title: "Registration failed",
          description: error.message || "Failed to register account",
        });
      }
    } catch (error: any) {
      console.log(error);

      // Try to extract error message from the thrown error
      // apiRequest throws errors in format "400: {...json...}" or "400: error text"
      let errorMessage =
        "An error occurred during registration. Please try again.";

      if (error?.message) {
        const message = error.message;

        // Try to extract JSON from error message (format: "400: {...json...}")
        const statusAndJsonMatch = message.match(/^(\d+):\s*({[\s\S]*})$/);

        if (statusAndJsonMatch) {
          try {
            const errorData = JSON.parse(statusAndJsonMatch[2]);
            errorMessage = errorData.message || errorMessage;
          } catch {
            // If JSON parsing fails, fall back to default message
          }
        } else {
          // Check if it's a status code with text (format: "400: error text")
          const statusMatch = message.match(/^(\d+):\s*(.+)$/);
          if (statusMatch) {
            const statusCode = statusMatch[1];
            const statusText = statusMatch[2];

            // Try to parse statusText as JSON
            try {
              const errorData = JSON.parse(statusText);
              errorMessage = errorData.message || errorMessage;
            } catch {
              // If not JSON, use appropriate message based on status code
              if (statusCode === "400") {
                // For 400 errors, use the status text if available
                if (
                  statusText &&
                  statusText.trim() &&
                  statusText !== statusCode
                ) {
                  errorMessage = statusText;
                } else {
                  errorMessage =
                    "Invalid registration data. Please check your input.";
                }
              } else if (
                statusText &&
                statusText.trim() &&
                statusText !== statusCode
              ) {
                errorMessage = statusText;
              }
            }
          } else if (message && !message.includes(":")) {
            // If it's a simple message without status code format
            errorMessage = message;
          }
        }
      }

      toast({
        variant: "destructive",
        title: "Registration failed",
        description: errorMessage,
      });
    } finally {
      setIsRegistering(false);
    }
  };

  if (showPendingVerification) {
    return <PendingVerification />;
  }

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-4">
            <div className="w-16 h-16 bg-primary rounded-lg flex items-center justify-center">
              <Heart className="w-6 h-6 text-white" />
            </div>
          </div>
          <CardTitle className="text-2xl font-bold">ChiroCareCRM</CardTitle>
          <CardDescription>
            HIPAA-compliant patient management system
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="login" className="w-full">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger
                className="data-[state=active]:text-white data-[state=active]:bg-primary text-primary"
                value="login"
              >
                Sign In
              </TabsTrigger>
              <TabsTrigger
                className="data-[state=active]:text-white data-[state=active]:bg-primary text-primary"
                value="register"
              >
                Register
              </TabsTrigger>
            </TabsList>

            <TabsContent value="login" className="space-y-4 mt-4">
              <form onSubmit={handleLogin} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="your.email@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    disabled={isLoading}
                    data-testid="input-email"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    type="password"
                    placeholder="Enter your password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    disabled={isLoading}
                    data-testid="input-password"
                  />
                </div>
                <Button
                  type="submit"
                  className="w-full"
                  disabled={isLoading}
                  data-testid="button-login"
                >
                  {isLoading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Signing in...
                    </>
                  ) : (
                    <>
                      <LogIn className="w-4 h-4 mr-2" />
                      Sign In
                    </>
                  )}
                </Button>
              </form>
            </TabsContent>

            <TabsContent value="register" className="space-y-4 mt-4">
              <form onSubmit={handleRegister} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="reg-first-name">First Name</Label>
                  <Input
                    id="reg-first-name"
                    type="text"
                    placeholder="John"
                    value={regFirstName}
                    onChange={(e) => setRegFirstName(e.target.value)}
                    required
                    disabled={isRegistering}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="reg-last-name">Last Name</Label>
                  <Input
                    id="reg-last-name"
                    type="text"
                    placeholder="Doe"
                    value={regLastName}
                    onChange={(e) => setRegLastName(e.target.value)}
                    required
                    disabled={isRegistering}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="reg-email">Email</Label>
                  <Input
                    id="reg-email"
                    type="email"
                    placeholder="your.email@example.com"
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                    required
                    disabled={isRegistering}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="reg-password">Password</Label>
                  <div className="relative">
                    <Input
                      id="reg-password"
                      type={showPassword ? "text" : "password"}
                      placeholder="At least 8 characters"
                      value={regPassword}
                      onChange={(e) => setRegPassword(e.target.value)}
                      required
                      disabled={isRegistering}
                      minLength={8}
                      className="pr-10"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                      onClick={() => setShowPassword(!showPassword)}
                      disabled={isRegistering}
                    >
                      {showPassword ? (
                        <EyeOff className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <Eye className="h-4 w-4 text-muted-foreground" />
                      )}
                    </Button>
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="reg-confirm-password">Confirm Password</Label>
                  <div className="relative">
                    <Input
                      id="reg-confirm-password"
                      type={showConfirmPassword ? "text" : "password"}
                      placeholder="Confirm your password"
                      value={regConfirmPassword}
                      onChange={(e) => setRegConfirmPassword(e.target.value)}
                      required
                      disabled={isRegistering}
                      minLength={8}
                      className="pr-10"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                      onClick={() =>
                        setShowConfirmPassword(!showConfirmPassword)
                      }
                      disabled={isRegistering}
                    >
                      {showConfirmPassword ? (
                        <EyeOff className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <Eye className="h-4 w-4 text-muted-foreground" />
                      )}
                    </Button>
                  </div>
                </div>
                <Button
                  type="submit"
                  className="w-full"
                  disabled={isRegistering}
                >
                  {isRegistering ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Registering...
                    </>
                  ) : (
                    <>
                      <UserPlusIcon className="w-4 h-4 mr-2" />
                      Register
                    </>
                  )}
                </Button>
              </form>
              <p className="text-xs text-muted-foreground text-center mt-4">
                Your account will be reviewed by an administrator before you can
                sign in.
              </p>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}
