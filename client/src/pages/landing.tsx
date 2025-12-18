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
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { Loader2, Eye, EyeOff, Heart, LogIn, UserPlusIcon } from "lucide-react";
import PendingVerification from "@/components/pending-verification";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export default function Landing() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showLoginPassword, setShowLoginPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [showPendingVerification, setShowPendingVerification] = useState(false);
  const [isRegistering, setIsRegistering] = useState(false);
  const [showForgotPassword, setShowForgotPassword] = useState(false);

  // Registration form state
  const [regEmail, setRegEmail] = useState("");
  const [regPassword, setRegPassword] = useState("");
  const [regConfirmPassword, setRegConfirmPassword] = useState("");
  const [regFirstName, setRegFirstName] = useState("");
  const [regLastName, setRegLastName] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  // Forgot password state
  const [fpEmail, setFpEmail] = useState("");
  const [fpOtp, setFpOtp] = useState("");
  const [fpResetToken, setFpResetToken] = useState<string | null>(null);
  const [fpNewPassword, setFpNewPassword] = useState("");
  const [fpConfirmPassword, setFpConfirmPassword] = useState("");
  const [fpShowNewPassword, setFpShowNewPassword] = useState(false);
  const [fpShowConfirmPassword, setFpShowConfirmPassword] = useState(false);
  const [fpStep, setFpStep] = useState<"email" | "otp" | "reset">("email");
  const [fpSendingOtp, setFpSendingOtp] = useState(false);
  const [fpVerifyingOtp, setFpVerifyingOtp] = useState(false);
  const [fpResetting, setFpResetting] = useState(false);
  const [fpCooldownSeconds, setFpCooldownSeconds] = useState(0);

  const { toast } = useToast();

  const startCooldown = (seconds: number) => {
    setFpCooldownSeconds(seconds);
    const startedAt = Date.now();
    const interval = window.setInterval(() => {
      const elapsed = Math.floor((Date.now() - startedAt) / 1000);
      const remaining = Math.max(0, seconds - elapsed);
      setFpCooldownSeconds(remaining);
      if (remaining <= 0) {
        window.clearInterval(interval);
      }
    }, 250);
  };

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

  const handleForgotPasswordSendOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setFpSendingOtp(true);

    try {
      const response = await apiRequest(
        "POST",
        "/api/auth/forgot-password/request",
        { email: fpEmail }
      );

      if (response.ok) {
        const data = await response.json();
        toast({
          title: "OTP sent",
          description:
            data.message ||
            "We sent a one-time code to your email. It expires soon.",
        });
        setFpStep("otp");
        setFpOtp("");
        setFpResetToken(null);
        startCooldown(Number(data.cooldownSeconds || 30));
        return;
      }

      const error = await response.json();
      if (error.code === "ACCOUNT_NOT_FOUND") {
        toast({
          variant: "destructive",
          title: "Account not found",
          description: "Account not found. Please register.",
        });
        return;
      }

      if (error.code === "OTP_RATE_LIMIT") {
        toast({
          variant: "destructive",
          title: "Too many requests",
          description:
            error.message ||
            "Too many OTP requests. Please wait a few minutes and try again.",
        });
        if (error.retryAfterSeconds) {
          startCooldown(Number(error.retryAfterSeconds));
        }
        return;
      }

      toast({
        variant: "destructive",
        title: "Failed to send OTP",
        description: error.message || "Please try again.",
      });
    } catch (error: any) {
      console.log(error);
      toast({
        variant: "destructive",
        title: "Failed to send OTP",
        description: "Please try again.",
      });
    } finally {
      setFpSendingOtp(false);
    }
  };

  const handleForgotPasswordVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setFpVerifyingOtp(true);

    try {
      const response = await apiRequest(
        "POST",
        "/api/auth/forgot-password/verify",
        {
          email: fpEmail,
          otp: fpOtp,
        }
      );

      if (response.ok) {
        const data = await response.json();
        setFpResetToken(String(data.resetToken || ""));
        toast({
          title: "OTP verified",
          description: "OTP verified. Please set your new password.",
        });
        setFpStep("reset");
        return;
      }

      const error = await response.json();
      if (error.code === "ACCOUNT_NOT_FOUND") {
        toast({
          variant: "destructive",
          title: "Account not found",
          description: "Account not found. Please register.",
        });
        setFpStep("email");
        return;
      }

      if (error.code === "OTP_NOT_FOUND") {
        toast({
          variant: "destructive",
          title: "OTP expired",
          description:
            error.message || "OTP expired. Please request a new OTP.",
        });
        setFpStep("email");
        return;
      }

      if (error.code === "OTP_INVALID") {
        toast({
          variant: "destructive",
          title: "Invalid OTP",
          description: error.message || "Invalid OTP. Please try again.",
        });
        return;
      }

      toast({
        variant: "destructive",
        title: "OTP verification failed",
        description: error.message || "Please try again.",
      });
    } catch (error: any) {
      console.log(error);
      toast({
        variant: "destructive",
        title: "OTP verification failed",
        description: "Please try again.",
      });
    } finally {
      setFpVerifyingOtp(false);
    }
  };

  const handleForgotPasswordReset = async (e: React.FormEvent) => {
    e.preventDefault();

    if (fpNewPassword !== fpConfirmPassword) {
      toast({
        variant: "destructive",
        title: "Password mismatch",
        description: "Passwords do not match",
      });
      return;
    }

    if (fpNewPassword.length < 8) {
      toast({
        variant: "destructive",
        title: "Invalid password",
        description: "Password must be at least 8 characters",
      });
      return;
    }

    setFpResetting(true);
    try {
      const response = await apiRequest(
        "POST",
        "/api/auth/forgot-password/reset",
        {
          email: fpEmail,
          resetToken: fpResetToken,
          newPassword: fpNewPassword,
          confirmPassword: fpConfirmPassword,
        }
      );

      if (response.ok) {
        const data = await response.json();
        toast({
          title: "Password updated",
          description:
            data.message || "You can now sign in with your new password.",
        });

        // Reset forgot-password state and go back to login
        setShowForgotPassword(false);
        setFpStep("email");
        setFpEmail("");
        setFpOtp("");
        setFpResetToken(null);
        setFpNewPassword("");
        setFpConfirmPassword("");
        setFpShowNewPassword(false);
        setFpShowConfirmPassword(false);
        setFpCooldownSeconds(0);
        return;
      }

      const error = await response.json();
      if (error.code === "ACCOUNT_NOT_FOUND") {
        toast({
          variant: "destructive",
          title: "Account not found",
          description: "Account not found. Please register.",
        });
        setFpStep("email");
        return;
      }

      if (error.code === "OTP_NOT_FOUND") {
        toast({
          variant: "destructive",
          title: "OTP expired",
          description:
            error.message || "OTP expired. Please request a new OTP.",
        });
        setFpStep("email");
        return;
      }

      if (error.code === "OTP_INVALID") {
        toast({
          variant: "destructive",
          title: "Invalid OTP",
          description: error.message || "Invalid OTP. Please try again.",
        });
        return;
      }

      if (error.code === "RESET_TOKEN_INVALID") {
        toast({
          variant: "destructive",
          title: "Session expired",
          description:
            error.message || "Verification expired. Please request a new OTP.",
        });
        setFpStep("email");
        setFpOtp("");
        setFpResetToken(null);
        return;
      }

      toast({
        variant: "destructive",
        title: "Reset failed",
        description:
          error.message || "Failed to reset password. Please try again.",
      });
    } catch (error: any) {
      console.log(error);
      toast({
        variant: "destructive",
        title: "Reset failed",
        description: "Failed to reset password. Please try again.",
      });
    } finally {
      setFpResetting(false);
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

  if (showForgotPassword) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-1 text-center">
            <div className="flex justify-center mb-4">
              <div className="w-16 h-16 bg-primary rounded-lg flex items-center justify-center">
                <Heart className="w-6 h-6 text-white" />
              </div>
            </div>
            <CardTitle className="text-2xl font-bold">Reset Password</CardTitle>
            <CardDescription>
              Enter your email to receive an OTP, then set a new password.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {fpStep === "email" ? (
              <form
                onSubmit={handleForgotPasswordSendOtp}
                className="space-y-4"
              >
                <div className="space-y-2">
                  <Label htmlFor="fp-email">Email</Label>
                  <Input
                    id="fp-email"
                    type="email"
                    placeholder="your.email@example.com"
                    value={fpEmail}
                    onChange={(e) => setFpEmail(e.target.value)}
                    required
                    disabled={fpSendingOtp}
                  />
                </div>
                <Button
                  type="submit"
                  className="w-full"
                  disabled={fpSendingOtp}
                >
                  {fpSendingOtp ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Sending OTP...
                    </>
                  ) : (
                    "Get OTP"
                  )}
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  className="w-full"
                  disabled={fpSendingOtp}
                  onClick={() => {
                    setShowForgotPassword(false);
                    setFpStep("email");
                  }}
                >
                  Back to Sign In
                </Button>
              </form>
            ) : fpStep === "otp" ? (
              <form
                onSubmit={handleForgotPasswordVerifyOtp}
                className="space-y-4"
              >
                <div className="space-y-2">
                  <Label htmlFor="fp-email-readonly">Email</Label>
                  <Input
                    id="fp-email-readonly"
                    type="email"
                    value={fpEmail}
                    disabled
                  />
                </div>

                <div className="space-y-2">
                  <Label>Enter the OTP sent to your email</Label>
                  <div className="flex justify-center">
                    <InputOTP
                      value={fpOtp}
                      onChange={(value) =>
                        setFpOtp(String(value).replace(/\D/g, "").slice(0, 6))
                      }
                      maxLength={6}
                      inputMode="numeric"
                      disabled={fpVerifyingOtp || fpSendingOtp}
                      autoFocus
                    >
                      <InputOTPGroup>
                        <InputOTPSlot index={0} />
                        <InputOTPSlot index={1} />
                        <InputOTPSlot index={2} />
                        <InputOTPSlot index={3} />
                        <InputOTPSlot index={4} />
                        <InputOTPSlot index={5} />
                      </InputOTPGroup>
                    </InputOTP>
                  </div>
                  <div className="flex items-center justify-between">
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      disabled={
                        fpSendingOtp || fpCooldownSeconds > 0 || fpVerifyingOtp
                      }
                      onClick={async () => {
                        await handleForgotPasswordSendOtp({
                          preventDefault: () => {},
                        } as any);
                      }}
                    >
                      {fpCooldownSeconds > 0
                        ? `Resend OTP in ${fpCooldownSeconds}s`
                        : "Resend OTP"}
                    </Button>
                  </div>
                </div>

                <Button
                  type="submit"
                  className="w-full"
                  disabled={fpVerifyingOtp || fpOtp.length !== 6}
                >
                  {fpVerifyingOtp ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Verifying...
                    </>
                  ) : (
                    "Verify OTP"
                  )}
                </Button>

                <Button
                  type="button"
                  variant="ghost"
                  className="w-full"
                  disabled={fpVerifyingOtp}
                  onClick={() => {
                    setFpStep("email");
                    setFpOtp("");
                    setFpResetToken(null);
                    setFpNewPassword("");
                    setFpConfirmPassword("");
                    setFpShowNewPassword(false);
                    setFpShowConfirmPassword(false);
                  }}
                >
                  Use a different email
                </Button>
              </form>
            ) : (
              <form onSubmit={handleForgotPasswordReset} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="fp-email-readonly">Email</Label>
                  <Input
                    id="fp-email-readonly"
                    type="email"
                    value={fpEmail}
                    disabled
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="fp-new-password">New Password</Label>
                  <div className="relative">
                    <Input
                      id="fp-new-password"
                      type={fpShowNewPassword ? "text" : "password"}
                      placeholder="At least 8 characters"
                      value={fpNewPassword}
                      onChange={(e) => setFpNewPassword(e.target.value)}
                      required
                      disabled={fpResetting}
                      minLength={8}
                      className="pr-10"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                      onClick={() => setFpShowNewPassword(!fpShowNewPassword)}
                      disabled={fpResetting}
                      aria-label={
                        fpShowNewPassword ? "Hide password" : "Show password"
                      }
                    >
                      {fpShowNewPassword ? (
                        <EyeOff className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <Eye className="h-4 w-4 text-muted-foreground" />
                      )}
                    </Button>
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="fp-confirm-password">Confirm Password</Label>
                  <div className="relative">
                    <Input
                      id="fp-confirm-password"
                      type={fpShowConfirmPassword ? "text" : "password"}
                      placeholder="Confirm your password"
                      value={fpConfirmPassword}
                      onChange={(e) => setFpConfirmPassword(e.target.value)}
                      required
                      disabled={fpResetting}
                      minLength={8}
                      className="pr-10"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                      onClick={() =>
                        setFpShowConfirmPassword(!fpShowConfirmPassword)
                      }
                      disabled={fpResetting}
                      aria-label={
                        fpShowConfirmPassword
                          ? "Hide password"
                          : "Show password"
                      }
                    >
                      {fpShowConfirmPassword ? (
                        <EyeOff className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <Eye className="h-4 w-4 text-muted-foreground" />
                      )}
                    </Button>
                  </div>
                </div>
                <Button type="submit" className="w-full" disabled={fpResetting}>
                  {fpResetting ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Updating...
                    </>
                  ) : (
                    "Update Password"
                  )}
                </Button>

                <Button
                  type="button"
                  variant="ghost"
                  className="w-full"
                  onClick={() => {
                    setFpStep("otp");
                    setFpNewPassword("");
                    setFpConfirmPassword("");
                    setFpShowNewPassword(false);
                    setFpShowConfirmPassword(false);
                  }}
                >
                  Back to Reset Password
                </Button>
              </form>
            )}
          </CardContent>
        </Card>
      </div>
    );
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
                  <div className="flex justify-between items-center">
                    <Label htmlFor="password">Password</Label>
                    <div className="flex justify-end">
                      <Button
                        type="button"
                        variant="link"
                        className="px-0 text-xs"
                        disabled={isLoading}
                        tabIndex={-1}
                        onClick={() => {
                          setShowForgotPassword(true);
                          setFpEmail(email);
                          setFpStep("email");
                        }}
                      >
                        Forgot password?
                      </Button>
                    </div>
                  </div>
                  <div className="relative">
                    <Input
                      id="password"
                      type={showLoginPassword ? "text" : "password"}
                      placeholder="Enter your password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      disabled={isLoading}
                      data-testid="input-password"
                      className="pr-10"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                      onClick={() => setShowLoginPassword(!showLoginPassword)}
                      disabled={isLoading}
                      aria-label={
                        showLoginPassword ? "Hide password" : "Show password"
                      }
                    >
                      {showLoginPassword ? (
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
                    onChange={(e) =>
                      setRegFirstName(
                        e.target.value.charAt(0).toUpperCase() +
                          e.target.value.slice(1).toLowerCase()
                      )
                    }
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
                    onChange={(e) =>
                      setRegLastName(
                        e.target.value.charAt(0).toUpperCase() +
                          e.target.value.slice(1).toLowerCase()
                      )
                    }
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
