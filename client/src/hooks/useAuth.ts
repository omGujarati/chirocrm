import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import type { User } from "@shared/schema";
import { getQueryFn } from "@/lib/queryClient";

export function useAuth() {
  const queryClient = useQueryClient();
  const { data: user, isLoading } = useQuery<User>({
    queryKey: ["/api/auth/user"],
    queryFn: getQueryFn({ on401: "returnNull" }), // Return null on 401, don't throw
    retry: false,
    staleTime: 0, // Always fetch fresh data
    refetchOnWindowFocus: true, // Refetch when user returns to tab
    refetchOnMount: true, // Always refetch on component mount
  });

  const isAuthenticated = !!user;

  // Clean auth state management - no aggressive reloads or global cache clearing
  useEffect(() => {
    // Only clear React Query cache when auth state actually changes
    if (!user && !isLoading) {
      // Clear only app-related queries, not global storage
      queryClient.invalidateQueries();
      console.log('[Auth] Cleared React Query cache for unauthenticated state');
    }
  }, [user, isLoading, queryClient]);

  const refetchUser = async () => {
    await queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
  };

  return {
    user,
    isLoading,
    isAuthenticated,
    refetchUser,
  };
}
