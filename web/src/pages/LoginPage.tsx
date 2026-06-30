import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/form";

export function LoginPage({ onLogin, onRoleChange }: { onLogin: () => void; onRoleChange?: (role: string | undefined) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [oidcAvailable, setOidcAvailable] = useState(false);

  // Handle OIDC callback FIRST — before any other effect that might
  // call oidcStart and overwrite the state/PKCE cookies.
  // This runs only when the URL contains ?code=... (redirect from IdP).
  const [callbackHandled, setCallbackHandled] = useState(false);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    if (code && !callbackHandled) {
      // R6-F4: Strip code from URL to prevent history/referer leakage
      history.replaceState({}, "", window.location.pathname);
      setCallbackHandled(true);
      handleCallback(code, state || "");
    }
  }, [callbackHandled]);

  // Check OIDC availability using the side-effect-free status endpoint.
  // NEVER call oidcStart here — it sets state/PKCE cookies and would
  // clobber the cookies from the actual OIDC flow if a callback is in progress.
  useEffect(() => {
    // Don't check availability while processing a callback
    const params = new URLSearchParams(window.location.search);
    if (params.get("code")) return;

    fetch("/api/auth/oidc/status")
      .then((res) => res.json())
      .then((data) => setOidcAvailable(data.available === true))
      .catch(() => setOidcAvailable(false));
  }, []);

  const handleAdminLogin = async () => {
    try {
      setLoading(true);
      setError("");
      const { user } = await api.adminLogin({ email, password });
      // Token is set as HttpOnly cookie by the server — no client-side handling needed
      if (user?.role) {
        sessionStorage.setItem("reflag_role", user.role);
        onRoleChange?.(user.role);
      }
      onLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const handleOIDC = async () => {
    try {
      setLoading(true);
      const { authorization_url } = await api.oidcStart();
      // R6-F1: Validate OIDC redirect URL before navigating
      const url = new URL(authorization_url);
      if (!url.protocol.startsWith("https")) {
        setError("OIDC provider URL must use HTTPS");
        return;
      }
      window.location.href = authorization_url;
    } catch (err) {
      setError(err instanceof Error ? err.message : "OIDC login failed");
    } finally {
      setLoading(false);
    }
  };

  const handleCallback = async (code: string, state: string) => {
    try {
      setLoading(true);
      const res = await fetch("/api/auth/oidc/callback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, state }),
        credentials: "include", // R6-F4: ensure cookie is set
      });
      const data = await res.json();
      if (res.ok && data.user) {
        // Token is set as HttpOnly cookie by the server
        if (data.user?.role) {
          sessionStorage.setItem("reflag_role", data.user.role);
          onRoleChange?.(data.user.role);
        }
        onLogin();
      } else {
        setError(data.error || "Authentication failed");
      }
    } catch {
      setError("Callback failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl">🚩 Reflag</CardTitle>
          <CardDescription>Feature Flags & Remote Config</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && (
            <div className="p-3 rounded-md bg-[var(--color-destructive)]/10 text-[var(--color-destructive)] text-sm">
              {error}
            </div>
          )}

          {/* Admin login form */}
          <div className="space-y-3">
            <div className="space-y-1">
              <Label>Email</Label>
              <Input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@example.com"
              />
            </div>
            <div className="space-y-1">
              <Label>Password</Label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") handleAdminLogin(); }}
                placeholder="••••••••"
              />
            </div>
            <Button onClick={handleAdminLogin} disabled={loading} className="w-full" size="lg">
              {loading ? "Signing in..." : "Sign in"}
            </Button>
          </div>

          {oidcAvailable && (
            <>
              <div className="flex items-center gap-3">
                <div className="flex-1 h-px bg-[var(--color-border)]" />
                <span className="text-xs text-[var(--color-muted-foreground)]">OR</span>
                <div className="flex-1 h-px bg-[var(--color-border)]" />
              </div>
              <Button onClick={handleOIDC} variant="outline" className="w-full">
                Sign in with OIDC
              </Button>
            </>
          )}

          {!oidcAvailable && (
            <p className="text-center text-xs text-[var(--color-muted-foreground)]">
              Admin login via ADMIN_EMAIL / ADMIN_PASSWORD env vars.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
