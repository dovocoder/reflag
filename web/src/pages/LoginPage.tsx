import { useState, useEffect } from "react";
import { api, setToken } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/form";

export function LoginPage({ onLogin }: { onLogin: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [oidcAvailable, setOidcAvailable] = useState(false);

  useEffect(() => {
    api.oidcStart().then(() => setOidcAvailable(true)).catch(() => setOidcAvailable(false));
  }, []);

  const handleAdminLogin = async () => {
    try {
      setLoading(true);
      setError("");
      const { token } = await api.adminLogin({ email, password });
      setToken(token);
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
      window.location.href = authorization_url;
    } catch (err) {
      setError(err instanceof Error ? err.message : "OIDC login failed");
    } finally {
      setLoading(false);
    }
  };

  // Handle OIDC callback
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    if (code) {
      handleCallback(code);
    }
  }, []);

  const handleCallback = async (code: string) => {
    try {
      setLoading(true);
      const res = await fetch("/api/auth/oidc/callback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      const data = await res.json();
      if (data.token) {
        setToken(data.token);
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
