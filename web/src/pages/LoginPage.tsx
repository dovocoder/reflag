import { useState, useEffect } from "react";
import { api, setToken } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";

export function LoginPage({ onLogin }: { onLogin: () => void }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [oidcConfigured, setOidcConfigured] = useState(false);

  useEffect(() => {
    api.oidcStart().then(() => setOidcConfigured(true)).catch(() => setOidcConfigured(false));
  }, []);

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

  // Handle callback from OIDC redirect
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
    } catch (err) {
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
          {oidcConfigured ? (
            <Button onClick={handleOIDC} disabled={loading} className="w-full" size="lg">
              {loading ? "Connecting..." : "Sign in with OIDC"}
            </Button>
          ) : (
            <div className="text-center text-sm text-[var(--color-muted-foreground)]">
              <p>OIDC not configured.</p>
              <p className="mt-2">Set OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_REDIRECT_URL environment variables.</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
