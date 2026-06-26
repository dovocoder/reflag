import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/form";
import { Badge } from "@/components/ui/badge";
import { Key, Trash2, Plus, Copy, Check } from "lucide-react";
import { useState } from "react";

export function ApiKeysPage() {
  const queryClient = useQueryClient();
  const { data: keys } = useQuery({ queryKey: ["api-keys"], queryFn: api.listAPIKeys });
  const { data: envs } = useQuery({ queryKey: ["environments"], queryFn: api.listEnvironments });
  const [showForm, setShowForm] = useState(false);
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [form, setForm] = useState({ name: "", environment_id: "", scopes: "read,evaluate" });

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.createAPIKey({ name: data.name, environment_id: data.environment_id, scopes: data.scopes.split(",").filter(Boolean) }),
    onSuccess: (data) => {
      setCreatedKey(data.key);
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
      setForm({ name: "", environment_id: "", scopes: "read,evaluate" });
      setShowForm(false);
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => api.revokeAPIKey(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["api-keys"] }),
  });

  const copyKey = () => {
    if (createdKey) {
      navigator.clipboard.writeText(createdKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">API Keys</h1>
        <Button onClick={() => { setShowForm(!showForm); setCreatedKey(null); }}>
          <Plus className="size-4" />
          New Key
        </Button>
      </div>

      {createdKey && (
        <Card className="border-[var(--color-ring)]">
          <CardContent className="space-y-3 py-4">
            <div>
              <Label>Your new API key (shown only once)</Label>
              <div className="flex items-center gap-2 mt-1">
                <code className="flex-1 p-2 rounded-md bg-[var(--color-secondary)] text-sm font-mono break-all">
                  {createdKey}
                </code>
                <Button variant="outline" size="icon" onClick={copyKey}>
                  {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
                </Button>
              </div>
            </div>
            <p className="text-xs text-[var(--color-muted-foreground)]">
              Store this key securely. You won't be able to see it again.
            </p>
          </CardContent>
        </Card>
      )}

      {showForm && !createdKey && (
        <Card>
          <CardContent className="space-y-3 py-4">
            <div className="space-y-1">
              <Label>Name</Label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Production SDK key" />
            </div>
            <div className="space-y-1">
              <Label>Environment</Label>
              <select
                value={form.environment_id}
                onChange={(e) => setForm({ ...form, environment_id: e.target.value })}
                className="flex h-8 w-full rounded-md border border-[var(--color-input)] bg-transparent px-3 text-sm"
              >
                <option value="">All environments</option>
                {envs?.map((env) => (
                  <option key={env.id} value={env.id}>{env.name}</option>
                ))}
              </select>
            </div>
            <div className="space-y-1">
              <Label>Scopes (comma-separated)</Label>
              <Input value={form.scopes} onChange={(e) => setForm({ ...form, scopes: e.target.value })} placeholder="read,evaluate" />
            </div>
            <Button onClick={() => createMutation.mutate(form)} disabled={createMutation.isPending}>
              {createMutation.isPending ? "Creating..." : "Create Key"}
            </Button>
          </CardContent>
        </Card>
      )}

      <div className="space-y-2">
        {keys?.map((key) => (
          <Card key={key.id}>
            <CardContent className="flex items-center justify-between py-4">
              <div className="flex items-center gap-3">
                <Key className="size-4 text-[var(--color-muted-foreground)]" />
                <div>
                  <p className="font-medium">{key.name}</p>
                  <p className="text-xs text-[var(--color-muted-foreground)] font-mono">{key.key_prefix}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {key.scopes.map((s) => (
                  <Badge key={s} variant="outline">{s}</Badge>
                ))}
                {key.revoked && <Badge variant="destructive">Revoked</Badge>}
                {!key.revoked && (
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => { if (confirm("Revoke this API key?")) revokeMutation.mutate(key.id); }}
                  >
                    <Trash2 className="size-4 text-[var(--color-destructive)]" />
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
