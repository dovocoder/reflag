import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input, Label, Textarea } from "@/components/ui/form";
import { Lock, Trash2, Plus, Eye, EyeOff, Copy, Check } from "lucide-react";
import { useState } from "react";

export function SecretsPage() {
  const queryClient = useQueryClient();
  const { data: secrets } = useQuery({ queryKey: ["secrets"], queryFn: api.listSecrets });
  const [showForm, setShowForm] = useState(false);
  const [revealValues, setRevealValues] = useState<Record<string, string>>({});
  const [copied, setCopied] = useState<string | null>(null);
  const [form, setForm] = useState({ key: "", name: "", description: "", value: "", environment_id: "" });

  const createMutation = useMutation({
    mutationFn: (data: typeof form) => api.createSecret(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["secrets"] });
      setForm({ key: "", name: "", description: "", value: "", environment_id: "" });
      setShowForm(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteSecret(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["secrets"] }),
  });

  const revealMutation = useMutation({
    mutationFn: (id: string) => api.getSecret(id),
    onSuccess: (data) => {
      setRevealValues((prev) => ({ ...prev, [data.id]: data.value }));
    },
  });

  const copyValue = (id: string, value: string) => {
    navigator.clipboard.writeText(value);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Secrets</h1>
          <p className="text-sm text-[var(--color-muted-foreground)]">Encrypted at rest with AES-256-GCM</p>
        </div>
        <Button onClick={() => setShowForm(!showForm)}>
          <Plus className="size-4" />
          New Secret
        </Button>
      </div>

      {showForm && (
        <Card>
          <CardContent className="space-y-3 py-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>Key</Label>
                <Input value={form.key} onChange={(e) => setForm({ ...form, key: e.target.value })} placeholder="DATABASE_URL" />
              </div>
              <div className="space-y-1">
                <Label>Name</Label>
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Database URL" />
              </div>
            </div>
            <div className="space-y-1">
              <Label>Description</Label>
              <Input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Production database connection string" />
            </div>
            <div className="space-y-1">
              <Label>Value</Label>
              <Textarea
                value={form.value}
                onChange={(e) => setForm({ ...form, value: e.target.value })}
                placeholder="postgres://user:pass@host:5432/db"
                className="font-mono text-xs"
                rows={3}
              />
            </div>
            <div className="space-y-1">
              <Label>Environment (optional)</Label>
              <Input value={form.environment_id} onChange={(e) => setForm({ ...form, environment_id: e.target.value })} placeholder="Environment ID" />
            </div>
            <Button onClick={() => createMutation.mutate(form)} disabled={createMutation.isPending}>
              {createMutation.isPending ? "Creating..." : "Create Secret"}
            </Button>
          </CardContent>
        </Card>
      )}

      <div className="space-y-2">
        {secrets?.map((secret) => (
          <Card key={secret.id}>
            <CardContent className="py-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Lock className="size-4 text-[var(--color-muted-foreground)]" />
                  <div>
                    <p className="font-medium">{secret.name || secret.key}</p>
                    <p className="text-xs text-[var(--color-muted-foreground)] font-mono">{secret.key}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {revealValues[secret.id] ? (
                    <>
                      <code className="text-xs font-mono bg-[var(--color-secondary)] px-2 py-1 rounded max-w-[200px] truncate block">
                        {revealValues[secret.id]}
                      </code>
                      <Button variant="ghost" size="icon-sm" onClick={() => copyValue(secret.id, revealValues[secret.id])}>
                        {copied === secret.id ? <Check className="size-4" /> : <Copy className="size-4" />}
                      </Button>
                      <Button variant="ghost" size="icon-sm" onClick={() => setRevealValues((prev) => {
                        const next = { ...prev };
                        delete next[secret.id];
                        return next;
                      })}>
                        <EyeOff className="size-4" />
                      </Button>
                    </>
                  ) : (
                    <Button variant="ghost" size="sm" onClick={() => revealMutation.mutate(secret.id)}>
                      <Eye className="size-4" />
                      Reveal
                    </Button>
                  )}
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => { if (confirm("Delete this secret?")) deleteMutation.mutate(secret.id); }}
                  >
                    <Trash2 className="size-4 text-[var(--color-destructive)]" />
                  </Button>
                </div>
              </div>
              {secret.description && (
                <p className="text-xs text-[var(--color-muted-foreground)] mt-2 ml-7">{secret.description}</p>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {secrets && secrets.length === 0 && (
        <Card>
          <CardContent className="py-8 text-center text-[var(--color-muted-foreground)]">
            <Lock className="size-12 mx-auto mb-2 opacity-50" />
            No secrets yet. Create one to get started.
          </CardContent>
        </Card>
      )}
    </div>
  );
}
