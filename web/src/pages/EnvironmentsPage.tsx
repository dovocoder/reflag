import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Environment } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/form";
import { Globe, Trash2, Plus } from "lucide-react";
import { useState } from "react";

export function EnvironmentsPage() {
  const queryClient = useQueryClient();
  const { data: envs } = useQuery({ queryKey: ["environments"], queryFn: api.listEnvironments });
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ key: "", name: "", description: "" });

  const createMutation = useMutation({
    mutationFn: (data: Partial<Environment>) => api.createEnvironment(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["environments"] });
      setForm({ key: "", name: "", description: "" });
      setShowForm(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteEnvironment(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["environments"] }),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Environments</h1>
        <Button onClick={() => setShowForm(!showForm)}>
          <Plus className="size-4" />
          New Environment
        </Button>
      </div>

      {showForm && (
        <Card>
          <CardContent className="space-y-3 py-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>Key</Label>
                <Input value={form.key} onChange={(e) => setForm({ ...form, key: e.target.value })} placeholder="staging" />
              </div>
              <div className="space-y-1">
                <Label>Name</Label>
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Staging" />
              </div>
            </div>
            <div className="space-y-1">
              <Label>Description</Label>
              <Input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Staging environment" />
            </div>
            <Button onClick={() => createMutation.mutate(form)} disabled={createMutation.isPending}>
              {createMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </CardContent>
        </Card>
      )}

      <div className="space-y-2">
        {envs?.map((env) => (
          <Card key={env.id}>
            <CardContent className="flex items-center justify-between py-4">
              <div className="flex items-center gap-3">
                <Globe className="size-4 text-[var(--color-muted-foreground)]" />
                <div>
                  <p className="font-medium">{env.name}</p>
                  <p className="text-xs text-[var(--color-muted-foreground)]">{env.key}</p>
                </div>
              </div>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => { if (confirm("Delete this environment?")) deleteMutation.mutate(env.id); }}
              >
                <Trash2 className="size-4 text-[var(--color-destructive)]" />
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
