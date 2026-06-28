import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Condition } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input, Label, Textarea } from "@/components/ui/form";
import { Badge } from "@/components/ui/badge";
import { Users, Trash2, Plus } from "lucide-react";
import { useState } from "react";

export function SegmentsPage() {
  const queryClient = useQueryClient();
  const { data: segments } = useQuery({ queryKey: ["segments"], queryFn: api.listSegments });
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ key: "", name: "", description: "", conditions: "[]" });

  const createMutation = useMutation({
    mutationFn: () => {
      let conditions: Condition[];
      try {
        conditions = JSON.parse(form.conditions || "[]");
      } catch {
        throw new Error("Invalid JSON in conditions field");
      }
      return api.createSegment({ key: form.key, name: form.name, description: form.description, conditions });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["segments"] });
      setForm({ key: "", name: "", description: "", conditions: "[]" });
      setShowForm(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteSegment(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["segments"] }),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Segments</h1>
        <Button onClick={() => setShowForm(!showForm)}>
          <Plus className="size-4" />
          New Segment
        </Button>
      </div>

      {showForm && (
        <Card>
          <CardContent className="space-y-3 py-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>Key</Label>
                <Input value={form.key} onChange={(e) => setForm({ ...form, key: e.target.value })} placeholder="beta-users" />
              </div>
              <div className="space-y-1">
                <Label>Name</Label>
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Beta Users" />
              </div>
            </div>
            <div className="space-y-1">
              <Label>Description</Label>
              <Input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </div>
            <div className="space-y-1">
              <Label>Conditions (JSON array)</Label>
              <Textarea
                value={form.conditions}
                onChange={(e) => setForm({ ...form, conditions: e.target.value })}
                placeholder='[{"id":"c1","attribute":"email","operator":"ends_with","values":["@beta.com"]}]'
                className="font-mono text-xs"
                rows={4}
              />
            </div>
            <Button onClick={() => createMutation.mutate()} disabled={createMutation.isPending}>
              {createMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </CardContent>
        </Card>
      )}

      <div className="space-y-2">
        {segments?.map((seg) => (
          <Card key={seg.id}>
            <CardContent className="py-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Users className="size-4 text-[var(--color-muted-foreground)]" />
                  <div>
                    <p className="font-medium">{seg.name}</p>
                    <p className="text-xs text-[var(--color-muted-foreground)]">{seg.key}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline">{seg.conditions.length} condition(s)</Badge>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => { if (confirm("Delete this segment?")) deleteMutation.mutate(seg.id); }}
                  >
                    <Trash2 className="size-4 text-[var(--color-destructive)]" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
