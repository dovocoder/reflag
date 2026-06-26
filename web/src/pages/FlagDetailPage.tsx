import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Flag } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Input, Label, Textarea, Select } from "@/components/ui/form";
import { ArrowLeft, Save, Trash2, Plus, X, Lock } from "lucide-react";
import { useState, useEffect } from "react";

export function FlagDetailPage({ id, onNavigate }: { id: string; onNavigate: (path: string) => void }) {
  const isNew = id === "new";
  const queryClient = useQueryClient();

  const { data: flag, isLoading } = useQuery({
    queryKey: ["flag", id],
    queryFn: () => api.getFlag(id),
    enabled: !isNew,
  });

  const { data: secrets } = useQuery({
    queryKey: ["secrets"],
    queryFn: api.listSecrets,
  });

  const [form, setForm] = useState<Partial<Flag>>({
    key: "",
    name: "",
    description: "",
    type: "boolean",
    enabled: false,
    variations: [{ id: "true-var", label: "True", value: true }, { id: "false-var", label: "False", value: false }],
    targeting_rules: [],
    default_rule: { variation_id: "false-var" },
  });

  const isSecretType = form.type === "secret";

  useEffect(() => {
    if (flag) {
      setForm(flag);
    }
  }, [flag]);

  const saveMutation = useMutation({
    mutationFn: (data: Partial<Flag>) => {
      if (isNew) return api.createFlag(data);
      return api.updateFlag(id, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["flags"] });
      onNavigate("/flags");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => api.deleteFlag(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["flags"] });
      onNavigate("/flags");
    },
  });

  if (!isNew && isLoading) return <p className="text-[var(--color-muted-foreground)]">Loading...</p>;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="icon" onClick={() => onNavigate("/flags")}>
          <ArrowLeft className="size-4" />
        </Button>
        <h1 className="text-2xl font-bold">{isNew ? "Create Flag" : "Edit Flag"}</h1>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Basic Info</CardTitle>
          <CardDescription>Configure the flag key, type, and description.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Key</Label>
            <Input
              value={form.key || ""}
              onChange={(e) => setForm({ ...form, key: e.target.value })}
              placeholder="my-feature-flag"
              disabled={!isNew}
            />
          </div>
          <div className="space-y-2">
            <Label>Name</Label>
            <Input
              value={form.name || ""}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="My Feature Flag"
            />
          </div>
          <div className="space-y-2">
            <Label>Description</Label>
            <Textarea
              value={form.description || ""}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              placeholder="What does this flag control?"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Type</Label>
              <Select
                value={form.type || "boolean"}
                onChange={(e) => setForm({ ...form, type: e.target.value as Flag["type"] })}
                disabled={!isNew}
              >
                <option value="boolean">Boolean</option>
                <option value="string">String</option>
                <option value="number">Number</option>
                <option value="object">Object (JSON)</option>
                <option value="secret">Secret (encrypted)</option>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>State</Label>
              <div className="flex items-center gap-2 pt-1">
                <Button
                  variant={form.enabled ? "default" : "outline"}
                  size="sm"
                  onClick={() => setForm({ ...form, enabled: !form.enabled })}
                >
                  {form.enabled ? "Enabled" : "Disabled"}
                </Button>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Variations */}
      <Card>
        <CardHeader>
          <CardTitle>Variations</CardTitle>
          <CardDescription>The possible values this flag can resolve to.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {(form.variations || []).map((v, i) => {
            const secretRef = typeof v.value === "object" && v.value !== null && "$secret" in (v.value as Record<string, unknown>)
              ? (v.value as Record<string, string>)["$secret"] : "";
            return (
            <div key={v.id} className="flex items-center gap-2">
              <Input
                value={v.label}
                onChange={(e) => {
                  const variations = [...(form.variations || [])];
                  variations[i] = { ...v, label: e.target.value };
                  setForm({ ...form, variations });
                }}
                placeholder="Variation label"
                className="flex-1"
              />
              {isSecretType ? (
                <div className="flex-1 flex items-center gap-1">
                  <Lock className="size-3 text-[var(--color-muted-foreground)] shrink-0" />
                  <Select
                    value={secretRef}
                    onChange={(e) => {
                      const variations = [...(form.variations || [])];
                      variations[i] = { ...v, value: { "$secret": e.target.value } };
                      setForm({ ...form, variations });
                    }}
                    className="flex-1"
                  >
                    <option value="">Select secret...</option>
                    {secrets?.map((s) => (
                      <option key={s.id} value={s.key}>{s.key}</option>
                    ))}
                  </Select>
                </div>
              ) : (
                <Input
                  value={typeof v.value === "object" ? JSON.stringify(v.value) : String(v.value)}
                  onChange={(e) => {
                    const variations = [...(form.variations || [])];
                    let val: unknown = e.target.value;
                    if (form.type === "boolean") val = e.target.value === "true";
                    else if (form.type === "number") val = parseFloat(e.target.value) || 0;
                    else if (form.type === "object") try { val = JSON.parse(e.target.value); } catch { val = e.target.value; }
                    variations[i] = { ...v, value: val };
                    setForm({ ...form, variations });
                  }}
                  placeholder="Value"
                  className="flex-1"
                />
              )}
              <Button
                variant="ghost"
                size="icon"
                onClick={() => {
                  const variations = (form.variations || []).filter(x => x.id !== v.id);
                  setForm({ ...form, variations });
                }}
              >
                <X className="size-4" />
              </Button>
            </div>
            );
          })}
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              const variations = [...(form.variations || [])];
              if (isSecretType) {
                variations.push({ id: `var-${Date.now()}`, label: "", value: { "$secret": "" } });
              } else {
                variations.push({ id: `var-${Date.now()}`, label: "", value: form.type === "boolean" ? false : "" });
              }
              setForm({ ...form, variations });
            }}
          >
            <Plus className="size-4" />
            Add Variation
          </Button>
        </CardContent>
      </Card>

      {/* Default Rule */}
      <Card>
        <CardHeader>
          <CardTitle>Default Rule</CardTitle>
          <CardDescription>Fallback when no targeting rules match.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <Label>Serve Variation</Label>
          <Select
            value={form.default_rule?.variation_id || ""}
            onChange={(e) => setForm({ ...form, default_rule: { ...form.default_rule, variation_id: e.target.value } })}
          >
            {(form.variations || []).map((v) => (
              <option key={v.id} value={v.id}>{v.label}</option>
            ))}
          </Select>
        </CardContent>
      </Card>

      {/* Actions */}
      <div className="flex items-center justify-between">
        {!isNew && (
          <Button
            variant="destructive"
            onClick={() => {
              if (confirm("Delete this flag?")) deleteMutation.mutate();
            }}
          >
            <Trash2 className="size-4" />
            Delete
          </Button>
        )}
        <Button onClick={() => saveMutation.mutate(form)} disabled={saveMutation.isPending}>
          <Save className="size-4" />
          {saveMutation.isPending ? "Saving..." : "Save"}
        </Button>
      </div>
    </div>
  );
}
