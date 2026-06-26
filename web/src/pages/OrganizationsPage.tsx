import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Organization } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/form";
import { Badge } from "@/components/ui/badge";
import { Building2, Trash2, Plus, UserPlus, X } from "lucide-react";
import { useState } from "react";

const roleColors: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  owner: "default",
  admin: "secondary",
  member: "outline",
  viewer: "outline",
};

export function OrganizationsPage() {
  const queryClient = useQueryClient();
  const { data: orgs } = useQuery({ queryKey: ["orgs"], queryFn: api.listOrgs });
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: "", slug: "", description: "" });
  const [selectedOrg, setSelectedOrg] = useState<string | null>(null);

  const createMutation = useMutation({
    mutationFn: (data: Partial<Organization>) => api.createOrg(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["orgs"] });
      setForm({ name: "", slug: "", description: "" });
      setShowForm(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteOrg(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["orgs"] }),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Organizations</h1>
        <Button onClick={() => setShowForm(!showForm)}>
          <Plus className="size-4" />
          New Org
        </Button>
      </div>

      {showForm && (
        <Card>
          <CardContent className="space-y-3 py-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>Name</Label>
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Acme Inc" />
              </div>
              <div className="space-y-1">
                <Label>Slug</Label>
                <Input value={form.slug} onChange={(e) => setForm({ ...form, slug: e.target.value })} placeholder="acme" />
              </div>
            </div>
            <div className="space-y-1">
              <Label>Description</Label>
              <Input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </div>
            <Button onClick={() => createMutation.mutate(form)} disabled={createMutation.isPending}>
              {createMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </CardContent>
        </Card>
      )}

      <div className="space-y-2">
        {orgs?.map((org) => (
          <Card key={org.id}>
            <CardContent className="py-4">
              <div className="flex items-center justify-between">
                <div
                  className="flex items-center gap-3 cursor-pointer"
                  onClick={() => setSelectedOrg(selectedOrg === org.id ? null : org.id)}
                >
                  <Building2 className="size-4 text-[var(--color-muted-foreground)]" />
                  <div>
                    <p className="font-medium">{org.name}</p>
                    <p className="text-xs text-[var(--color-muted-foreground)] font-mono">{org.slug}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {selectedOrg === org.id && <Badge variant="outline">expanded</Badge>}
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => { if (confirm("Delete this org?")) deleteMutation.mutate(org.id); }}
                  >
                    <Trash2 className="size-4 text-[var(--color-destructive)]" />
                  </Button>
                </div>
              </div>
              {selectedOrg === org.id && (
                <OrgMembers orgId={org.id} />
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

function OrgMembers({ orgId }: { orgId: string }) {
  const queryClient = useQueryClient();
  const { data: members } = useQuery({
    queryKey: ["org-members", orgId],
    queryFn: () => api.listOrgMembers(orgId),
  });
  const [showAdd, setShowAdd] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("member");

  const addMutation = useMutation({
    mutationFn: (data: { email: string; role: string }) => api.addOrgMember(orgId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["org-members", orgId] });
      setEmail("");
      setShowAdd(false);
    },
  });

  const updateRoleMutation = useMutation({
    mutationFn: ({ memberId, role }: { memberId: string; role: string }) => api.updateOrgMemberRole(memberId, role),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["org-members", orgId] }),
  });

  const removeMutation = useMutation({
    mutationFn: (memberId: string) => api.removeOrgMember(memberId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["org-members", orgId] }),
  });

  return (
    <div className="mt-4 pt-4 border-t border-[var(--color-border)] space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">Members</h3>
        <Button variant="outline" size="sm" onClick={() => setShowAdd(!showAdd)}>
          <UserPlus className="size-4" />
          Add Member
        </Button>
      </div>

      {showAdd && (
        <div className="flex items-end gap-2">
          <div className="flex-1 space-y-1">
            <Label>Email</Label>
            <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="user@example.com" />
          </div>
          <div className="space-y-1">
            <Label>Role</Label>
            <Select value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="owner">Owner</option>
              <option value="admin">Admin</option>
              <option value="member">Member</option>
              <option value="viewer">Viewer</option>
            </Select>
          </div>
          <Button onClick={() => addMutation.mutate({ email, role })} disabled={addMutation.isPending}>
            Add
          </Button>
        </div>
      )}

      <div className="space-y-1">
        {members?.map((m) => (
          <div key={m.id} className="flex items-center justify-between py-1">
            <div className="flex items-center gap-2">
              <span className="text-sm">{m.user_name || m.user_email}</span>
              {m.user_email && <span className="text-xs text-[var(--color-muted-foreground)]">{m.user_email}</span>}
            </div>
            <div className="flex items-center gap-2">
              <Select
                value={m.role}
                onChange={(e) => updateRoleMutation.mutate({ memberId: m.id, role: e.target.value })}
                className="h-7 text-xs w-28"
              >
                <option value="owner">Owner</option>
                <option value="admin">Admin</option>
                <option value="member">Member</option>
                <option value="viewer">Viewer</option>
              </Select>
              <Badge variant={roleColors[m.role] || "outline"}>{m.role}</Badge>
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={() => { if (confirm("Remove this member?")) removeMutation.mutate(m.id); }}
              >
                <X className="size-3" />
              </Button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
