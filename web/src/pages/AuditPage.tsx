import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const actionColors: Record<string, string> = {
  CREATE: "default",
  UPDATE: "secondary",
  DELETE: "destructive",
  REVOKE: "destructive",
  LOGIN: "outline",
};

export function AuditPage() {
  const { data: entries, isLoading } = useQuery({
    queryKey: ["audit"],
    queryFn: () => api.listAudit(100, 0),
  });

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Audit Log</h1>

      {isLoading && <p className="text-[var(--color-muted-foreground)]">Loading...</p>}

      <div className="space-y-2">
        {entries?.map((entry) => (
          <Card key={entry.id}>
            <CardContent className="flex items-center justify-between py-3">
              <div className="flex items-center gap-3">
                <Badge variant={(actionColors[entry.action] as "default" | "secondary" | "destructive" | "outline") || "outline"}>
                  {entry.action}
                </Badge>
                <div>
                  <p className="text-sm font-medium">
                    {entry.resource}
                    {entry.details && <span className="text-[var(--color-muted-foreground)]"> — {entry.details}</span>}
                  </p>
                  <p className="text-xs text-[var(--color-muted-foreground)]">
                    by {entry.actor} • {new Date(entry.timestamp).toLocaleString()}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {entries && entries.length === 0 && (
        <Card>
          <CardContent className="py-8 text-center text-[var(--color-muted-foreground)]">
            No audit entries yet.
          </CardContent>
        </Card>
      )}
    </div>
  );
}
