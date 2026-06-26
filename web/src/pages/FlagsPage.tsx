import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Plus, Flag as FlagIcon } from "lucide-react";

export function FlagsPage({ onNavigate }: { onNavigate: (path: string) => void }) {
  const { data: flags, isLoading } = useQuery({
    queryKey: ["flags"],
    queryFn: api.listFlags,
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Feature Flags</h1>
        <Button onClick={() => onNavigate("/flags/new")}>
          <Plus className="size-4" />
          New Flag
        </Button>
      </div>

      {isLoading && <p className="text-[var(--color-muted-foreground)]">Loading...</p>}

      {flags && flags.length === 0 && (
        <Card>
          <CardContent className="py-12 text-center">
            <FlagIcon className="size-12 mx-auto text-[var(--color-muted-foreground)] mb-2" />
            <p className="text-[var(--color-muted-foreground)]">No flags yet. Create one to get started.</p>
          </CardContent>
        </Card>
      )}

      <div className="space-y-2">
        {flags?.map((flag) => (
          <Card
            key={flag.id}
            className="cursor-pointer hover:border-[var(--color-ring)] transition-colors"
            onClick={() => onNavigate(`/flags/${flag.id}`)}
          >
            <CardContent className="flex items-center justify-between py-4">
              <div className="flex items-center gap-3">
                <div className={`w-2 h-2 rounded-full ${flag.enabled ? "bg-green-500" : "bg-gray-500"}`} />
                <div>
                  <p className="font-medium">{flag.key}</p>
                  <p className="text-xs text-[var(--color-muted-foreground)]">{flag.name}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="outline">{flag.type}</Badge>
                <Badge variant={flag.enabled ? "default" : "secondary"}>
                  {flag.enabled ? "Enabled" : "Disabled"}
                </Badge>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
