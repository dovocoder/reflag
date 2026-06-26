export function IndexPage(_props: { onNavigate: (path: string) => void }) {
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>
      <p className="text-[var(--color-muted-foreground)]">Welcome to Reflag. Select a section from the sidebar.</p>
    </div>
  );
}
