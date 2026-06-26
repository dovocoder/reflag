import React from "react";
import { cn } from "@/lib/utils";

type BadgeVariant = "default" | "secondary" | "destructive" | "outline";

const variants: Record<BadgeVariant, string> = {
  default: "bg-[var(--color-primary)] text-[var(--color-primary-foreground)]",
  secondary: "bg-[var(--color-secondary)] text-[var(--color-secondary-foreground)]",
  destructive: "bg-[var(--color-destructive)] text-[var(--color-destructive-foreground)]",
  outline: "border border-[var(--color-border)] text-[var(--color-foreground)]",
};

export function Badge({ variant = "default", className, ...props }: React.HTMLAttributes<HTMLSpanElement> & { variant?: BadgeVariant }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium",
        variants[variant],
        className
      )}
      {...props}
    />
  );
}
