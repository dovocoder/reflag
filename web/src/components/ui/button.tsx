import React from "react";
import { cn } from "@/lib/utils";

type ButtonVariant = "default" | "outline" | "secondary" | "ghost" | "destructive";
type ButtonSize = "default" | "sm" | "lg" | "xs" | "icon" | "icon-sm" | "icon-lg";

const variantClasses: Record<ButtonVariant, string> = {
  default: "bg-[var(--color-primary)] text-[var(--color-primary-foreground)] hover:opacity-90",
  outline: "border border-[var(--color-border)] bg-transparent hover:bg-[var(--color-accent)]",
  secondary: "bg-[var(--color-secondary)] text-[var(--color-secondary-foreground)] hover:opacity-80",
  ghost: "hover:bg-[var(--color-accent)] hover:text-[var(--color-accent-foreground)]",
  destructive: "bg-[var(--color-destructive)] text-[var(--color-destructive-foreground)] hover:opacity-90",
};

const sizeClasses: Record<ButtonSize, string> = {
  default: "h-8 px-4 py-2 text-sm",
  sm: "h-7 px-3 text-xs",
  lg: "h-9 px-6 text-base",
  xs: "h-6 px-2 text-xs",
  icon: "h-8 w-8",
  "icon-sm": "h-7 w-7",
  "icon-lg": "h-9 w-9",
};

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

export function Button({ variant = "default", size = "default", className, ...props }: ButtonProps) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-md font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-ring)] disabled:pointer-events-none disabled:opacity-50",
        variantClasses[variant],
        sizeClasses[size],
        className
      )}
      {...props}
    />
  );
}
