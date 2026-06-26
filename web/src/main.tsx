import React, { StrictMode, useState, useEffect, useCallback } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { IndexPage } from "./pages/IndexPage";
import { FlagsPage } from "./pages/FlagsPage";
import { FlagDetailPage } from "./pages/FlagDetailPage";
import { EnvironmentsPage } from "./pages/EnvironmentsPage";
import { SegmentsPage } from "./pages/SegmentsPage";
import { ApiKeysPage } from "./pages/ApiKeysPage";
import { AuditPage } from "./pages/AuditPage";
import { LoginPage } from "./pages/LoginPage";
import { Layout } from "./components/Layout";
import { isAuthenticated, clearToken } from "./lib/api";
import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 30_000, retry: 1 },
  },
});

type Route =
  | { page: "login" }
  | { page: "flags" }
  | { page: "flag-detail"; id: string }
  | { page: "environments" }
  | { page: "segments" }
  | { page: "api-keys" }
  | { page: "audit" };

function parseRoute(): Route {
  const path = window.location.pathname;
  const authenticated = isAuthenticated();

  if (path === "/login" || !authenticated) {
    return { page: "login" };
  }
  if (path === "/" || path === "/flags") return { page: "flags" };
  if (path.startsWith("/flags/")) {
    const id = path.split("/")[2];
    return { page: "flag-detail", id };
  }
  if (path === "/environments") return { page: "environments" };
  if (path === "/segments") return { page: "segments" };
  if (path === "/api-keys") return { page: "api-keys" };
  if (path === "/audit") return { page: "audit" };
  return { page: "flags" };
}

export function navigate(path: string) {
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function App() {
  const [route, setRoute] = useState<Route>(parseRoute);

  useEffect(() => {
    const handler = () => setRoute(parseRoute());
    window.addEventListener("popstate", handler);
    return () => window.removeEventListener("popstate", handler);
  }, []);

  const handleNavigate = useCallback((path: string) => navigate(path), []);

  if (route.page === "login") {
    return (
      <StrictMode>
        <QueryClientProvider client={queryClient}>
          <LoginPage onLogin={() => handleNavigate("/flags")} />
        </QueryClientProvider>
      </StrictMode>
    );
  }

  let pageContent: React.ReactNode;
  switch (route.page) {
    case "flags":
      pageContent = <FlagsPage onNavigate={handleNavigate} />;
      break;
    case "flag-detail":
      pageContent = <FlagDetailPage id={route.id} onNavigate={handleNavigate} />;
      break;
    case "environments":
      pageContent = <EnvironmentsPage />;
      break;
    case "segments":
      pageContent = <SegmentsPage />;
      break;
    case "api-keys":
      pageContent = <ApiKeysPage />;
      break;
    case "audit":
      pageContent = <AuditPage />;
      break;
    default:
      pageContent = <IndexPage onNavigate={handleNavigate} />;
  }

  return (
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <Layout
          current={route.page}
          onNavigate={handleNavigate}
          onLogout={() => {
            clearToken();
            handleNavigate("/login");
          }}
        >
          {pageContent}
        </Layout>
      </QueryClientProvider>
    </StrictMode>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
