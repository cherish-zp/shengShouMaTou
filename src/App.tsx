import { lazy, Suspense } from "react";
import { HashRouter, Route, Routes } from "react-router-dom";

import { AppLayout } from "@/components/layout/app-layout";
import { ThemeProvider } from "@/components/theme-provider";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { UpdateBanner } from "@/components/update/update-banner";

// Route-level code splitting: each page ships as its own chunk.
const HomePage = lazy(() =>
  import("@/pages/home-page").then((m) => ({ default: m.HomePage })),
);
const ServersPage = lazy(() =>
  import("@/pages/servers-page").then((m) => ({ default: m.ServersPage })),
);
const SettingsPage = lazy(() =>
  import("@/pages/settings-page").then((m) => ({ default: m.SettingsPage })),
);
const HelpPage = lazy(() =>
  import("@/pages/help-page").then((m) => ({ default: m.HelpPage })),
);

function RouteFallback() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <div className="size-6 animate-spin rounded-full border-2 border-muted-foreground/30 border-t-foreground/70" />
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <TooltipProvider delayDuration={250}>
        <HashRouter>
          <Routes>
            <Route element={<AppLayout />}>
              <Route
                index
                element={
                  <Suspense fallback={<RouteFallback />}>
                    <HomePage />
                  </Suspense>
                }
              />
              <Route
                path="/servers"
                element={
                  <Suspense fallback={<RouteFallback />}>
                    <ServersPage />
                  </Suspense>
                }
              />
              <Route
                path="/help"
                element={
                  <Suspense fallback={<RouteFallback />}>
                    <HelpPage />
                  </Suspense>
                }
              />
              <Route
                path="/settings"
                element={
                  <Suspense fallback={<RouteFallback />}>
                    <SettingsPage />
                  </Suspense>
                }
              />
            </Route>
          </Routes>
          <UpdateBanner />
          <Toaster position="bottom-right" closeButton />
        </HashRouter>
      </TooltipProvider>
    </ThemeProvider>
  );
}
