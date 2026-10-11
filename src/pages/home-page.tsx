import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { FileUp, Plus } from "lucide-react";

import { AddTunnelDialog } from "@/components/tunnel/add-tunnel-dialog";
import { ImportDialog } from "@/components/tunnel/import-dialog";
import { TunnelCard } from "@/components/tunnel/tunnel-card";
import { LogSheet } from "@/components/tunnel/log-sheet";
import { BridgeIllustration } from "@/components/pier-logo";
import { Button } from "@/components/ui/button";
import {
  consumeNewTunnelIntent,
  useTunnelStore,
  removeConfig,
} from "@/store/tunnel-store";
import type { TunnelConfig } from "@/types/tunnel";

export function HomePage() {
  const { t } = useTranslation();
  const { configs, states, initialized } = useTunnelStore();

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editTunnel, setEditTunnel] = useState<TunnelConfig | null>(null);
  const [logTunnel, setLogTunnel] = useState<TunnelConfig | null>(null);
  const [logOpen, setLogOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);

  // The Settings page can jump straight into the New Tunnel wizard
  // (Cloudflare fixed-hostname entry point).
  useEffect(() => {
    if (consumeNewTunnelIntent()) {
      setEditTunnel(null);
      setDialogOpen(true);
    }
  }, []);

  // Handlers passed to TunnelCard are memoized (with state-setter-only deps)
  // so React.memo on TunnelCard can skip re-renders of untouched cards.
  const openCreate = () => {
    setEditTunnel(null);
    setDialogOpen(true);
  };

  const openEdit = useCallback((tunnel: TunnelConfig) => {
    setEditTunnel(tunnel);
    setDialogOpen(true);
  }, []);

  const openLogs = useCallback((tunnel: TunnelConfig) => {
    setLogTunnel(tunnel);
    setLogOpen(true);
  }, []);

  // removeConfig is a module-level store function (stable reference).
  const handleDelete = useCallback((deleted: TunnelConfig) => {
    removeConfig(deleted.id);
  }, []);

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col px-8 py-10">
      {/* Header */}
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">
            {t("home.title")}
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {t("home.subtitle")}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Button variant="outline" onClick={() => setImportOpen(true)}>
            <FileUp className="size-4" />
            {t("import.button")}
          </Button>
          <Button onClick={openCreate}>
            <Plus className="size-4" />
            {t("home.newTunnel")}
          </Button>
        </div>
      </header>

      {/* Tunnel list */}
      {configs.length > 0 ? (
        <section className="mt-8 flex flex-col gap-4">
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {t("home.tunnelCount", { n: configs.length })}
          </p>
          {configs.map((tunnel) => (
            <TunnelCard
              key={tunnel.id}
              tunnel={tunnel}
              state={states[tunnel.id]}
              onEdit={openEdit}
              onShowLogs={openLogs}
              onDelete={handleDelete}
            />
          ))}
        </section>
      ) : (
        <EmptyState onCreate={openCreate} visible={initialized} />
      )}

      <AddTunnelDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        editTunnel={editTunnel}
      />
      <ImportDialog
        open={importOpen}
        onOpenChange={setImportOpen}
        onImported={() => undefined}
      />
      <LogSheet
        tunnel={logTunnel}
        state={logTunnel ? states[logTunnel.id] : undefined}
        open={logOpen}
        onOpenChange={setLogOpen}
      />
    </div>
  );
}

function EmptyState({
  onCreate,
  visible,
}: {
  onCreate: () => void;
  visible: boolean;
}) {
  const { t } = useTranslation();
  return (
    <section
      className={
        "mt-16 flex flex-col items-center pb-10 text-center transition-opacity duration-300 " +
        (visible ? "opacity-100" : "opacity-0")
      }
    >
      <BridgeIllustration className="w-64 max-w-full" />
      <h2 className="mt-8 text-base font-medium">{t("home.emptyTitle")}</h2>
      <p className="mt-2 max-w-sm text-sm leading-relaxed text-muted-foreground">
        {t("home.emptyDescription")}
      </p>
      <Button onClick={onCreate} className="mt-6">
        <Plus className="size-4" />
        {t("home.emptyCta")}
      </Button>
    </section>
  );
}
