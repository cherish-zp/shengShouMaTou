import { memo, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Activity,
  ArrowDown,
  ArrowRight,
  ArrowUp,
  CircleAlert,
  CloudOff,
  Copy,
  Ellipsis,
  LoaderCircle,
  Lock,
  Pencil,
  ScrollText,
  Shield,
  Stethoscope,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";

import { DiagnosisCard } from "@/components/tunnel/diagnosis-card";
import { QrPopover } from "@/components/tunnel/qr-popover";
import { StatsSparkline } from "@/components/tunnel/stats-sparkline";
import { StatusDot } from "@/components/status-dot";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/tauri";
import { cn, copyText, errorMessage, formatBytes, formatDateTime } from "@/lib/utils";
import { mergeState, useTunnelStats } from "@/store/tunnel-store";
import i18n from "@/i18n";
import type { Diagnosis, TunnelConfig, TunnelState } from "@/types/tunnel";

interface TunnelCardProps {
  tunnel: TunnelConfig;
  state?: TunnelState;
  onEdit: (tunnel: TunnelConfig) => void;
  onShowLogs: (tunnel: TunnelConfig) => void;
  onDelete: (tunnel: TunnelConfig) => void;
}

const ACTIVE_STATUSES = new Set(["running", "starting", "reconnecting"]);

function TunnelCardBase({ tunnel, state, onEdit, onShowLogs, onDelete }: TunnelCardProps) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [cfCleanupOpen, setCfCleanupOpen] = useState(false);
  const [cfCleaning, setCfCleaning] = useState(false);
  const [diagnosing, setDiagnosing] = useState(false);
  const [diagnosis, setDiagnosis] = useState<Diagnosis | null>(null);
  const [diagnosisOpen, setDiagnosisOpen] = useState(false);

  const status = state?.status ?? "stopped";
  const publicUrl = state?.publicUrl;
  const isActive = ACTIVE_STATUSES.has(status);
  const switching = busy || status === "starting" || status === "reconnecting";
  // Fixed-hostname tunnels cannot be edited in place: changing the setup
  // requires a fresh provision on the Cloudflare side.
  const isCfNamed = tunnel.backend === "cloudflareNamed";

  // Live traffic: the per-second stats event wins over the coarse state
  // snapshot so the numbers update every second while running.
  const { stats, history } = useTunnelStats(tunnel.id);
  const bytesIn = stats?.bytesIn ?? state?.bytesIn ?? 0;
  const bytesOut = stats?.bytesOut ?? state?.bytesOut ?? 0;
  const totalBytes = bytesIn + bytesOut;
  const showSparkline = status === "running" && history.length >= 2;

  const localTarget = `${tunnel.localHost}:${tunnel.localPort}`;

  async function handleToggle(nextOn: boolean) {
    setBusy(true);
    try {
      const nextState = nextOn
        ? await api.startTunnel(tunnel.id)
        : await api.stopTunnel(tunnel.id);
      mergeState(nextState);
    } catch (error) {
      toast.error(
        t(nextOn ? "card.startFailed" : "card.stopFailed"),
        { description: errorMessage(error) },
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleCfCleanup() {
    try {
      // Removes the remote tunnel + DNS records AND the local config.
      await api.cfDeprovision(tunnel.id, true);
      setCfCleanupOpen(false);
      toast.success(t("card.cleanupCfNamedDone", { name: tunnel.name }));
    } catch (e) {
      toast.error(t("card.cleanupCfNamedFailed"), {
        description: errorMessage(e),
      });
    } finally {
      setCfCleaning(false);
    }
  }

  async function handleDelete() {
    try {
      await api.deleteTunnel(tunnel.id);
      setConfirmOpen(false);
      toast.success(
        t("card.deleteSuccess", { name: tunnel.name }),
        // Deleting is local-only: the remote tunnel + DNS record stay in the
        // user's Cloudflare account until manual cleanup (or a later version).
        isCfNamed ? { description: t("card.deleteCfNamedHint") } : undefined,
      );
      onDelete(tunnel);
    } catch (error) {
      toast.error(t("card.deleteFailed"), { description: errorMessage(error) });
      setConfirmOpen(false);
    }
  }

  async function handleCopyUrl() {
    if (!publicUrl) return;
    const ok = await copyText(publicUrl);
    if (ok) toast.success(t("common.copied"));
    else toast.error(t("common.copyFailed"));
  }

  async function handleDiagnose() {
    setDiagnosing(true);
    try {
      const result = await api.diagnoseTunnel(tunnel.id);
      setDiagnosis(result);
      setDiagnosisOpen(true);
    } catch (error) {
      toast.error(t("diagnosis.actionFailed"), { description: errorMessage(error) });
    } finally {
      setDiagnosing(false);
    }
  }

  return (
    <Card
      className={cn(
        "gap-0 py-0 transition-shadow hover:shadow-md",
        status === "error" && "border-destructive/40",
      )}
    >
      <CardContent className="flex flex-col gap-4 p-5">
        {/* Header: status + name + badges + actions */}
        <div className="flex items-center gap-2.5">
          <StatusDot status={status} className="mr-0.5" />
          <h3 className="min-w-0 truncate text-[15px] font-medium">
            {tunnel.name}
          </h3>
          <Badge variant="secondary" className="font-mono text-[11px]">
            {tunnel.tunnelType.toUpperCase()}
          </Badge>
          <Badge variant="outline" className="text-[11px] text-muted-foreground">
            {tunnel.backend === "cloudflare"
              ? t("card.backendCloudflare")
              : tunnel.backend === "cloudflareNamed"
                ? t("card.backendCloudflareNamed")
                : tunnel.backend === "bore"
                  ? t("card.backendBore")
                  : t("card.backendFrp")}
          </Badge>
          {tunnel.autoStart ? (
            <Badge
              variant="outline"
              className="text-[11px] text-muted-foreground"
            >
              {t("card.autoStart")}
            </Badge>
          ) : null}

          {/* Access control markers */}
          {tunnel.auth ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="flex shrink-0 items-center">
                  <Lock className="size-3.5 text-muted-foreground" />
                </span>
              </TooltipTrigger>
              <TooltipContent side="top">
                {t("card.authTooltip", { username: tunnel.auth.username })}
              </TooltipContent>
            </Tooltip>
          ) : null}
          {tunnel.ipAllowlist && tunnel.ipAllowlist.length > 0 ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <Badge
                  variant="outline"
                  className="gap-1 text-[11px] text-muted-foreground"
                >
                  <Shield className="size-3" />
                  {tunnel.ipAllowlist.length}
                </Badge>
              </TooltipTrigger>
              <TooltipContent side="top">
                {t("card.allowlistTooltip", { n: tunnel.ipAllowlist.length })}
              </TooltipContent>
            </Tooltip>
          ) : null}

          <div className="ml-auto flex items-center gap-2">
            <Switch
              checked={isActive}
              disabled={switching}
              onCheckedChange={handleToggle}
              aria-label={isActive ? t("card.stop") : t("card.start")}
            />
            <Button
              variant="ghost"
              size="icon-sm"
              className="text-muted-foreground hover:text-foreground"
              onClick={() => onShowLogs(tunnel)}
              aria-label={t("card.logs")}
            >
              <ScrollText className="size-4" />
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  className="text-muted-foreground hover:text-foreground"
                  aria-label={t("card.editTunnel")}
                >
                  <Ellipsis className="size-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                <DropdownMenuItem onSelect={() => onEdit(tunnel)}>
                  <Pencil />
                  {t("card.editTunnel")}
                </DropdownMenuItem>
                {isCfNamed && (
                  <DropdownMenuItem onSelect={() => setCfCleanupOpen(true)}>
                    <CloudOff />
                    {t("card.cleanupCfNamed")}
                  </DropdownMenuItem>
                )}
                <DropdownMenuItem
                  variant="destructive"
                  onSelect={() => setConfirmOpen(true)}
                >
                  <Trash2 />
                  {t("card.deleteTunnel")}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>

        {/* Address row */}
        <div className="flex items-center gap-2 rounded-lg border bg-muted/40 px-3 py-2 font-mono text-[13px]">
          <span className="shrink-0 text-muted-foreground">{localTarget}</span>
          <ArrowRight className="size-3.5 shrink-0 text-muted-foreground/70" />
          {publicUrl ? (
            <span className="min-w-0 flex-1 truncate">{publicUrl}</span>
          ) : (
            <span className="min-w-0 flex-1 truncate text-muted-foreground/70 italic">
              {status === "starting" || status === "reconnecting"
                ? t("card.waitingUrl")
                : t("card.noUrl")}
            </span>
          )}
          <div className="flex shrink-0 items-center gap-0.5">
            <Button
              variant="ghost"
              size="icon-xs"
              disabled={!publicUrl}
              className="text-muted-foreground hover:text-foreground"
              onClick={handleCopyUrl}
              aria-label={t("common.copy")}
            >
              <Copy className="size-3.5" />
            </Button>
            <QrPopover url={publicUrl ?? null} disabled={!publicUrl} />
          </div>
        </div>

        {/* Stats row */}
        <div className="flex items-center gap-6 text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1.5">
            <span className="text-foreground/60">{t("card.traffic")}</span>
            {totalBytes > 0 ? (
              <span className="inline-flex items-center gap-1.5 font-mono">
                <ArrowDown className="size-3 text-emerald-600 dark:text-success" />
                {formatBytes(bytesIn)}
                <ArrowUp className="size-3 text-foreground/60" />
                {formatBytes(bytesOut)}
              </span>
            ) : (
              <span className="font-mono">{t("common.dash")}</span>
            )}
          </span>
          {stats && stats.connActive > 0 ? (
            <span className="inline-flex items-center gap-1.5">
              <Activity className="size-3 text-foreground/60" />
              <span className="font-mono text-foreground/80">
                {stats.connActive}
              </span>
              <span>{t("card.connActive")}</span>
            </span>
          ) : null}
          <span className="inline-flex items-center gap-1.5">
            <span className="text-foreground/60">{t("card.uptime")}</span>
            {state?.startedAt ? (
              <span className="font-mono">
                {formatDateTime(state.startedAt, i18n.language)}
              </span>
            ) : (
              <span>{t("card.notStarted")}</span>
            )}
          </span>
          {showSparkline ? (
            <StatsSparkline history={history} className="ml-auto" />
          ) : null}
        </div>

        {/* Error summary */}
        {status === "error" && state?.error ? (
          <button
            type="button"
            onClick={() => onShowLogs(tunnel)}
            className="flex w-full items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-left text-[13px] text-destructive transition-colors hover:bg-destructive/15"
          >
            <CircleAlert className="size-4 shrink-0" />
            <span className="min-w-0 flex-1 truncate">{state.error}</span>
            <span className="shrink-0 font-medium underline underline-offset-2">
              {t("card.viewLogs")}
            </span>
          </button>
        ) : null}

        {/* Diagnosis (error state only) */}
        {status === "error" ? (
          <>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={diagnosing}
                onClick={() => void handleDiagnose()}
              >
                {diagnosing ? (
                  <>
                    <LoaderCircle className="size-3.5 animate-spin" />
                    {t("diagnosis.diagnosing")}
                  </>
                ) : (
                  <>
                    <Stethoscope className="size-3.5" />
                    {diagnosis && diagnosisOpen
                      ? t("diagnosis.rerun")
                      : t("diagnosis.action")}
                  </>
                )}
              </Button>
              {diagnosis && diagnosisOpen ? (
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-muted-foreground"
                  onClick={() => setDiagnosisOpen(false)}
                >
                  {t("diagnosis.collapse")}
                </Button>
              ) : null}
            </div>
            {diagnosis && diagnosisOpen ? (
              <DiagnosisCard diagnosis={diagnosis} />
            ) : null}
          </>
        ) : null}
      </CardContent>

      {/* Delete confirmation */}
      <Dialog open={cfCleanupOpen} onOpenChange={setCfCleanupOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>{t("card.cleanupCfNamedTitle")}</DialogTitle>
            <DialogDescription>
              {t("card.cleanupCfNamedDescription", { name: tunnel.name })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCfCleanupOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button variant="destructive" disabled={cfCleaning} onClick={handleCfCleanup}>
              {cfCleaning ? <LoaderCircle className="size-4 animate-spin" /> : null}
              {t("card.cleanupCfNamedConfirm")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>{t("card.deleteTitle")}</DialogTitle>
            <DialogDescription>
              {t("card.deleteDescription", { name: tunnel.name })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button variant="destructive" onClick={handleDelete}>
              {t("common.delete")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

// Props are stable (memoized handlers + store data), so memo skips
// re-rendering every card when a single tunnel's state ticks.
export const TunnelCard = memo(TunnelCardBase);
