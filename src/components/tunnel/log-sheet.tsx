import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { LoaderCircle, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { StatusDot } from "@/components/status-dot";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { useTunnelLogs } from "@/hooks/use-tunnel-logs";
import { api } from "@/lib/tauri";
import { cn, errorMessage } from "@/lib/utils";
import type { TunnelConfig, TunnelLogEvent, TunnelState } from "@/types/tunnel";

interface LogSheetProps {
  tunnel: TunnelConfig | null;
  state?: TunnelState;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const LEVEL_CLASSES: Record<TunnelLogEvent["level"], string> = {
  info: "text-foreground/90",
  warn: "text-warning",
  error: "text-destructive",
};

export function LogSheet({ tunnel, state, open, onOpenChange }: LogSheetProps) {
  const { t } = useTranslation();
  const [logs, clearLogs] = useTunnelLogs(tunnel?.id ?? null, open && tunnel !== null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const stickToBottomRef = useRef(true);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [clearing, setClearing] = useState(false);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el || !stickToBottomRef.current) return;
    el.scrollTop = el.scrollHeight;
  }, [logs]);

  function handleScroll() {
    const el = scrollRef.current;
    if (!el) return;
    const distance = el.scrollHeight - el.scrollTop - el.clientHeight;
    stickToBottomRef.current = distance < 48;
  }

  /** 确认后清空后端环形缓冲 + 本地面板缓冲（两者互不阻塞隧道运行）。 */
  async function handleClearLogs() {
    if (!tunnel) return;
    setClearing(true);
    try {
      await api.clearTunnelLogs(tunnel.id);
      clearLogs();
      setConfirmOpen(false);
      toast.success(t("logs.cleared"));
    } catch (error) {
      toast.error(t("logs.clearFailed"), { description: errorMessage(error) });
    } finally {
      setClearing(false);
    }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="flex w-full flex-col gap-0 sm:max-w-xl">
        <SheetHeader className="border-b py-4">
          <div className="flex items-center">
            <SheetTitle className="flex items-center gap-2.5 text-base">
              {tunnel ? (
                <>
                  <StatusDot status={state?.status ?? "stopped"} />
                  <span className="truncate">{tunnel.name}</span>
                  <span className="font-normal text-muted-foreground">
                    {t("logs.title")}
                  </span>
                </>
              ) : (
                t("logs.title")
              )}
            </SheetTitle>
            {tunnel ? (
              <Button
                variant="ghost"
                size="icon-sm"
                className="ml-auto mr-8 text-muted-foreground hover:text-foreground"
                onClick={() => setConfirmOpen(true)}
                disabled={clearing || logs.length === 0}
                aria-label={t("logs.clear")}
              >
                <Trash2 className="size-4" />
              </Button>
            ) : null}
          </div>
          <SheetDescription className="sr-only">
            {t("logs.title")}
          </SheetDescription>
        </SheetHeader>

        <div
          ref={scrollRef}
          onScroll={handleScroll}
          className="pier-scroll min-h-0 flex-1 overflow-y-auto bg-muted/30 px-4 py-3 font-mono text-xs leading-relaxed"
        >
          {logs.length === 0 ? (
            <p className="mt-6 text-center font-sans text-sm text-muted-foreground">
              {t("logs.empty")}
            </p>
          ) : (
            <div className="flex flex-col gap-0.5">
              {logs.map((log, index) => (
                <div key={`${log.ts}-${index}`} className="flex gap-2.5">
                  <span className="shrink-0 text-muted-foreground/60">
                    {log.ts.slice(11, 19)}
                  </span>
                  <span
                    className={cn(
                      "min-w-0 break-all",
                      LEVEL_CLASSES[log.level] ?? LEVEL_CLASSES.info,
                    )}
                  >
                    {log.line}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* 清理确认：跟随项目现有的 Dialog 确认交互（同 tunnel-card 删除确认）。 */}
        <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
          <DialogContent className="max-w-sm">
            <DialogHeader>
              <DialogTitle>{t("logs.clearConfirmTitle")}</DialogTitle>
              <DialogDescription>{t("logs.clearConfirmBody")}</DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setConfirmOpen(false)}>
                {t("common.cancel")}
              </Button>
              <Button variant="destructive" disabled={clearing} onClick={handleClearLogs}>
                {clearing ? <LoaderCircle className="size-4 animate-spin" /> : null}
                {t("logs.clear")}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </SheetContent>
    </Sheet>
  );
}
