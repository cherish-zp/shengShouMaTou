import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Database,
  HardDrive,
  LoaderCircle,
  ScrollText,
  Sigma,
  Trash2,
  Wrench,
} from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/tauri";
import { cn, errorMessage } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { StorageUsage } from "@/types/storage";

/** 字节数 → 人类可读单位（1024 进制，B/KB/MB/GB，保留 1 位小数）。 */
function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 1024) {
    return `${Math.max(0, Math.round(bytes))} B`;
  }
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = "B";
  for (const next of units) {
    unit = next;
    value /= 1024;
    if (value < 1024) break;
  }
  return `${value.toFixed(1)} ${unit}`;
}

interface UsageRow {
  icon: typeof Database;
  label: string;
  hint?: string;
  value: string;
  strong?: boolean;
}

/** 设置页「存储占用」卡片：日志缓冲 / 缓存 / 应用数据 / 合计，附清理操作。 */
export function StorageSection() {
  const { t } = useTranslation();
  const [usage, setUsage] = useState<StorageUsage | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [clearingLogs, setClearingLogs] = useState(false);

  const load = useCallback(async () => {
    try {
      setUsage(await api.getStorageUsage());
    } catch {
      // 统计读取失败不打断页面：保留占位「—」，用户可重进设置页重试
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  /** 清理缓存（引擎二进制与隧道配置）：先确认，成功后提示释放大小并刷新统计。 */
  async function handleClearCache() {
    setClearing(true);
    try {
      const freed = await api.clearCache();
      setConfirmOpen(false);
      toast.success(t("settings.storage.cacheCleared", { size: formatBytes(freed) }));
      await load();
    } catch (error) {
      // 隧道运行中后端会拒绝清理（中文错误信息），直接展示
      toast.error(t("settings.storage.clearFailed"), {
        description: errorMessage(error),
      });
    } finally {
      setClearing(false);
    }
  }

  /** 清空全部内存日志缓冲：成功后提示清除行数并刷新统计。 */
  async function handleClearLogs() {
    setClearingLogs(true);
    try {
      const removed = await api.clearAllTunnelLogs();
      toast.success(t("settings.storage.logsCleared", { lines: removed.toLocaleString() }));
      await load();
    } catch (error) {
      toast.error(t("settings.storage.clearLogsFailed"), {
        description: errorMessage(error),
      });
    } finally {
      setClearingLogs(false);
    }
  }

  const rows: UsageRow[] = [
    {
      icon: ScrollText,
      label: t("settings.storage.logs"),
      hint: t("settings.storage.logsHint"),
      value: usage
        ? t("settings.storage.logLinesValue", {
            lines: usage.logLines.toLocaleString(),
            size: formatBytes(usage.logsBytes),
          })
        : "—",
    },
    {
      icon: Wrench,
      label: t("settings.storage.cache"),
      hint: t("settings.storage.cacheHint"),
      value: usage ? formatBytes(usage.cacheBytes) : "—",
    },
    {
      icon: Database,
      label: t("settings.storage.data"),
      hint: t("settings.storage.dataHint"),
      value: usage ? formatBytes(usage.dataBytes) : "—",
    },
    {
      icon: Sigma,
      label: t("settings.storage.total"),
      value: usage ? formatBytes(usage.totalBytes) : "—",
      strong: true,
    },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t("settings.storage.title")}</CardTitle>
        <CardDescription>{t("settings.storage.description")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-col">
          {rows.map(({ icon: Icon, label, hint, value, strong }, index) => (
            <div
              key={label}
              className={cn(
                "flex items-center gap-3.5 py-2.5",
                index > 0 && "border-t border-border/60",
              )}
            >
              <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-secondary text-secondary-foreground">
                <Icon className="size-4.5" strokeWidth={1.8} />
              </span>
              <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                <p
                  className={cn(
                    "text-sm leading-none",
                    strong ? "font-semibold" : "font-medium",
                  )}
                >
                  {label}
                </p>
                {hint ? (
                  <p className="truncate text-xs text-muted-foreground">{hint}</p>
                ) : null}
              </div>
              <span
                className={cn(
                  "shrink-0 font-mono text-[13px]",
                  strong && "font-semibold",
                )}
              >
                {value}
              </span>
            </div>
          ))}
        </div>
        <div className="flex justify-end gap-2">
          {/* 次级操作：弱化样式 */}
          <Button
            variant="outline"
            size="sm"
            disabled={clearingLogs || clearing}
            onClick={() => void handleClearLogs()}
          >
            {clearingLogs ? (
              <LoaderCircle className="size-3.5 animate-spin" />
            ) : (
              <Trash2 className="size-3.5" />
            )}
            {t("settings.storage.clearLogs")}
          </Button>
          <Button size="sm" disabled={clearing} onClick={() => setConfirmOpen(true)}>
            {clearing ? (
              <LoaderCircle className="size-3.5 animate-spin" />
            ) : (
              <HardDrive className="size-3.5" />
            )}
            {t("settings.storage.clearCache")}
          </Button>
        </div>
      </CardContent>

      {/* 清理缓存确认框（沿用项目 Dialog 确认模式） */}
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>{t("settings.storage.clearCacheTitle")}</DialogTitle>
            <DialogDescription>
              {t("settings.storage.clearCacheDescription")}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button disabled={clearing} onClick={() => void handleClearCache()}>
              {clearing ? <LoaderCircle className="size-4 animate-spin" /> : null}
              {t("settings.storage.clearCacheConfirm")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
