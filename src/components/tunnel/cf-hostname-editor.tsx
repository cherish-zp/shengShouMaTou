import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Check, Eye, EyeOff, Globe, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/tauri";
import { errorMessage } from "@/lib/utils";
import type { CfZone, TunnelConfig } from "@/types/tunnel";

/**
 * Editable fixed-hostname section for a provisioned CloudflareNamed tunnel:
 *   - domain dropdown + subdomain input + "update" action (re-points the
 *     remote ingress and CNAME; tunnel object/token unchanged),
 *   - eye-reveal for the stored API token.
 */
export function CfHostnameEditor({
  tunnel,
  onUpdated,
}: {
  tunnel: TunnelConfig;
  onUpdated: (saved: TunnelConfig) => void;
}) {
  const { t } = useTranslation();
  const [zones, setZones] = useState<CfZone[]>([]);
  const [zonesError, setZonesError] = useState<string | null>(null);
  const [zoneId, setZoneId] = useState("");
  const [subdomain, setSubdomain] = useState(
    (tunnel.cfHostname || "").split(".")[0] || "",
  );
  const [saving, setSaving] = useState(false);
  const [savedFlash, setSavedFlash] = useState(false);
  const [showToken, setShowToken] = useState(false);
  const [apiToken, setApiToken] = useState<string | null>(null);
  const [tokenLoading, setTokenLoading] = useState(false);

  const currentHostname = tunnel.cfHostname || "";

  useEffect(() => {
    api
      .cfListZonesStored(tunnel.id)
      .then((zs) => {
        setZones(zs);
        // preselect the zone that owns the current hostname
        const current = (tunnel.cfHostname || "").split(".").slice(1).join(".");
        const match = zs.find((z) => current.endsWith(z.name));
        if (match) setZoneId(match.id);
      })
      .catch((e) => setZonesError(errorMessage(e)));
  }, [tunnel.id, tunnel.cfHostname]);

  const selectedZone = zones.find((z) => z.id === zoneId);
  const newHostname =
    selectedZone && subdomain ? `${subdomain}.${selectedZone.name}` : "";
  const changed = Boolean(selectedZone && subdomain && newHostname !== currentHostname);

  const revealToken = async () => {
    if (apiToken !== null) {
      setShowToken((v) => !v);
      return;
    }
    setTokenLoading(true);
    try {
      setApiToken(await api.cfGetApiToken(tunnel.id));
      setShowToken(true);
    } catch (e) {
      toastError(errorMessage(e));
    } finally {
      setTokenLoading(false);
    }
  };

  const toastError = (msg: string) => toast.error(msg);

  const save = async () => {
    if (!changed) return;
    setSaving(true);
    try {
      const saved = await api.cfUpdateHostname({
        id: tunnel.id,
        zoneId,
        subdomain,
      });
      onUpdated(saved);
      setSavedFlash(true);
      setTimeout(() => setSavedFlash(false), 2500);
    } catch (e) {
      toastError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex flex-col gap-3 rounded-lg border bg-muted/20 p-3">
      {/* fixed hostname (current or pending) */}
      <div className="flex items-center gap-2 text-sm">
        <Globe className="size-4 shrink-0 text-muted-foreground" />
        <span className="font-mono text-[13px] break-all">
          {savedFlash && newHostname ? newHostname : currentHostname}
        </span>
        {savedFlash && <Check className="size-4 text-success" />}
        {!savedFlash && changed && (
          <span className="text-xs text-muted-foreground">
            → <span className="font-mono">{newHostname}</span>
          </span>
        )}
      </div>

      {/* zone + subdomain */}
      <div className="grid grid-cols-1 gap-2">
        <select
          value={zoneId}
          onChange={(e) => setZoneId(e.target.value)}
          className="h-9 rounded-md border bg-background px-2 text-sm"
          aria-label={t("help.permZone")}
        >
          {zonesError && <option value="">{zonesError}</option>}
          {!zonesError && zones.length === 0 && <option value="">…</option>}
          {zones.map((z) => (
            <option key={z.id} value={z.id}>
              {z.name}
            </option>
          ))}
        </select>
        <Input
          value={subdomain}
          onChange={(e) =>
            setSubdomain(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))
          }
          placeholder="pier"
          className="font-mono"
        />
      </div>

      <Button size="sm" disabled={!changed || saving} onClick={save}>
        {saving ? <Loader2 className="size-4 animate-spin" /> : null}
        {t("help.editUpdateHostname")}
      </Button>

      {/* stored API token eye-reveal */}
      <div className="flex items-center gap-2 border-t pt-2">
        <span className="text-xs text-muted-foreground">{t("help.storedToken")}</span>
        <Button
          size="icon"
          variant="ghost"
          className="size-7"
          onClick={revealToken}
          aria-label={t("help.revealToken")}
        >
          {showToken ? (
            <EyeOff className="size-3.5" />
          ) : (
            <Eye className="size-3.5" />
          )}
        </Button>
        {showToken && (
          <span className="font-mono text-xs break-all">
            {tokenLoading ? "…" : apiToken}
          </span>
        )}
      </div>
    </div>
  );
}
