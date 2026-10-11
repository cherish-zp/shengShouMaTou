// Subscribes to the "tunnel://log" event and buffers lines for one tunnel,
// seeding the buffer with the historical backlog via "get_tunnel_logs".

import { useCallback, useEffect, useState } from "react";
import type { UnlistenFn } from "@tauri-apps/api/event";

import { api, onTunnelLog } from "@/lib/tauri";
import type { TunnelLogEvent } from "@/types/tunnel";

const MAX_LINES = 500;

/** Composite dedup key — a line may arrive via both backlog and live event. */
function logKey(log: TunnelLogEvent): string {
  return `${log.ts}\u0000${log.line}`;
}

/**
 * Collects log lines for `tunnelId` while `enabled` is true.
 *
 * On enable it subscribes to live events first, then fetches the historical
 * backlog (oldest first). Live lines that arrived before the fetch resolved
 * are kept at the tail; backlog entries replace duplicates by composite key,
 * so no line is lost or shown twice. The buffer is capped and reset whenever
 * the target tunnel changes.
 *
 * Returns a `[logs, clearLogs]` tuple: `clearLogs` wipes the local panel
 * buffer (the backend ring buffer is cleared separately via
 * `api.clearTunnelLogs`, which the caller invokes first and then resets this
 * state so the panel immediately reflects the cleared buffer).
 */
export function useTunnelLogs(
  tunnelId: string | null,
  enabled: boolean,
): [TunnelLogEvent[], () => void] {
  const [logs, setLogs] = useState<TunnelLogEvent[]>([]);

  // Stable identity so a re-render of the consumer never re-triggers effects
  // that depend on the callback.
  const clearLogs = useCallback(() => setLogs([]), []);

  useEffect(() => {
    if (!enabled || !tunnelId) {
      setLogs([]);
      return;
    }
    setLogs([]);
    let alive = true;
    let unlisten: UnlistenFn | undefined;

    // Subscribe first so lines emitted while the backlog is in flight
    // are not lost; the merge below dedups the overlap.
    onTunnelLog((event) => {
      if (event.tunnelId !== tunnelId) return;
      setLogs((prev) => {
        const next = [...prev, event];
        return next.length > MAX_LINES ? next.slice(-MAX_LINES) : next;
      });
    })
      .then((fn) => {
        if (alive) unlisten = fn;
        else fn();
      })
      .catch(() => {
        // Event system unavailable — leave the buffer empty.
      });

    // Then pull the historical backlog (oldest first) and merge: keep the
    // backlog in order, append live lines whose key is not in the backlog.
    api
      .getTunnelLogs(tunnelId)
      .then((backlog) => {
        if (!alive) return; // tunnel switched or panel closed meanwhile
        setLogs((prev) => {
          const seen = new Set(backlog.map(logKey));
          const liveOnly = prev.filter((log) => !seen.has(logKey(log)));
          const merged = [...backlog, ...liveOnly];
          return merged.length > MAX_LINES ? merged.slice(-MAX_LINES) : merged;
        });
      })
      .catch((error) => {
        console.warn("get_tunnel_logs failed:", error);
      });

    return () => {
      alive = false;
      unlisten?.();
    };
  }, [tunnelId, enabled]);

  return [logs, clearLogs];
}
