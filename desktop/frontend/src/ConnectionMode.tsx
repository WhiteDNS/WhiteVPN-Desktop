// One plain choice of how to connect, for people who do not know what a chain,
// an engine or a subscription is. Each option sets the backend the same way the
// detailed pages do, and the VPN page then shows only the rows that option uses.
import { Check, Cloud, Layers, Server, ShieldCheck, Waypoints } from "lucide-react";
import { useState } from "react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import { isolateLatin } from "./bidi";
import type { EngineProfile } from "./engine-profiles";
import type { EngineSelection } from "./EngineProfilesSection";
import type { StringKey, TranslateFn } from "./i18n";
import type { AppState } from "./types";
import { backend } from "./wails";

// A title with no Persian in it, like "WARP (Cloudflare)", is isolated whole:
// word by word, its brackets would flip around it in a right-to-left page.
const latinOnly = (text: string) => !/[؀-ۿ]/.test(text);

export type ConnectionMode = "servers" | "chain" | "warp" | "psiphon" | "tor";

const allListsID = "all";

export function isWarpSubscription(subscription: { inline?: boolean } | undefined): boolean {
  return Boolean(subscription?.inline);
}

export function connectionMode(state: AppState, engines: EngineSelection): ConnectionMode {
  if (engines.selectedId) {
    const kind = engines.profiles.find((profile) => profile.id === engines.selectedId)?.kind;
    if (kind === "psiphon" || kind === "tor") {
      return kind;
    }
  }
  if (state.whiteVpn.chain && state.whiteVpn.chain.exit.mode !== "off") {
    return "chain";
  }
  const selected = state.v2raySubscriptions.find((entry) => entry.id === state.selectedSubscriptionId);
  return isWarpSubscription(selected) ? "warp" : "servers";
}

const options: { mode: ConnectionMode; icon: typeof Server; title: StringKey; detail: StringKey }[] = [
  { mode: "servers", icon: Server, title: "mode.servers", detail: "mode.servers.detail" },
  { mode: "chain", icon: Layers, title: "mode.chain", detail: "mode.chain.detail" },
  { mode: "warp", icon: Cloud, title: "mode.warp", detail: "mode.warp.detail" },
  { mode: "psiphon", icon: Waypoints, title: "mode.psiphon", detail: "mode.psiphon.detail" },
  { mode: "tor", icon: ShieldCheck, title: "mode.tor", detail: "mode.tor.detail" },
];

// The list "servers" connects through: every list at once when the app has
// that row, otherwise the first that is not WARP.
function serverListFor(state: AppState): string {
  const lists = state.v2raySubscriptions.filter((entry) => !isWarpSubscription(entry));
  return lists.find((entry) => entry.id === allListsID)?.id ?? lists[0]?.id ?? "";
}

export function ConnectionModePicker({
  state,
  engines,
  locked,
  t,
  onState,
  onEnginesChanged,
  onError,
}: {
  state: AppState;
  engines: EngineSelection;
  locked: boolean;
  t: TranslateFn;
  onState: (state: AppState) => void;
  onEnginesChanged: () => void;
  onError: (message: string) => void;
}) {
  const current = connectionMode(state, engines);
  const [busy, setBusy] = useState<ConnectionMode | null>(null);

  function unavailable(mode: ConnectionMode): boolean {
    if (mode !== "psiphon" && mode !== "tor") {
      return false;
    }
    return !engines.availability.find((entry) => entry.kind === mode)?.available;
  }

  async function engineProfileFor(kind: "psiphon" | "tor"): Promise<string> {
    const existing = engines.profiles.find((profile) => profile.kind === kind);
    if (existing) {
      return existing.id;
    }
    // A beginner gets Android's defaults rather than a form.
    const base = { id: "", name: kind === "psiphon" ? "Psiphon" : "Tor", version: 1, revision: 0 };
    const profile: EngineProfile = kind === "psiphon"
      ? { ...base, kind, config: { psiphon: { mode: "auto", country: "", cdnIps: [], cdnSni: "" } } }
      : { ...base, kind, config: { tor: { bridgeMode: "default", transport: "obfs4", bridges: "" } } };
    return (await backend.saveEngineProfile(profile)).id;
  }

  async function choose(mode: ConnectionMode) {
    if (mode === current || locked || busy) {
      return;
    }
    setBusy(mode);
    onError("");
    try {
      let next = state;
      const chain = next.whiteVpn.chain;
      // A chain overrides the list, so every mode but "chain" turns it off.
      if (mode !== "chain" && chain && chain.exit.mode !== "off") {
        next = await backend.saveConnectionChain({ ...chain, exit: { mode: "off" } });
      }
      if (mode === "psiphon" || mode === "tor") {
        await backend.selectEngineProfile(await engineProfileFor(mode));
        next = await backend.getAppState();
      } else {
        if (engines.selectedId) {
          await backend.useSubscriptionConnection();
          next = await backend.getAppState();
        }
        if (mode === "warp") {
          let warp = next.v2raySubscriptions.find(isWarpSubscription);
          if (!warp) {
            next = await backend.addWarpSubscription();
            warp = next.v2raySubscriptions.find(isWarpSubscription);
          }
          if (warp) {
            next = await backend.selectSubscription(warp.id);
          }
        } else if (isWarpSubscription(next.v2raySubscriptions.find((entry) => entry.id === next.selectedSubscriptionId))) {
          const list = serverListFor(next);
          if (list) {
            next = await backend.selectSubscription(list);
          }
        }
        if (mode === "chain") {
          const hops = next.whiteVpn.chain;
          const warp = next.v2raySubscriptions.find(isWarpSubscription);
          // WARP first, a public server second: the pair the help text suggests.
          const entry = hops.entry.mode === "automatic" && warp
            ? { mode: "fixed" as const, subscriptionId: warp.id, node: "WARP" }
            : hops.entry;
          next = await backend.saveConnectionChain({ entry, exit: { mode: "automatic" } });
        }
      }
      onState(next);
      onEnginesChanged();
    } catch (err) {
      onError(mode === "warp" ? t("warp.failed") : err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="grid gap-2">
      <p className="text-xs font-medium">{t("mode.title")}</p>
      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5" role="radiogroup" aria-label={t("mode.title")}>
        {options.map(({ mode, icon: Icon, title, detail }) => {
          const selected = mode === current;
          const off = unavailable(mode);
          return (
            <button
              key={mode}
              type="button"
              role="radio"
              aria-checked={selected}
              disabled={(locked && !selected) || off || busy !== null}
              onClick={() => void choose(mode)}
              className={cn(
                "flex min-w-0 flex-col gap-1 rounded-lg border p-3 text-start transition-colors hover:bg-muted/60 disabled:cursor-not-allowed disabled:opacity-55 disabled:hover:bg-transparent",
                selected ? "border-emerald-500/70 bg-emerald-500/10" : "bg-background/60",
              )}
            >
              <span className="flex items-center gap-2">
                <Icon className={cn("size-4 shrink-0", busy === mode && "animate-pulse")} />
                <span className="min-w-0 flex-1 truncate text-sm font-semibold">{latinOnly(t(title)) ? <bdi>{t(title)}</bdi> : isolateLatin(t(title))}</span>
                {selected && <Check className="size-4 shrink-0 text-emerald-600" />}
              </span>
              <span className="text-xs text-muted-foreground">{isolateLatin(t(off ? "mode.unavailable" : detail))}</span>
            </button>
          );
        })}
      </div>
      {locked && <p className="text-xs text-muted-foreground">{t("mode.locked")}</p>}
    </div>
  );
}

// Which list "Automatic servers" draws from, with every list at once first.
export function ServerListDialog({
  open,
  state,
  t,
  onOpenChange,
  onState,
  onError,
}: {
  open: boolean;
  state: AppState;
  t: TranslateFn;
  onOpenChange: (open: boolean) => void;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
}) {
  const lists = state.v2raySubscriptions
    .filter((entry) => !isWarpSubscription(entry))
    .sort((a, b) => Number(b.id === allListsID) - Number(a.id === allListsID));

  async function pick(id: string) {
    onOpenChange(false);
    try {
      onState(await backend.selectSubscription(id));
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("mode.serverList")}</DialogTitle>
          <DialogDescription>{t("mode.serverList.description")}</DialogDescription>
        </DialogHeader>
        <div className="grid gap-1.5">
          {lists.map((entry) => {
            const selected = entry.id === state.selectedSubscriptionId;
            return (
              <button
                key={entry.id}
                type="button"
                onClick={() => void pick(entry.id)}
                className={cn(
                  "flex w-full items-center gap-2 rounded-md border px-3 py-2 text-start transition-colors hover:bg-muted/60",
                  selected ? "border-emerald-500/60 bg-emerald-500/10" : "bg-background/60",
                )}
              >
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium" dir="auto">
                    {entry.id === allListsID ? t("mode.allLists") : entry.name}
                  </span>
                  {entry.id === allListsID && <span className="block text-xs text-muted-foreground">{t("mode.allLists.detail")}</span>}
                </span>
                {selected && <Check className="size-4 shrink-0 text-emerald-600" />}
              </button>
            );
          })}
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function serverListLabel(state: AppState, t: TranslateFn): string {
  if (state.selectedSubscriptionId === allListsID) {
    return t("mode.allLists");
  }
  return state.v2raySubscriptions.find((entry) => entry.id === state.selectedSubscriptionId)?.name ?? "—";
}
