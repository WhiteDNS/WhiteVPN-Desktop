// Engine profiles beside the subscriptions, as Android's SavedProfilesUi and
// EngineProfilesUi have them: creating a profile never connects, selecting one
// replaces the subscription as the connection, and the form fields are
// EngineFields'. Only Psiphon and Tor are offered on the desktop; DNS tunnels
// stay in the WhiteDNS app.
import { Check, Gauge, Pencil, Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { isolateLatin } from "./bidi";
import type { EngineAvailability, EngineKind, EngineProfile, EngineProfileSummary, PsiphonConfig, TorConfig } from "./engine-profiles";
import type { Language, StringKey, TranslateFn } from "./i18n";
import type { RuntimeStatus, V2RaySubscription } from "./types";
import { backend } from "./wails";

export type EngineSelection = {
  selectedId: string;
  profiles: EngineProfileSummary[];
  availability: EngineAvailability[];
};

const offeredKinds: EngineKind[] = ["psiphon", "tor"];

const kindTitles: Record<EngineKind, string> = {
  ssh: "SSH", psiphon: "Psiphon", tor: "Tor", dns: "DNS tunnels", amneziawg: "AmneziaWG", ikev2: "IKEv2",
};

export function engineKindTitle(kind: EngineKind): string {
  return kindTitles[kind];
}

// Android EngineProfilesUi.unavailableReason.
export function engineUnavailableKey(kind: EngineKind, availability: EngineAvailability[]): StringKey | null {
  const entry = availability.find((item) => item.kind === kind);
  if (entry?.available) {
    return null;
  }
  switch (entry?.reason) {
    case "platform-unsupported":
      return "engine.platformUnsupported";
    case "credential-vault-unavailable":
      return "engine.vaultUnavailable";
  }
  return kind === "tor" ? "engine.transportMissing" : "engine.nativeMissing";
}

type Draft = {
  id: string;
  revision: number;
  kind: "psiphon" | "tor";
  name: string;
  psiphon: PsiphonConfig;
  tor: TorConfig;
  cdnIpsText: string;
};

function newDraft(kind: "psiphon" | "tor"): Draft {
  return {
    id: "", revision: 0, kind, name: "", cdnIpsText: "",
    psiphon: { mode: "auto", country: "", cdnIps: [], cdnSni: "" },
    tor: { bridgeMode: "default", transport: "obfs4", bridges: "" },
  };
}

// Hidden subtype fields are discarded, as on Android.
function profileFromDraft(draft: Draft): EngineProfile {
  const base = { id: draft.id, name: draft.name.trim(), version: 1, revision: draft.revision };
  if (draft.kind === "psiphon") {
    const direct = draft.psiphon.mode === "direct";
    return {
      ...base, kind: "psiphon",
      config: { psiphon: {
        mode: draft.psiphon.mode, country: draft.psiphon.country,
        cdnIps: direct ? [] : draft.cdnIpsText.split(/[\s,;]+/).filter(Boolean),
        cdnSni: direct ? "" : draft.psiphon.cdnSni.trim(),
      } },
    };
  }
  const mode = draft.tor.bridgeMode;
  return {
    ...base, kind: "tor",
    config: { tor: { bridgeMode: mode, transport: mode === "none" ? "obfs4" : draft.tor.transport, bridges: mode === "custom" ? draft.tor.bridges : "" } },
  };
}

function countryLabel(code: string, language: Language, t: TranslateFn): string {
  if (!code) {
    return t("engine.option.auto");
  }
  try {
    return new Intl.DisplayNames([language], { type: "region" }).of(code) || code;
  } catch {
    return code;
  }
}

// WARP is a subscription underneath, but to the user it is one more way to
// connect, so it is listed and added here beside the engines.
export type WarpRows = {
  subscriptions: V2RaySubscription[];
  selectedId: string;
  adding: boolean;
  onAdd: () => void;
  onUse: (id: string) => void;
  onEdit: (subscription: V2RaySubscription) => void;
  onDelete: (subscription: V2RaySubscription) => void;
};

export function EngineProfilesSection({
  selection,
  warp,
  runtime,
  language,
  t,
  onChanged,
  onError,
  onSuccess,
}: {
  selection: EngineSelection;
  warp: WarpRows;
  runtime: RuntimeStatus;
  language: Language;
  t: TranslateFn;
  onChanged: () => void;
  onError: (message: string) => void;
  onSuccess: (message: string) => void;
}) {
  const [draft, setDraft] = useState<Draft | null>(null);
  const [regions, setRegions] = useState<string[]>([""]);
  const [selectTarget, setSelectTarget] = useState<EngineProfileSummary | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<EngineProfileSummary | null>(null);
  const [test, setTest] = useState<{ name: string; result: string } | null>(null);
  const locked = runtime.status !== "disconnected" && runtime.status !== "failed";
  const missingSelection = selection.selectedId !== "" && !selection.profiles.some((p) => p.id === selection.selectedId);

  const country = draft?.kind === "psiphon" ? draft.psiphon.country : null;
  useEffect(() => {
    if (country === null) {
      return;
    }
    let current = true;
    void backend.getPsiphonRegions(country).then((codes) => {
      if (current) {
        // Automatic first, then by name in the app's language (PsiphonRegions.options).
        const named = codes.filter(Boolean).sort((a, b) => countryLabel(a, language, t).localeCompare(countryLabel(b, language, t), language));
        setRegions(["", ...named]);
      }
    }).catch(() => undefined);
    return () => { current = false; };
  }, [country, language, t]);

  function inUse(id: string): boolean {
    return locked && runtime.engineProfileId === id;
  }

  async function openEditor(summary: EngineProfileSummary) {
    if (inUse(summary.id)) {
      onError(t("engine.stopBeforeEdit"));
      return;
    }
    try {
      const profile = await backend.getEngineProfileForEdit(summary.id);
      const next = newDraft(profile.kind === "tor" ? "tor" : "psiphon");
      next.id = profile.id;
      next.revision = profile.revision;
      next.name = profile.name;
      if (profile.kind === "psiphon") {
        next.psiphon = { ...profile.config.psiphon, cdnIps: profile.config.psiphon.cdnIps ?? [] };
        next.cdnIpsText = next.psiphon.cdnIps.join("\n");
      } else if (profile.kind === "tor") {
        next.tor = { ...profile.config.tor, transport: profile.config.tor.transport === "conjure" ? "obfs4" : profile.config.tor.transport };
      }
      setDraft(next);
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    }
  }

  async function save() {
    if (!draft) {
      return;
    }
    try {
      await backend.saveEngineProfile(profileFromDraft(draft));
      setDraft(null);
      onChanged();
    } catch {
      onError(t("engine.invalid"));
    }
  }

  async function confirmSelect(profile: EngineProfileSummary) {
    setSelectTarget(null);
    try {
      await backend.selectEngineProfile(profile.id);
      onChanged();
      onSuccess(t("engine.selectedReconnect"));
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    }
  }

  async function confirmDelete(profile: EngineProfileSummary) {
    setDeleteTarget(null);
    if (inUse(profile.id)) {
      onError(t("engine.stopBeforeEdit"));
      return;
    }
    try {
      await backend.deleteEngineProfile(profile.id, profile.revision);
      onChanged();
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    }
  }

  async function runTest(profile: EngineProfileSummary) {
    if (locked && runtime.engineProfileId !== profile.id) {
      onError(t("engine.stopBeforeTest"));
      return;
    }
    setTest({ name: profile.name, result: t("engine.testing") });
    let result: string;
    try {
      result = await backend.testEngineProfile(profile.id);
    } catch {
      result = t("engine.testFailed");
    }
    setTest((current) => (current && current.name === profile.name ? { ...current, result } : current));
  }

  async function useSubscription() {
    try {
      await backend.useSubscriptionConnection();
      onChanged();
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div className="overflow-hidden rounded-lg border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b bg-muted/30 px-3 py-2.5">
        <div className="min-w-0">
          <p className="text-sm font-semibold">{t("engine.title")}</p>
          <p className="text-xs text-muted-foreground" dir="ltr">{t("engine.description")}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {selection.selectedId && (
            <Button type="button" variant="outline" size="sm" disabled={locked} onClick={() => void useSubscription()}>
              {t("engine.useSubscription")}
            </Button>
          )}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button type="button" variant="outline" size="sm"><Plus />{t("engine.add")}</Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem disabled={warp.adding} onSelect={warp.onAdd}>
                <bdi>{t(warp.adding ? "warp.registering" : "warp.add")}</bdi>
              </DropdownMenuItem>
              {offeredKinds.map((kind) => (
                <DropdownMenuItem key={kind} onSelect={() => setDraft(newDraft(kind as "psiphon" | "tor"))}>
                  <bdi>{engineKindTitle(kind)}</bdi>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
      {missingSelection && <p className="border-b px-3 py-2 text-xs text-destructive">{t("engine.missingProfile")}</p>}
      {warp.subscriptions.length > 0 && (
        <div className="divide-y border-b">
          {warp.subscriptions.map((subscription) => {
            const selected = !selection.selectedId && subscription.id === warp.selectedId;
            return (
              <div key={subscription.id} className="flex flex-wrap items-center justify-between gap-3 px-3 py-3 text-sm">
                <div className="min-w-0">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="truncate font-medium" dir="auto">{subscription.name}</span>
                    {selected && <Badge className="shrink-0">{t("engine.selected")}</Badge>}
                  </div>
                  <p className="text-xs text-muted-foreground"><bdi>{t("warp.add")}</bdi> · <bdi>WireGuard</bdi></p>
                </div>
                <div className="flex flex-wrap gap-1">
                  <Button type="button" size="sm" variant={selected ? "secondary" : "default"} disabled={selected || locked} onClick={() => warp.onUse(subscription.id)}>
                    <Check />{selected ? t("engine.selected") : t("engine.select")}
                  </Button>
                  <Button type="button" size="icon-sm" variant="ghost" disabled={locked && selected} aria-label={t("engine.edit")} onClick={() => warp.onEdit(subscription)}>
                    <Pencil />
                  </Button>
                  <Button type="button" size="icon-sm" variant="ghost" disabled={locked && selected} aria-label={t("engine.delete")} onClick={() => warp.onDelete(subscription)}>
                    <Trash2 />
                  </Button>
                </div>
              </div>
            );
          })}
        </div>
      )}
      {selection.profiles.length === 0 && warp.subscriptions.length === 0 ? (
        <div className="px-3 py-4 text-sm text-muted-foreground">{t("engine.empty")}</div>
      ) : (
        <div className="divide-y">
          {selection.profiles.map((profile) => {
            const unavailable = engineUnavailableKey(profile.kind, selection.availability);
            const selected = profile.id === selection.selectedId;
            const editable = offeredKinds.includes(profile.kind);
            return (
              <div key={profile.id} className="flex flex-wrap items-center justify-between gap-3 px-3 py-3 text-sm">
                <div className="min-w-0">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="truncate font-medium">{profile.name}</span>
                    {selected && <Badge className="shrink-0">{t("engine.selected")}</Badge>}
                  </div>
                  <p className="text-xs text-muted-foreground"><bdi>{engineKindTitle(profile.kind)}</bdi> · <bdi>{t("engine.tcpRoute")}</bdi></p>
                  {unavailable && <p className="text-xs text-destructive">{isolateLatin(t(unavailable))}</p>}
                </div>
                <div className="flex flex-wrap gap-1">
                  <Button type="button" size="sm" variant={selected ? "secondary" : "default"} disabled={selected || locked || Boolean(unavailable)} onClick={() => setSelectTarget(profile)}>
                    <Check />{selected ? t("engine.selected") : t("engine.select")}
                  </Button>
                  <Button type="button" size="sm" variant="outline" disabled={Boolean(unavailable) || test !== null} onClick={() => void runTest(profile)}>
                    <Gauge />{t("engine.test")}
                  </Button>
                  <Button type="button" size="icon-sm" variant="ghost" disabled={!editable} aria-label={t("engine.edit")} onClick={() => void openEditor(profile)}>
                    <Pencil />
                  </Button>
                  <Button type="button" size="icon-sm" variant="ghost" aria-label={t("engine.delete")} onClick={() => setDeleteTarget(profile)}>
                    <Trash2 />
                  </Button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <Dialog open={draft !== null} onOpenChange={(open) => !open && setDraft(null)}>
        <DialogContent className="sm:max-w-md">
          {draft && (
            <>
              <DialogHeader>
                <DialogTitle><bdi>{engineKindTitle(draft.kind)}</bdi></DialogTitle>
              </DialogHeader>
              <div className="grid gap-3">
                <Field>
                  <FieldLabel htmlFor="engine-name">{t("engine.name")}</FieldLabel>
                  <Input id="engine-name" maxLength={100} value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
                </Field>
                {draft.kind === "psiphon" ? (
                  <>
                    <Field>
                      <FieldLabel>{isolateLatin(t("engine.psiphonMode"))}</FieldLabel>
                      <Select value={draft.psiphon.mode} onValueChange={(mode) => setDraft({ ...draft, psiphon: { ...draft.psiphon, mode: mode as PsiphonConfig["mode"] } })}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          {(["auto", "cdn", "direct"] as const).map((mode) => (
                            <SelectItem key={mode} value={mode}>{t(`engine.option.${mode}` as StringKey)}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </Field>
                    <Field>
                      <FieldLabel>{t("engine.country")}</FieldLabel>
                      {/* Radix Select reserves "" for no value, so automatic is "auto" here. */}
                      <Select value={draft.psiphon.country || "auto"} onValueChange={(code) => setDraft({ ...draft, psiphon: { ...draft.psiphon, country: code === "auto" ? "" : code } })}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          {regions.map((code) => (
                            <SelectItem key={code || "auto"} value={code || "auto"}>{countryLabel(code, language, t)}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </Field>
                    {draft.psiphon.mode !== "direct" && (
                      <>
                        <Field>
                          <FieldLabel htmlFor="engine-cdn-ips">{isolateLatin(t("engine.cdnIps"))}</FieldLabel>
                          <Textarea id="engine-cdn-ips" dir="ltr" rows={3} value={draft.cdnIpsText} onChange={(e) => setDraft({ ...draft, cdnIpsText: e.target.value })} />
                        </Field>
                        <Field>
                          <FieldLabel htmlFor="engine-cdn-sni">{isolateLatin(t("engine.cdnSni"))}</FieldLabel>
                          <Input id="engine-cdn-sni" dir="ltr" value={draft.psiphon.cdnSni} onChange={(e) => setDraft({ ...draft, psiphon: { ...draft.psiphon, cdnSni: e.target.value } })} />
                        </Field>
                      </>
                    )}
                  </>
                ) : (
                  <>
                    <Field>
                      <FieldLabel>{t("engine.bridgeMode")}</FieldLabel>
                      <Select value={draft.tor.bridgeMode} onValueChange={(mode) => setDraft({ ...draft, tor: { ...draft.tor, bridgeMode: mode as TorConfig["bridgeMode"] } })}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="none">{isolateLatin(t("engine.option.noBridges"))}</SelectItem>
                          <SelectItem value="default">{t("engine.option.defaultBridges")}</SelectItem>
                          <SelectItem value="custom">{t("engine.option.customBridges")}</SelectItem>
                        </SelectContent>
                      </Select>
                    </Field>
                    {draft.tor.bridgeMode !== "none" && (
                      <Field>
                        <FieldLabel>{t("engine.transport")}</FieldLabel>
                        {/* Conjure does not build for Windows (native/engines/windows-sources.json). */}
                        <Select value={draft.tor.transport} onValueChange={(transport) => setDraft({ ...draft, tor: { ...draft.tor, transport: transport as TorConfig["transport"] } })}>
                          <SelectTrigger dir="ltr"><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="obfs4">obfs4</SelectItem>
                            <SelectItem value="snowflake">snowflake</SelectItem>
                          </SelectContent>
                        </Select>
                      </Field>
                    )}
                    {draft.tor.bridgeMode === "custom" && (
                      <Field>
                        <FieldLabel htmlFor="engine-bridges">{t("engine.bridges")}</FieldLabel>
                        <Textarea id="engine-bridges" dir="ltr" rows={5} className="font-mono text-xs" value={draft.tor.bridges} onChange={(e) => setDraft({ ...draft, tor: { ...draft.tor, bridges: e.target.value } })} />
                      </Field>
                    )}
                  </>
                )}
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setDraft(null)}>{t("common.cancel")}</Button>
                <Button disabled={!draft.name.trim()} onClick={() => void save()}>{t("engine.save")}</Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={selectTarget !== null} onOpenChange={(open) => !open && setSelectTarget(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{selectTarget?.name}</DialogTitle>
            <DialogDescription>{isolateLatin(t("engine.tcpFeatures"))}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSelectTarget(null)}>{t("common.cancel")}</Button>
            <Button onClick={() => selectTarget && void confirmSelect(selectTarget)}>{t("engine.select")}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={deleteTarget !== null} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t("engine.delete")}</DialogTitle>
            <DialogDescription>{deleteTarget?.name}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>{t("common.cancel")}</Button>
            <Button variant="destructive" onClick={() => deleteTarget && void confirmDelete(deleteTarget)}>{t("engine.delete")}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={test !== null} onOpenChange={(open) => !open && setTest(null)}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle>{t("engine.test")}</DialogTitle>
            <DialogDescription>{test?.name}</DialogDescription>
          </DialogHeader>
          <p className="text-sm" dir="auto">{test?.result}</p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTest(null)}>{t("common.close")}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
