import { useEffect, useState } from "react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import type { TranslateFn } from "./i18n";
import type { FragmentSettings } from "./types";
import { backend } from "./wails";

function jsonKey(raw: string) {
  try { return JSON.stringify(JSON.parse(raw)); } catch { return raw; }
}

export function FragmentSettingsPanel({ settings, savedSettings, saving, onChange, onApply, t }: {
  settings: FragmentSettings;
  savedSettings: FragmentSettings;
  saving: boolean;
  onChange: (settings: FragmentSettings) => void;
  onApply: (settings: FragmentSettings) => Promise<void>;
  t: TranslateFn;
}) {
  const [presets, setPresets] = useState<string[]>([]);
  const [defaults, setDefaults] = useState<FragmentSettings | null>(null);
  const [error, setError] = useState("");
  const [validating, setValidating] = useState(false);
  useEffect(() => {
    let current = true;
    Promise.all([backend.getFragmentPresets(), backend.getDefaultFragmentSettings()]).then(([items, initial]) => {
      if (current) { setPresets(items); setDefaults(initial); }
    }).catch((err) => { if (current) setError(String(err)); });
    return () => { current = false; };
  }, []);
  const selected = presets.findIndex((raw) => jsonKey(raw) === jsonKey(settings.rawJson));
  const busy = saving || validating;

  async function apply(next: FragmentSettings) {
    setValidating(true);
    setError("");
    try {
      const valid = await backend.validateFragmentSettings(next);
      onChange(valid);
      await onApply(valid);
    } catch (err) { setError(String(err)); }
    finally { setValidating(false); }
  }

  return <div className="grid gap-4">
    <div className="flex items-center justify-between gap-4">
      <label htmlFor="fragments-enabled" className="text-sm font-medium">{t("fragments.enable")}</label>
      <Switch id="fragments-enabled" dir="ltr" checked={settings.enabled} disabled={busy}
        onCheckedChange={(enabled) => void apply({ ...(enabled ? settings : savedSettings), enabled })} />
    </div>
    <FieldDescription>{t("fragments.scope")}</FieldDescription>
    {settings.enabled && <fieldset disabled={busy} className="grid min-w-0 gap-4">
      <Field>
        <FieldLabel htmlFor="fragment-preset">{t("fragments.presets")}</FieldLabel>
        <Select value={selected < 0 ? "custom" : String(selected)} disabled={busy || presets.length === 0}
          onValueChange={(value) => { if (value !== "custom") { onChange({ ...settings, rawJson: presets[Number(value)] }); setError(""); } }}>
          <SelectTrigger id="fragment-preset"><SelectValue /></SelectTrigger>
          <SelectContent position="popper">
            {selected < 0 && <SelectItem value="custom">{t("fragments.custom")}</SelectItem>}
            {presets.map((_, index) => <SelectItem key={index} value={String(index)}>{t("fragments.preset", { number: index + 1 })}</SelectItem>)}
          </SelectContent>
        </Select>
      </Field>
      <Field>
        <FieldLabel htmlFor="fragment-json">{t("fragments.json")}</FieldLabel>
        <Textarea id="fragment-json" dir="ltr" spellCheck={false} className="min-h-64 font-mono text-xs"
          value={settings.rawJson} onChange={(e) => onChange({ ...settings, rawJson: e.target.value })} />
        <FieldDescription>{t("fragments.json.help")}</FieldDescription>
      </Field>
      <Field>
        <FieldLabel htmlFor="fragment-alpn">ALPN</FieldLabel>
        <Input id="fragment-alpn" dir="ltr" value={settings.alpn} placeholder="http/1.1"
          onChange={(e) => onChange({ ...settings, alpn: e.target.value })} />
        <FieldDescription>{t("fragments.alpn.help")}</FieldDescription>
      </Field>
      <Field>
        <FieldLabel htmlFor="fragment-ciphers">{t("fragments.ciphers")}</FieldLabel>
        <Textarea id="fragment-ciphers" dir="ltr" spellCheck={false} className="font-mono text-xs"
          value={settings.cipherSuites} onChange={(e) => onChange({ ...settings, cipherSuites: e.target.value })} />
        <FieldDescription>{t("fragments.ciphers.help")}</FieldDescription>
      </Field>
      <div className="flex flex-wrap gap-2">
        <Button type="button" disabled={busy} onClick={() => void apply(settings)}>{t("fragments.apply")}</Button>
        <Button type="button" variant="outline" disabled={busy || !defaults}
          onClick={() => { if (defaults) { onChange({ ...defaults, enabled: settings.enabled }); setError(""); } }}>{t("fragments.reset")}</Button>
      </div>
      <FieldDescription>{t("fragments.reconnect")}</FieldDescription>
    </fieldset>}
    {error && <Alert variant="destructive"><AlertDescription role="alert">{error}</AlertDescription></Alert>}
  </div>;
}
