// Persian and English, with the Persian taken from WhiteVPN for Android's own
// strings wherever the app already has a word for something. That matters more
// than a fluent fresh translation: someone moving between the phone and the
// desktop should meet the same vocabulary, not two ways of saying "split
// tunnel".
//
// Keys are added as screens are translated. Anything without a key falls back to
// English, which is why `t` returns the key's English text rather than the key
// itself — a missing translation should read as English, not as `settings.dns`.

export type Language = "en" | "fa";

export const languages: { value: Language; label: string }[] = [
  { value: "en", label: "English" },
  { value: "fa", label: "فارسی" },
];

type Entry = { en: string; fa: string };

const strings = {
  // Navigation
  "nav.group.whitevpn": { en: "WhiteVPN", fa: "وایت‌وی‌پی‌ان" },
  "nav.group.tools": { en: "Tools", fa: "ابزارها" },
  "nav.vpn": { en: "VPN", fa: "وی‌پی‌ان" },
  "nav.servers": { en: "Servers", fa: "سرورها" },
  "nav.subscriptions": { en: "Subscriptions", fa: "اشتراک‌ها" },
  "nav.settings": { en: "Settings", fa: "تنظیمات" },
  "nav.logs": { en: "Logs", fa: "گزارش‌ها" },
  "nav.whiteIps": { en: "White IP Generator", fa: "سازندهٔ آی‌پی سفید" },
  "nav.validator": { en: "Validator", fa: "اعتبارسنج" },
  "nav.backup": { en: "Full Backup", fa: "پشتیبان کامل" },

  // Connection status
  "status.connected": { en: "Connected", fa: "متصل" },
  "status.connecting": { en: "Connecting", fa: "در حال اتصال" },
  "status.disconnected": { en: "Disconnected", fa: "قطع" },
  "status.failed": { en: "Failed", fa: "ناموفق" },
  "status.noActiveProxy": { en: "No active proxy", fa: "پراکسی فعالی نیست" },

  // Settings page
  "settings.title": { en: "Settings", fa: "تنظیمات" },
  "settings.save": { en: "Save changes", fa: "ذخیرهٔ تغییرات" },
  "settings.discard": { en: "Discard", fa: "انصراف" },
  "settings.saved": { en: "Settings saved.", fa: "تنظیمات ذخیره شد." },

  "settings.connection.title": { en: "Connection", fa: "اتصال" },
  "settings.connection.description": {
    en: "How traffic reaches your machine.",
    fa: "اینکه ترافیک چطور به دستگاه شما می‌رسد.",
  },
  "settings.tunnel": { en: "Tunnel (TUN)", fa: "تونل (TUN)" },
  "settings.killSwitch": { en: "Kill switch", fa: "قطع‌کنندهٔ اضطراری" },

  "settings.security.title": { en: "Security", fa: "امنیت اتصال" },
  "settings.security.description": {
    en: "Checks applied to a server before it is trusted with traffic.",
    fa: "بررسی‌هایی که پیش از سپردن ترافیک به یک سرور انجام می‌شود.",
  },
  "settings.tlsIntegrity": { en: "TLS integrity", fa: "یکپارچگی TLS" },
  "settings.tlsIntegrity.description": {
    en: "Verifies a server's certificate before connecting, and sets aside any that fail for a day.",
    fa: "گواهی سرور را پیش از اتصال بررسی می‌کند و هر سروری را که رد شود یک روز کنار می‌گذارد.",
  },

  "settings.dns.title": { en: "DNS privacy", fa: "حریم خصوصی DNS" },
  "settings.dns.description": {
    en: "Where name lookups go, and over what.",
    fa: "اینکه جست‌وجوی نام‌ها کجا و از چه راهی انجام شود.",
  },
  "settings.dns.mode": { en: "Mode", fa: "حالت" },
  "settings.dns.automatic": { en: "Automatic", fa: "خودکار" },
  "settings.dns.doh": { en: "DNS over HTTPS", fa: "DNS روی HTTPS" },
  "settings.dns.dot": { en: "DNS over TLS", fa: "DNS روی TLS" },
  "settings.dns.dohServer": { en: "DoH server", fa: "سرور DoH" },
  "settings.dns.dotServer": { en: "DoT server", fa: "سرور DoT" },
  "settings.dns.hint": {
    en: "Automatic offers both, encrypted either way.",
    fa: "حالت خودکار هر دو را ارائه می‌دهد و در هر صورت رمزگذاری‌شده است.",
  },

  "settings.fronting.title": { en: "IP fronting", fa: "آی‌پی جایگزین" },
  "settings.fronting.empty": {
    en: "No fronting addresses. Servers are reached directly.",
    fa: "آدرس جایگزینی تنظیم نشده. سرورها مستقیم در دسترس‌اند.",
  },

  "settings.splitTunnel.title": { en: "Split tunnel", fa: "تقسیم تونل" },
  "settings.splitTunnel.description": {
    en: "Choose which programs the tunnel carries.",
    fa: "انتخاب کنید تونل کدام برنامه‌ها را حمل کند.",
  },
  "settings.splitTunnel.off": { en: "Off — carry everything", fa: "خاموش — همه‌چیز از تونل" },
  "settings.splitTunnel.bypass": {
    en: "Bypass selected programs",
    fa: "برنامه‌های انتخاب‌شده خارج از VPN",
  },
  "settings.splitTunnel.vpnOnly": {
    en: "Only selected programs",
    fa: "فقط برنامه‌های انتخاب‌شده داخل VPN",
  },
  "settings.splitTunnel.program": { en: "Program", fa: "برنامه" },
  "settings.splitTunnel.empty": { en: "No programs selected.", fa: "برنامه‌ای انتخاب نشده." },

  "settings.noise.title": { en: "Obfuscation", fa: "Amnezia Noise" },
  "settings.noise.description": {
    en: "Pad the connection with noise so its shape is less recognisable.",
    fa: "اتصال را با نویز پر می‌کند تا الگویش کمتر قابل تشخیص باشد.",
  },
  "settings.noise.enable": { en: "Amnezia noise", fa: "فعال‌سازی Amnezia Noise" },
  "settings.noise.count": { en: "Packets", fa: "تعداد" },
  "settings.noise.minSize": { en: "Smallest (bytes)", fa: "کمینه اندازه (بایت)" },
  "settings.noise.maxSize": { en: "Largest (bytes)", fa: "بیشینه اندازه (بایت)" },

  "settings.appearance.title": { en: "Appearance", fa: "ظاهر" },
  "settings.appearance.description": {
    en: "How the app looks and what language it speaks.",
    fa: "اینکه برنامه چه شکلی باشد و به چه زبانی صحبت کند.",
  },
  "settings.language": { en: "App language", fa: "زبان برنامه" },

  "settings.engine.title": { en: "Engine settings", fa: "تنظیمات موتور" },
  "settings.engine.open": { en: "Open engine settings", fa: "باز کردن تنظیمات موتور" },

  "common.add": { en: "Add", fa: "افزودن" },
  "common.remove": { en: "Remove", fa: "حذف" },
} satisfies Record<string, Entry>;

export type StringKey = keyof typeof strings;

export function translate(language: Language, key: StringKey): string {
  const entry = strings[key];
  if (!entry) {
    return key;
  }
  // Persian falls back to English rather than to the key: a screen part-way
  // through translation should read as mixed language, not as identifiers.
  return language === "fa" ? entry.fa || entry.en : entry.en;
}

// normalizeLanguage decides what an unset or unknown setting means.
//
// The phone defaults to Persian. This defaults to whatever the system is set to,
// because someone who installed an English build and is shown Persian will
// assume the app is broken rather than that it has a preference.
export function normalizeLanguage(value: string): Language {
  if (value === "fa" || value === "en") {
    return value;
  }
  if (typeof navigator !== "undefined" && navigator.language?.toLowerCase().startsWith("fa")) {
    return "fa";
  }
  return "en";
}

export function isRightToLeft(language: Language): boolean {
  return language === "fa";
}
