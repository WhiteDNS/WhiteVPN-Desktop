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
  "status.stopping": { en: "Disconnecting", fa: "در حال قطع اتصال" },
  "status.failed": { en: "Failed", fa: "ناموفق" },
  "status.noActiveProxy": { en: "No active proxy", fa: "پراکسی فعالی نیست" },

  // The connect button. One control, five states, as the phone has it.
  "connect.connect": { en: "Connect", fa: "اتصال" },
  "connect.connecting": { en: "Connecting…", fa: "در حال اتصال…" },
  "connect.disconnect": { en: "Disconnect", fa: "قطع اتصال" },
  "connect.disconnecting": { en: "Disconnecting…", fa: "در حال قطع اتصال…" },
  "connect.retry": { en: "Retry", fa: "تلاش دوباره" },
  // Stopping mid-connect is a click on the same button, so what that click does
  // has to be said somewhere.
  "connect.cancelHint": { en: "Stop connecting", fa: "توقف اتصال" },
  "connect.refresh": { en: "Refresh", fa: "تازه‌سازی" },
  "connect.busy": { en: "Busy", fa: "مشغول" },

  // The dashboard's two rows, and the dialogs behind them.
  "vpn.rows.title": { en: "Connection", fa: "اتصال" },
  "vpn.rows.description": {
    en: "Where traffic leaves from, and which node carries it.",
    fa: "اینکه ترافیک از کجا خارج شود و کدام سرور آن را حمل کند.",
  },
  "vpn.location": { en: "Location", fa: "موقعیت" },
  "vpn.location.title": { en: "Choose a location", fa: "انتخاب موقعیت" },
  "vpn.location.description": {
    en: "Only nodes in this country will be used.",
    fa: "فقط سرورهای این کشور استفاده می‌شوند.",
  },
  "vpn.connection": { en: "Connection", fa: "سرور" },
  "vpn.connection.title": { en: "Choose a connection", fa: "انتخاب سرور" },
  "vpn.connection.description": {
    en: "Pick one node, or leave it automatic and let any working one be used.",
    fa: "یک سرور را انتخاب کنید، یا خودکار بگذارید تا هر سرور سالمی استفاده شود.",
  },
  "vpn.automatic": { en: "Automatic", fa: "خودکار" },
  "vpn.search": { en: "Search", fa: "جست‌وجو" },
  "vpn.types": { en: "Protocol", fa: "نوع اتصال" },
  "vpn.types.all": { en: "All", fa: "همه" },
  "vpn.delaySort": { en: "Sort by delay", fa: "مرتب‌سازی بر اساس تأخیر" },
  "vpn.measure": { en: "Measure delay", fa: "اندازه‌گیری تأخیر" },
  "vpn.measuring": { en: "Measuring…", fa: "در حال اندازه‌گیری…" },
  "vpn.measure.needsConnection": {
    en: "Delay is measured through the engine, so it needs a connection first.",
    fa: "تأخیر از طریق موتور اندازه‌گیری می‌شود، پس اول باید متصل شوید.",
  },
  "vpn.nodes.none": { en: "No node matches this.", fa: "سروری با این شرایط نیست." },
  "vpn.nodes.count": { en: "nodes", fa: "سرور" },
  "vpn.nodes.unknownCountry": { en: "Unknown", fa: "نامشخص" },
  "vpn.nodes.reload": { en: "Reload catalogue", fa: "بارگیری دوبارهٔ فهرست" },
  "vpn.nodes.loading": { en: "Loading…", fa: "در حال بارگیری…" },
  // Where traffic leaves from: the node's own claim until it is measured, the
  // measurement afterwards.
  "vpn.exit.ip": { en: "Exit IP", fa: "آی‌پی خروجی" },
  "vpn.exit.measured": {
    en: "Measured through the connection itself.",
    fa: "از طریق خود اتصال اندازه‌گیری شده.",
  },
  "vpn.exit.claimed": {
    en: "What the node's name says. Measuring where traffic actually leaves from…",
    fa: "طبق نام سرور. در حال اندازه‌گیری محل واقعی خروج ترافیک…",
  },
  "vpn.exit.unmeasured": {
    en: "What the node's name says. Where traffic leaves from could not be measured.",
    fa: "طبق نام سرور. محل واقعی خروج ترافیک قابل اندازه‌گیری نبود.",
  },
  "vpn.exit.mismatch": {
    en: "Traffic leaves from here, not from where the node's name says.",
    fa: "ترافیک از اینجا خارج می‌شود، نه از جایی که نام سرور می‌گوید.",
  },

  "vpn.moreSettings": {
    en: "The tunnel, DNS privacy, split tunnel and the rest are on the Settings page.",
    fa: "تونل، حریم خصوصی DNS، تقسیم تونل و بقیه در صفحهٔ تنظیمات هستند.",
  },

  "common.close": { en: "Close", fa: "بستن" },

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
