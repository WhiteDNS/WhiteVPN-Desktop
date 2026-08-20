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
  "nav.source": { en: "Source: WhiteDNS Telegram", fa: "منبع: تلگرام وایت‌دی‌ان‌اس" },
  "nav.youtubeSubscribe": { en: "Subscribe on YouTube", fa: "عضویت در یوتیوب" },
  "nav.loading": { en: "Loading command center", fa: "در حال بارگذاری" },

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

  // The status card.
  "vpn.card.ready": { en: "WhiteVPN ready", fa: "وایت‌وی‌پی‌ان آماده است" },
  "vpn.card.ready.description": { en: "Runtime idle", fa: "موتور بی‌کار است" },
  "vpn.card.connecting": { en: "Connecting WhiteVPN", fa: "در حال اتصال وایت‌وی‌پی‌ان" },
  "vpn.card.connecting.description": {
    en: "Testing available connections before starting VPN.",
    fa: "آزمودن سرورهای در دسترس پیش از برپا کردن وی‌پی‌ان.",
  },
  "vpn.card.connected": { en: "WhiteVPN connected", fa: "وایت‌وی‌پی‌ان متصل است" },
  "vpn.card.connected.description": {
    en: "Proxy listening on {endpoint}",
    fa: "پراکسی روی {endpoint} در حال شنود است",
  },
  "vpn.card.disconnecting": { en: "Disconnecting WhiteVPN", fa: "در حال قطع وایت‌وی‌پی‌ان" },
  "vpn.card.disconnecting.description": {
    en: "Stopping the engine and removing what it created.",
    fa: "متوقف کردن موتور و برداشتن آنچه ساخته است.",
  },
  "vpn.card.failed": { en: "WhiteVPN could not connect", fa: "وایت‌وی‌پی‌ان نتوانست وصل شود" },
  "vpn.card.failed.description": {
    en: "The connection did not come up.",
    fa: "اتصال برقرار نشد.",
  },
  "vpn.card.otherRuntime": { en: "Another runtime is active", fa: "موتور دیگری فعال است" },
  "vpn.card.otherRuntime.description": {
    en: "Disconnect the active runtime before starting WhiteVPN.",
    fa: "پیش از راه‌اندازی وایت‌وی‌پی‌ان، موتور فعال را قطع کنید.",
  },
  "vpn.metric.localProxy": { en: "Local proxy", fa: "پراکسی محلی" },
  "vpn.localProxy.copy": {
    en: "Copy — point a browser extension or Telegram here (HTTP or SOCKS5)",
    fa: "کپی — افزونهٔ مرورگر یا تلگرام را به اینجا وصل کنید (HTTP یا SOCKS5)",
  },
  "vpn.metric.frontingIp": { en: "Fronting IP", fa: "آی‌پی جایگزین" },
  "vpn.metric.download": { en: "Download", fa: "دریافت" },
  "vpn.metric.upload": { en: "Upload", fa: "ارسال" },
  "vpn.metric.traffic": { en: "Traffic", fa: "ترافیک" },
  "vpn.frontingAuto": { en: "IP fronting auto", fa: "آی‌پی جایگزین خودکار" },

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

  // The first-run gate. Every line here describes something the app actually
  // does and can be checked against the code; none of it is boilerplate.
  "privacy.title": { en: "Before you connect", fa: "پیش از اتصال" },
  "privacy.intro": {
    en: "What this app does with your data, in full:",
    fa: "کاری که این برنامه با داده‌های شما می‌کند، به‌طور کامل:",
  },
  "privacy.local": {
    en: "Your settings, servers and logs are kept on this computer and are never uploaded.",
    fa: "تنظیمات، سرورها و گزارش‌های شما روی همین رایانه می‌مانند و هرگز جایی فرستاده نمی‌شوند.",
  },
  "privacy.catalogue": {
    en: "It downloads the WhiteDNS server list, and a list of alternative addresses, from WhiteDNS.",
    fa: "فهرست سرورهای وایت‌دی‌ان‌اس و فهرست آدرس‌های جایگزین را از وایت‌دی‌ان‌اس دریافت می‌کند.",
  },
  "privacy.checks": {
    en: "To prove a connection works it requests three well-known addresses through it — Let's Encrypt, Google's connectivity check and Cloudflare — and asks Cloudflare which country your traffic leaves from.",
    fa: "برای اثبات کارکرد اتصال، سه آدرس شناخته‌شده را از راه آن درخواست می‌کند — Let's Encrypt، بررسی اتصال گوگل و Cloudflare — و از Cloudflare می‌پرسد ترافیک شما از کدام کشور خارج می‌شود.",
  },
  "privacy.traffic": {
    en: "Your traffic travels through the server you choose, which can see it as any VPN provider can.",
    fa: "ترافیک شما از سروری که انتخاب می‌کنید عبور می‌کند و آن سرور، مانند هر ارائه‌دهندهٔ VPN، آن را می‌بیند.",
  },
  "privacy.noAnalytics": {
    en: "No usage data, analytics or crash reports are sent anywhere.",
    fa: "هیچ داده‌ای از نحوهٔ استفاده، آمار یا گزارش خطا به جایی فرستاده نمی‌شود.",
  },
  "privacy.more": {
    en: "The full policy is published on the WhiteDNS Telegram channel.",
    fa: "متن کامل سیاست حریم خصوصی در کانال تلگرام وایت‌دی‌ان‌اس منتشر می‌شود.",
  },
  "privacy.accept": { en: "Accept and continue", fa: "می‌پذیرم و ادامه" },
  "privacy.quit": { en: "Quit", fa: "خروج" },

  "subs.inTheClear": {
    en: "Fetched over plain HTTP. Anyone on the network path can read this server list and replace it with one of their own — which, on a network that blocks VPNs, is the same party the VPN exists to get past. Ask the provider for an https:// address if there is one.",
    fa: "با HTTP ساده دریافت می‌شود. هرکسی در مسیر شبکه می‌تواند این فهرست سرورها را بخواند و با فهرست خودش جایگزین کند — و در شبکه‌ای که وی‌پی‌ان را مسدود می‌کند، این همان طرفی است که وی‌پی‌ان برای عبور از آن وجود دارد. اگر ارائه‌دهنده آدرس https:// دارد، آن را بگیرید.",
  },
  "subs.use": { en: "Connect through this", fa: "اتصال از طریق این" },
  "vpn.exit.checking": { en: "checking", fa: "در حال بررسی" },
  // Short enough for a tile; vpn.exit.unmeasured is the sentence for a tooltip.
  "vpn.exit.notMeasured": { en: "not measured", fa: "اندازه‌گیری نشد" },
  "vpn.systemProxy": { en: "System proxy", fa: "پراکسی سیستم" },
  "vpn.systemProxy.hint": {
    en: "Windows is pointed at this app's local proxy, so applications that follow the system setting go through the VPN. It is put back when you disconnect.",
    fa: "ویندوز به پراکسی محلی این برنامه اشاره می‌کند، پس برنامه‌هایی که تنظیم سیستم را دنبال می‌کنند از وی‌پی‌ان عبور می‌کنند. با قطع اتصال به حالت قبل برمی‌گردد.",
  },
  "subs.inUse": { en: "In use", fa: "در حال استفاده" },
  "subs.disconnectFirst": { en: "Disconnect first", fa: "اول قطع کنید" },
  "subs.new": { en: "New subscription", fa: "اشتراک جدید" },
  "subs.groups": { en: "Subscription groups", fa: "گروه‌های اشتراک" },
  "subs.sources": { en: "{count} sources", fa: "{count} منبع" },
  "subs.empty": { en: "No saved subscription URLs.", fa: "هیچ نشانی اشتراکی ذخیره نشده است." },
  "subs.column.name": { en: "Name", fa: "نام" },
  "subs.column.url": { en: "URL", fa: "نشانی" },
  "subs.column.profiles": { en: "Profiles", fa: "پروفایل‌ها" },
  "subs.column.status": { en: "Status", fa: "وضعیت" },
  "subs.builtIn": { en: "Built-in", fa: "داخلی" },
  "subs.builtInStays": { en: "The built-in catalogue stays", fa: "فهرست داخلی حذف نمی‌شود" },
  "subs.refresh": { en: "Refresh", fa: "تازه‌سازی" },
  "subs.refreshing": { en: "Refreshing", fa: "در حال تازه‌سازی" },
  "subs.refreshFailed": { en: "Subscription refresh failed.", fa: "تازه‌سازی اشتراک ناموفق بود." },
  "subs.imported": { en: "Imported {count} V2Ray profiles.", fa: "{count} پروفایل V2Ray وارد شد." },
  "subs.lastRefreshFailed": { en: "Last refresh failed", fa: "آخرین تازه‌سازی ناموفق بود" },
  "subs.delete": { en: "Delete", fa: "حذف" },
  "subs.deleteHint": {
    en: "Delete subscription and related configs",
    fa: "حذف اشتراک و کانفیگ‌های مرتبط",
  },
  "subs.editor.description": { en: "Saved V2Ray subscription URL", fa: "نشانی اشتراک V2Ray ذخیره‌شده" },
  "subs.editor.url": { en: "Subscription URL", fa: "نشانی اشتراک" },
  "subs.editor.allowInsecureTls": {
    en: "Fetch without checking the certificate",
    fa: "دریافت بدون بررسی گواهی",
  },
  "subs.editor.allowInsecureTlsHint": {
    en: "This server's certificate cannot be verified, so there is no proof you are talking to the real address. Your subscription link contains your account key — if something is intercepting this connection, turning this on hands the key to it. Only for a provider and a network you trust.",
    fa: "گواهی این سرور تأیید نمی‌شود، پس معلوم نیست واقعاً با همان نشانی طرف هستید. نشانی اشتراک شما کلید حسابتان را در خود دارد — اگر چیزی این ارتباط را شنود کند، با روشن کردن این گزینه کلید را به آن می‌دهید. فقط برای ارائه‌دهنده و شبکه‌ای که به آن اطمینان دارید.",
  },
  "subs.thisSubscription": { en: "this subscription", fa: "این اشتراک" },
  "subs.deleteDialog.title": { en: "Delete V2Ray subscription?", fa: "اشتراک V2Ray حذف شود؟" },
  "subs.deleteDialog.description": {
    en: "This will delete {name} and {count} related V2Ray configs. This action cannot be undone.",
    fa: "{name} و {count} کانفیگ V2Ray مرتبط حذف می‌شوند. این کار قابل بازگشت نیست.",
  },
  "subs.deleteConfirm": { en: "Delete subscription and configs", fa: "حذف اشتراک و کانفیگ‌ها" },

  // The White IP generator. Desktop-only, and the counts are interpolated
  // rather than concatenated: Persian does not put the number where English
  // does, and only the translation can say where it goes.
  "whiteip.resetDefault": { en: "Reset default", fa: "بازگردانی پیش‌فرض" },
  "whiteip.generate": { en: "Generate", fa: "ساختن" },
  "whiteip.generating": { en: "Generating", fa: "در حال ساختن" },
  "whiteip.loading": { en: "Loading", fa: "در حال بارگذاری" },
  "whiteip.importFile": { en: "Import list file", fa: "وارد کردن فایل فهرست" },
  "whiteip.endpoints": { en: "Endpoints", fa: "نقاط اتصال" },
  "whiteip.copied": { en: "Copied", fa: "کپی شد" },
  "whiteip.copyFailed": { en: "Copy failed", fa: "کپی نشد" },
  "whiteip.importing": { en: "Importing", fa: "در حال وارد کردن" },
  "whiteip.importAsProfiles": { en: "Import as V2Ray profiles", fa: "وارد کردن به‌عنوان پروفایل V2Ray" },
  "whiteip.source.title": { en: "Source config", fa: "کانفیگ مبدأ" },
  "whiteip.source.description": {
    en: "Paste one or more V2Ray share links or a WireGuard config.",
    fa: "یک یا چند لینک اشتراک V2Ray یا یک کانفیگ WireGuard را اینجا بگذارید.",
  },
  "whiteip.source.label": { en: "V2Ray config", fa: "کانفیگ V2Ray" },
  "whiteip.list.title": { en: "White IP list", fa: "فهرست آی‌پی سفید" },
  "whiteip.list.count": { en: "{count} endpoint lines", fa: "{count} خط نقطهٔ اتصال" },
  "whiteip.list.none": { en: "No endpoint lines", fa: "هیچ خط نقطهٔ اتصالی نیست" },
  "whiteip.status.generated": { en: "Generated {count} configs.", fa: "{count} کانفیگ ساخته شد." },
  "whiteip.status.imported": {
    en: "Imported {profiles} V2Ray profiles from {endpoints} White IP endpoints.",
    fa: "{profiles} پروفایل V2Ray از {endpoints} نقطهٔ اتصال آی‌پی سفید وارد شد.",
  },
  "whiteip.status.converted": { en: "{count} source profiles converted.", fa: "{count} پروفایل مبدأ تبدیل شد." },
  "whiteip.status.loaded": { en: "Loaded {name}.", fa: "{name} بارگذاری شد." },
  "whiteip.status.reset": { en: "Default WhiteDNS IP list restored.", fa: "فهرست آی‌پی پیش‌فرض WhiteDNS بازگردانده شد." },
  "whiteip.dialog.title": { en: "Generated V2Ray White IP Profiles", fa: "پروفایل‌های آی‌پی سفید ساخته‌شده" },
  "whiteip.dialog.description": {
    en: "{configs} configs from {endpoints} White IP endpoints.",
    fa: "{configs} کانفیگ از {endpoints} نقطهٔ اتصال آی‌پی سفید.",
  },
  "whiteip.dialog.fallback": { en: "Converted V2Ray configs", fa: "کانفیگ‌های V2Ray تبدیل‌شده" },
  "whiteip.dialog.sources": { en: "{count} source profiles", fa: "{count} پروفایل مبدأ" },

  // Full backup. Desktop-only.
  "backup.section": { en: "Backup and restore", fa: "پشتیبان‌گیری و بازگردانی" },
  "backup.card.title": { en: "Profile Backup", fa: "پشتیبان پروفایل‌ها" },
  "backup.card.description": {
    en: "Export or restore all saved WhiteVPN profiles.",
    fa: "برون‌بری یا بازگردانی همهٔ پروفایل‌های ذخیره‌شدهٔ WhiteVPN.",
  },
  "backup.export": { en: "Export", fa: "برون‌بری" },
  "backup.export.title": { en: "Export full backup", fa: "برون‌بری پشتیبان کامل" },
  "backup.export.hint": {
    en: "MasterDNS, V2Ray, resolvers, settings, selected profiles, and saved secrets.",
    fa: "MasterDNS، V2Ray، حل‌کننده‌ها، تنظیمات، پروفایل‌های انتخاب‌شده و کلیدهای ذخیره‌شده.",
  },
  "backup.export.description": { en: "Full profile backup exported as JSON.", fa: "پشتیبان کامل پروفایل‌ها به شکل JSON." },
  "backup.copyJson": { en: "Copy JSON", fa: "کپی JSON" },
  "backup.downloadJson": { en: "Download JSON", fa: "دانلود JSON" },
  "backup.restore": { en: "Restore", fa: "بازگردانی" },
  "backup.restore.fieldTitle": { en: "Restore full backup", fa: "بازگردانی پشتیبان کامل" },
  "backup.restore.hint": {
    en: "Restores are available when WhiteDNS is disconnected.",
    fa: "بازگردانی فقط وقتی ممکن است که اتصال قطع باشد.",
  },
  "backup.restore.title": { en: "Restore Backup", fa: "بازگردانی پشتیبان" },
  "backup.restore.description": {
    en: "Restore replaces saved MasterDNS, V2Ray, resolver, and settings profiles.",
    fa: "بازگردانی، پروفایل‌های ذخیره‌شدهٔ MasterDNS، V2Ray، حل‌کننده و تنظیمات را جایگزین می‌کند.",
  },
  "backup.file": { en: "Backup file", fa: "فایل پشتیبان" },
  "backup.json": { en: "Backup JSON", fa: "JSON پشتیبان" },
  "backup.restored": { en: "Restored backup.", fa: "پشتیبان بازگردانده شد." },

  // The tunnel validator. Desktop-only, and the largest screen in the app.
  "validator.title": { en: "Tunnel Validator", fa: "اعتبارسنج تونل" },
  "validator.input.title": { en: "Endpoint input", fa: "ورودی نقاط اتصال" },
  "validator.tab.quick": { en: "Quick", fa: "سریع" },
  "validator.tab.bulk": { en: "Bulk", fa: "انبوه" },
  "validator.tab.default": { en: "Default list", fa: "فهرست پیش‌فرض" },
  "validator.tab.imported": { en: "Imported file", fa: "فایل واردشده" },
  "validator.host": { en: "Host", fa: "میزبان" },
  "validator.ports": { en: "Ports", fa: "پورت‌ها" },
  "validator.sni": { en: "SNI", fa: "SNI" },
  "validator.ports.hint": {
    en: "Comma or space separated. Each selected range is scanned once per port.",
    fa: "با کاما یا فاصله جدا کنید. هر بازهٔ انتخاب‌شده به‌ازای هر پورت یک بار پویش می‌شود.",
  },
  "validator.range.hint": {
    en: "IP or CIDR range, separated by comma or line.",
    fa: "آی‌پی یا بازهٔ CIDR، جداشده با کاما یا خط جدید.",
  },
  "validator.endpointCount": { en: "{count} endpoints", fa: "{count} نقطهٔ اتصال" },
  "validator.portCount": { en: "{count} ports", fa: "{count} پورت" },
  "validator.noRanges": { en: "No ranges selected", fa: "بازه‌ای انتخاب نشده" },
  "validator.noPorts": { en: "No ports", fa: "بدون پورت" },
  "validator.noPortsSelected": { en: "No ports selected", fa: "پورتی انتخاب نشده" },
  "validator.noPortsSelected.hint": {
    en: "Select at least one port to scan each range.",
    fa: "برای پویش هر بازه دست‌کم یک پورت انتخاب کنید.",
  },
  "validator.tooLarge": { en: "Range selection too large", fa: "بازه‌های انتخاب‌شده بیش از حد بزرگ‌اند" },
  "validator.invalidPorts": { en: "Invalid port list", fa: "فهرست پورت نامعتبر" },
  "validator.filterDefault": { en: "Filter default ranges", fa: "فیلتر بازه‌های پیش‌فرض" },
  "validator.filterImported": { en: "Filter imported ranges", fa: "فیلتر بازه‌های واردشده" },
  "validator.defaultUnavailable": { en: "Default ranges unavailable", fa: "بازه‌های پیش‌فرض در دسترس نیست" },
  "validator.noDefault": { en: "No default ranges", fa: "بازهٔ پیش‌فرضی نیست" },
  "validator.noDefaultMatch": { en: "No default ranges match", fa: "بازهٔ پیش‌فرضی با این شرط نیست" },
  "validator.noImportedMatch": { en: "No imported ranges match", fa: "بازهٔ واردشده‌ای با این شرط نیست" },
  "validator.importToShow": { en: "Import a file to show ranges", fa: "برای دیدن بازه‌ها یک فایل وارد کنید" },
  "validator.inputError": { en: "Validator input error", fa: "خطای ورودی اعتبارسنج" },
  "validator.retries": { en: "Retries", fa: "تعداد تلاش" },
  "validator.timeout": { en: "Timeout ms", fa: "مهلت (میلی‌ثانیه)" },
  "validator.workers": { en: "Scan workers", fa: "کارگرهای پویش" },
  "validator.httpPaths": { en: "HTTP paths", fa: "مسیرهای HTTP" },
  "validator.insecureTls": { en: "Insecure TLS", fa: "TLS ناامن" },
  "validator.progress": { en: "{completed} of {total} endpoints complete", fa: "{completed} از {total} نقطهٔ اتصال کامل شد" },
  "validator.idle": { en: "No validation running", fa: "اعتبارسنجی در جریان نیست" },
  "validator.clear": { en: "Clear", fa: "پاک کردن" },
  "validator.pause": { en: "Pause", fa: "مکث" },
  "validator.resume": { en: "Resume", fa: "ادامه" },
  "validator.scan": { en: "Scan", fa: "پویش" },
  "validator.failed": { en: "Validator failed", fa: "اعتبارسنجی ناموفق بود" },
  "validator.importing": { en: "Importing file", fa: "در حال وارد کردن فایل" },
  "validator.import.imported": { en: "{count} imported", fa: "{count} واردشده" },
  "validator.import.inputs": { en: "{count} inputs", fa: "{count} ورودی" },
  "validator.import.duplicates": { en: "{count} duplicates", fa: "{count} تکراری" },
  "validator.import.invalid": { en: "{count} invalid", fa: "{count} نامعتبر" },
  "validator.import.invalidSample": { en: "Invalid: {list}", fa: "نامعتبر: {list}" },
  "validator.import.none": { en: "No input found.", fa: "ورودی‌ای پیدا نشد." },
  "validator.import.noRanges": {
    en: "Imported file contains no valid IPv4 or CIDR ranges.",
    fa: "فایل واردشده هیچ بازهٔ IPv4 یا CIDR معتبری ندارد.",
  },
  "validator.import.empty": { en: "Imported file is empty.", fa: "فایل واردشده خالی است." },
  "validator.files.title": { en: "Files", fa: "فایل‌ها" },
  "validator.files.description": {
    en: "Previous validator CSV scans. Files stay on disk until deleted.",
    fa: "پویش‌های CSV پیشین. فایل‌ها تا زمان حذف روی دیسک می‌مانند.",
  },
  "validator.files.empty": { en: "No CSV files", fa: "فایل CSVای نیست" },
  "validator.files.empty.hint": {
    en: "Validator runs will appear here after they start.",
    fa: "پویش‌ها پس از شروع اینجا نمایش داده می‌شوند.",
  },
  "validator.files.column.file": { en: "File", fa: "فایل" },
  "validator.files.column.rows": { en: "Rows", fa: "ردیف‌ها" },
  "validator.files.column.size": { en: "Size", fa: "اندازه" },
  "validator.files.open": { en: "Open", fa: "باز کردن" },

  // Diagnostics. Desktop-only: the phone shows no engine output at all.
  "logs.title": { en: "Diagnostics", fa: "عیب‌یابی" },
  "logs.description": { en: "Engine output and health checks.", fa: "خروجی موتور و بررسی‌های سلامت." },
  "logs.search": { en: "Search logs", fa: "جست‌وجو در گزارش‌ها" },
  "logs.copy": { en: "Copy logs", fa: "کپی گزارش‌ها" },
  "logs.save": { en: "Save log", fa: "ذخیرهٔ گزارش" },
  "logs.clear": { en: "Clear logs", fa: "پاک کردن گزارش‌ها" },
  "logs.empty": { en: "No logs found", fa: "گزارشی نیست" },

  // The Servers page: the workbench.
  "servers.description": {
    en: "The same nodes the VPN connects through. Test them, sort them, share them.",
    fa: "همان سرورهایی که وی‌پی‌ان از آن‌ها وصل می‌شود. آزمایش، مرتب‌سازی و اشتراک‌گذاری.",
  },
  "servers.category": { en: "Server category", fa: "دسته‌بندی سرورها" },
  "servers.manual": { en: "Manual", fa: "دستی" },
  "servers.import": { en: "Add configs", fa: "افزودن کانفیگ" },
  "servers.importing": { en: "Adding…", fa: "در حال افزودن…" },
  "servers.import.title": { en: "Add server configs", fa: "افزودن کانفیگ سرور" },
  "servers.import.description": {
    en: "Paste one or more config links. They are saved locally under Manual, not as a subscription. On Servers, you can also paste directly with Cmd+V or Ctrl+V.",
    fa: "یک یا چند لینک کانفیگ را وارد کنید. کانفیگ‌ها در دستهٔ دستی ذخیره می‌شوند، نه به‌عنوان اشتراک. در صفحهٔ سرورها می‌توانید مستقیماً با Cmd+V یا Ctrl+V وارد کنید.",
  },
  "servers.import.placeholder": {
    en: "vless://…\nvmess://…\ntrojan://…",
    fa: "vless://…\nvmess://…\ntrojan://…",
  },
  "servers.import.success": { en: "Added {count} config(s) to Manual.", fa: "{count} کانفیگ به دستهٔ دستی افزوده شد." },
  "servers.notInUse": { en: "not connected through", fa: "اتصال از این دسته نیست" },
  "servers.notInUse.hint": {
    en: "You are looking at another server category. Connecting through one of its servers switches to it.",
    fa: "در حال دیدن دستهٔ دیگری هستید. اتصال از یکی از سرورهای آن، دسته را هم تغییر می‌دهد.",
  },
  "servers.empty": { en: "This category has no servers to show.", fa: "این دسته سروری برای نمایش ندارد." },
  "servers.tests": { en: "Tests", fa: "آزمون‌ها" },
  "servers.test.reach": { en: "Reachable", fa: "در دسترس" },
  "servers.test.delay": { en: "Delay", fa: "تأخیر" },
  "servers.test.speed": { en: "Speed", fa: "سرعت" },
  "servers.testAll": { en: "Test all", fa: "آزمون همه" },
  "servers.testSelected": { en: "Test selected", fa: "آزمون انتخاب‌شده‌ها" },
  "servers.testOptions": { en: "Options", fa: "تنظیمات" },
  "servers.stop": { en: "Stop", fa: "توقف" },
  "servers.selected": { en: "selected", fa: "انتخاب‌شده" },
  "servers.column.node": { en: "Node", fa: "سرور" },
  "servers.column.address": { en: "Address", fa: "آدرس" },
  "servers.column.actions": { en: "Actions", fa: "عملیات" },
  "servers.failed": { en: "failed", fa: "ناموفق" },
  "servers.failed.hint": {
    en: "The test ran and did not succeed. Reachable dials the address directly, without the VPN, so a node that is blocked from here fails it while still working through the engine.",
    fa: "آزمون اجرا شد و موفق نبود. «در دسترس» آدرس را مستقیم و بدون وی‌پی‌ان می‌زند، پس سروری که از اینجا مسدود است در این آزمون رد می‌شود ولی ممکن است از راه موتور کاملاً کار کند.",
  },
  "servers.use": { en: "Connect through this node", fa: "اتصال از این سرور" },
  "servers.share": { en: "Share", fa: "اشتراک‌گذاری" },
  "servers.share.none": {
    en: "This node came from a configuration file, so it has no link to share.",
    fa: "این سرور از یک فایل کانفیگ آمده، پس لینکی برای اشتراک‌گذاری ندارد.",
  },
  "servers.copy": { en: "Copy link", fa: "کپی لینک" },
  "servers.copied": { en: "Link copied.", fa: "لینک کپی شد." },

  // Editing and removing configs added by hand. These never appear on a node
  // from the catalogue or a subscription: that node is a reading of what a
  // provider is serving and comes back at the next refresh, so there is nothing
  // to edit and a delete would undo itself.
  "servers.edit": { en: "Edit", fa: "ویرایش" },
  "servers.edit.title": { en: "Edit config", fa: "ویرایش کانفیگ" },
  "servers.edit.description": {
    en: "Only configs you added yourself can be changed. Fields follow the protocol and transport you choose.",
    fa: "فقط کانفیگ‌هایی که خودتان اضافه کرده‌اید قابل تغییرند. فیلدها بر اساس پروتکل و ترنسپورتی که انتخاب می‌کنید نشان داده می‌شوند.",
  },
  "servers.edit.saving": { en: "Saving…", fa: "در حال ذخیره…" },
  "servers.edit.saved": { en: "Config saved.", fa: "کانفیگ ذخیره شد." },
  "servers.edit.section.basics": { en: "Basics", fa: "مشخصات اصلی" },
  "servers.edit.section.credentials": { en: "Credentials", fa: "اطلاعات ورود" },
  "servers.edit.section.transport": { en: "Transport", fa: "ترنسپورت" },
  "servers.edit.section.tls": { en: "TLS", fa: "TLS" },
  "servers.edit.name": { en: "Name", fa: "نام" },
  "servers.edit.protocol": { en: "Protocol", fa: "پروتکل" },
  "servers.edit.server": { en: "Server", fa: "سرور" },
  "servers.edit.port": { en: "Port", fa: "پورت" },
  "servers.edit.username": { en: "Username", fa: "نام کاربری" },
  "servers.edit.password": { en: "Password", fa: "رمز" },
  "servers.edit.security": { en: "Encryption", fa: "رمزنگاری" },
  "servers.edit.ssMethod": { en: "Method", fa: "روش رمزنگاری" },
  "servers.edit.hysteriaAuth": { en: "Auth", fa: "احراز هویت" },
  "servers.edit.hysteriaMasquerade": { en: "Masquerade", fa: "استتار" },
  "servers.edit.transport": { en: "Transport", fa: "ترنسپورت" },
  "servers.edit.path": { en: "Path", fa: "مسیر" },
  "servers.edit.host": { en: "Host", fa: "هاست" },
  "servers.edit.serviceName": { en: "Service name", fa: "نام سرویس" },
  "servers.edit.xhttpMode": { en: "XHTTP mode", fa: "حالت XHTTP" },
  "servers.edit.xhttpExtra": { en: "XHTTP extra", fa: "تنظیمات اضافهٔ XHTTP" },
  "servers.edit.wsEarlyData": { en: "Early data", fa: "Early data" },
  "servers.edit.wsEarlyDataHeader": { en: "Early data header", fa: "هدر Early data" },
  "servers.edit.fingerprint": { en: "Fingerprint", fa: "اثر انگشت (fingerprint)" },
  "servers.edit.allowInsecure": { en: "Allow insecure", fa: "پذیرش گواهی نامعتبر" },
  "servers.edit.allowInsecure.hint": {
    en: "Accepts a certificate that does not verify. Leave off unless the server needs it.",
    fa: "گواهی‌ای که تأیید نمی‌شود را می‌پذیرد. تا وقتی سرور لازم ندارد، خاموش بماند.",
  },
  "servers.edit.realityPublicKey": { en: "REALITY public key", fa: "کلید عمومی REALITY" },
  "servers.edit.realityShortId": { en: "REALITY short ID", fa: "شناسهٔ کوتاه REALITY" },
  "servers.edit.wgSecretKey": { en: "Private key", fa: "کلید خصوصی" },
  "servers.edit.wgPeerPublicKey": { en: "Peer public key", fa: "کلید عمومی طرف مقابل" },
  "servers.edit.wgPreSharedKey": { en: "Pre-shared key", fa: "کلید مشترک" },
  "servers.edit.wgAddresses": { en: "Local addresses", fa: "آدرس‌های محلی" },
  "servers.edit.wgAllowedIps": { en: "Allowed IPs", fa: "آی‌پی‌های مجاز" },
  "servers.edit.wgReserved": { en: "Reserved", fa: "Reserved" },
  "servers.edit.wgKeepAlive": { en: "Keep-alive (s)", fa: "Keep-alive (ثانیه)" },

  "servers.selectAll": { en: "Select all", fa: "انتخاب همه" },

  // What can be done to a node that belongs to a subscription. Not editing: a
  // refresh rebuilds every one of them, so a change would not survive.
  "servers.copyToManual": { en: "Copy to my configs", fa: "کپی به کانفیگ‌های من" },
  "servers.copyToManual.none": {
    en: "This node came from a configuration file, so there is no link to copy.",
    fa: "این سرور از یک فایل کانفیگ آمده، پس لینکی برای کپی کردن ندارد.",
  },
  "servers.copyToManual.done": {
    en: "{name} copied to your configs, where you can edit it.",
    fa: "«{name}» به کانفیگ‌های شما کپی شد و حالا قابل ویرایش است.",
  },
  "servers.hide": { en: "Hide", fa: "مخفی کردن" },
  "servers.unhide": { en: "Show again", fa: "بازگرداندن" },
  "servers.hideSelected": { en: "Hide {count}", fa: "مخفی کردن {count} مورد" },
  "servers.showHidden": { en: "Show hidden ({count})", fa: "نمایش مخفی‌شده‌ها ({count})" },
  "servers.hideHidden": { en: "Hide them again", fa: "پنهان کردن دوباره" },
  "servers.hide.done": { en: "Hidden {count}.", fa: "{count} مورد مخفی شد." },
  "servers.unhide.done": { en: "Restored {count}.", fa: "{count} مورد بازگردانده شد." },

  "servers.delete": { en: "Delete", fa: "حذف" },
  "servers.delete.title": { en: "Delete config", fa: "حذف کانفیگ" },
  "servers.delete.one": {
    en: "Delete {name}? This cannot be undone.",
    fa: "«{name}» حذف شود؟ این کار برگشت‌پذیر نیست.",
  },
  "servers.delete.many": {
    en: "Delete {count} configs? This cannot be undone.",
    fa: "{count} کانفیگ حذف شود؟ این کار برگشت‌پذیر نیست.",
  },
  "servers.delete.deleting": { en: "Deleting…", fa: "در حال حذف…" },
  "servers.delete.done": { en: "Deleted {count}.", fa: "{count} مورد حذف شد." },
  "servers.deleteSelected": { en: "Delete {count}", fa: "حذف {count} مورد" },
  "servers.option.reachTimeout": { en: "Reachable timeout (ms)", fa: "مهلت در دسترس بودن (ms)" },
  "servers.option.reachWorkers": { en: "Reachable at once", fa: "همزمانی در دسترس بودن" },
  "servers.option.delayTimeout": { en: "Delay timeout (ms)", fa: "مهلت تأخیر (ms)" },
  "servers.option.delayWorkers": { en: "Delay at once", fa: "همزمانی تأخیر" },
  "servers.option.speedBudget": { en: "Speed budget (ms)", fa: "بودجهٔ سرعت (ms)" },
  "servers.option.speedSize": { en: "Speed test size (MB)", fa: "حجم آزمون سرعت (مگابایت)" },
  "servers.option.hint": {
    en: "Reachable dials the address directly, without the VPN and without an engine — so a node blocked from where you are fails it while still working through the engine. Delay and speed run on an engine of their own, so they never disturb a live connection, and speed is one node at a time, so it is capped at 25.",
    fa: "«در دسترس» آدرس را مستقیم می‌زند، بدون وی‌پی‌ان و بدون موتور — پس سروری که از محل شما مسدود است در این آزمون رد می‌شود، در حالی که از راه موتور کاملاً کار می‌کند. تأخیر و سرعت روی موتور جداگانه‌ای اجرا می‌شوند و هرگز اتصال زنده را مختل نمی‌کنند، و سرعت هر بار یک سرور است، پس تا ۲۵ مورد محدود می‌شود.",
  },

  // Telling someone a newer version exists. The app does not download or
  // install anything — it runs as Administrator and nothing it ships is signed,
  // so fetching a binary and running it is not something to do without verified
  // signatures. Whoever is still on an old build is not in the Telegram
  // channel; this is what reaches them.
  // Putting the app back to a fresh install. It exists because a bug that only
  // shows on a first launch is invisible to everyone who has already used the
  // app — which was all of us until a user on a clean install found one.
  "settings.reset.title": { en: "Reset", fa: "بازنشانی" },
  "settings.reset.description": {
    en: "Delete everything this app has saved and start again as if it were newly installed.",
    fa: "همهٔ چیزی که این اپ ذخیره کرده پاک می‌شود و اپ مثل روز نصب از نو شروع می‌کند.",
  },
  "settings.reset.button": { en: "Reset app data", fa: "بازنشانی داده‌های اپ" },
  "settings.reset.confirm.title": { en: "Delete everything?", fa: "همه‌چیز پاک شود؟" },
  "settings.reset.confirm.body": {
    en: "Your settings, subscriptions and saved configs will be deleted. This cannot be undone, and nothing is backed up first — export a backup on the Full Backup page if you want to keep any of it.",
    fa: "تنظیمات، اشتراک‌ها و کانفیگ‌های ذخیره‌شدهٔ شما پاک می‌شوند. این کار برگشت‌پذیر نیست و هیچ پشتیبانی هم گرفته نمی‌شود — اگر می‌خواهید چیزی را نگه دارید، از صفحهٔ Full Backup خروجی بگیرید.",
  },
  "settings.reset.working": { en: "Resetting…", fa: "در حال بازنشانی…" },
  "settings.reset.done": { en: "Everything was deleted. The app is as it was on the day it was installed.", fa: "همه‌چیز پاک شد. اپ مثل روز نصب است." },

  "settings.update.title": { en: "Updates", fa: "بروزرسانی" },
  "settings.update.description": {
    en: "The app checks for a newer version at startup. It never downloads or installs anything by itself.",
    fa: "اپ هنگام اجرا نسخهٔ جدید را بررسی می‌کند. هیچ‌وقت خودش چیزی دانلود یا نصب نمی‌کند.",
  },
  "update.badge": { en: "Update to v{version}", fa: "بروزرسانی به نسخهٔ {version}" },
  "update.available": {
    en: "Version {version} is out. Click to open the download page.",
    fa: "نسخهٔ {version} منتشر شده. برای باز کردن صفحهٔ دانلود کلیک کنید.",
  },
  "update.check": { en: "Check for updates", fa: "بررسی بروزرسانی" },
  "update.checking": { en: "Checking…", fa: "در حال بررسی…" },
  "update.upToDate": { en: "You are on the latest version ({version}).", fa: "شما روی آخرین نسخه هستید ({version})." },
  "update.failed": {
    en: "Could not reach the release list. Connect first and try again.",
    fa: "دسترسی به فهرست نسخه‌ها ممکن نشد. اول وصل شوید و دوباره امتحان کنید.",
  },
  "update.dev": {
    en: "This is a development build, so there is nothing to update to.",
    fa: "این یک بیلد توسعه است، پس چیزی برای بروزرسانی وجود ندارد.",
  },

  "common.close": { en: "Close", fa: "بستن" },
  "common.copy": { en: "Copy", fa: "کپی" },
  "common.cancel": { en: "Cancel", fa: "انصراف" },
  "common.save": { en: "Save", fa: "ذخیره" },
  "common.dismiss": { en: "Dismiss", fa: "بستن" },
  "toast.failed": { en: "Operation failed", fa: "عملیات ناموفق بود" },
  "theme.title": { en: "Theme", fa: "پوسته" },
  "theme.open": { en: "Open appearance settings", fa: "باز کردن تنظیمات ظاهر" },
  "theme.light": { en: "Light", fa: "روشن" },
  "theme.dark": { en: "Dark", fa: "تیره" },
  "theme.system": { en: "System", fa: "سیستم" },
  "nav.source.open": { en: "Open WhiteDNS Telegram channel", fa: "باز کردن کانال تلگرام WhiteDNS" },
  "validator.testEndpointsFrom": { en: "Test endpoints from {file}.", fa: "نقاط اتصال آزمایشی از {file}." },
  "nav.tools": { en: "Tools", fa: "ابزارها" },

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
  "settings.routing.mode": { en: "How traffic reaches the tunnel", fa: "ترافیک چطور به تونل برسد" },
  "settings.routing.systemProxy": { en: "System proxy — the whole machine", fa: "پراکسی سیستم — کل دستگاه" },
  "settings.routing.proxyOnly": { en: "Proxy only — nothing is redirected", fa: "فقط پراکسی — چیزی تغییر نمی‌کند" },
  "settings.routing.tun": { en: "Tunnel (TUN) — the whole machine", fa: "تونل (TUN) — کل دستگاه" },
  "settings.routing.systemProxy.description": {
    en: "This desktop's proxy settings are pointed at the app while it is connected, and put back when it disconnects. Most programs follow them.",
    fa: "تا وقتی متصل هستید، تنظیمات پراکسی این دستگاه به برنامه اشاره می‌کند و هنگام قطع به حالت قبل برمی‌گردد. بیشتر برنامه‌ها از آن پیروی می‌کنند.",
  },
  "settings.routing.proxyOnly.description": {
    en: "Nothing on this machine is changed. The app just listens, and you point one program at it — a browser extension, or Telegram's proxy settings. Everything else goes out normally.",
    fa: "هیچ چیزی روی این دستگاه تغییر نمی‌کند. برنامه فقط گوش می‌دهد و شما یک برنامه را به آن وصل می‌کنید — افزونهٔ مرورگر یا تنظیمات پراکسی تلگرام. بقیه مثل همیشه از مسیر عادی می‌روند.",
  },
  "settings.routing.tun.description": {
    en: "A virtual network adapter carries everything, including programs that ignore proxy settings. Needs Administrator on Windows.",
    fa: "یک کارت شبکهٔ مجازی همه چیز را حمل می‌کند، حتی برنامه‌هایی که تنظیمات پراکسی را نادیده می‌گیرند. روی ویندوز نیاز به دسترسی Administrator دارد.",
  },
  "settings.routing.tun.unavailable": {
    en: "Tunnel (TUN) mode is available on Windows only for now. It needs to run the engine with administrator rights, and that is not implemented on this platform yet.",
    fa: "حالت تونل (TUN) فعلاً فقط روی ویندوز در دسترس است. این حالت باید موتور را با دسترسی مدیر اجرا کند و این کار هنوز روی این سیستم‌عامل پیاده‌سازی نشده است.",
  },
  "settings.routing.port": { en: "Local proxy port", fa: "پورت پراکسی محلی" },
  "settings.routing.port.description": {
    en: "Point your program at {endpoint} — it accepts both HTTP and SOCKS5. If another program already holds this port, connecting will say so rather than quietly moving to another one, which would leave whatever you configured pointing at nothing.",
    fa: "برنامه‌تان را به {endpoint} وصل کنید — هم HTTP و هم SOCKS5 را می‌پذیرد. اگر برنامهٔ دیگری این پورت را گرفته باشد، هنگام اتصال همین را می‌گوید و بی‌سروصدا پورت دیگری انتخاب نمی‌کند، چون آن‌وقت چیزی که تنظیم کرده‌اید به جای خالی وصل می‌ماند.",
  },
  "servers.testEverywhere": { en: "Test all {count} lists", fa: "تست همهٔ {count} فهرست" },
  "servers.testEverywhere.hint": {
    en: "Runs the chosen tests over every subscription in turn, so the results can be compared across all of them. Each list is measured on its own engine, one after another, so this takes about as long as testing each page separately.",
    fa: "تست‌های انتخاب‌شده را روی همهٔ اشتراک‌ها به‌ترتیب اجرا می‌کند تا نتیجه‌ها با هم قابل مقایسه باشند. هر فهرست با موتور خودش و یکی پس از دیگری اندازه‌گیری می‌شود، پس تقریباً به‌اندازهٔ تست جداگانهٔ هر صفحه طول می‌کشد.",
  },
  "servers.export": { en: "Export configs", fa: "خروجی گرفتن از کانفیگ‌ها" },
  "servers.exportSelected": { en: "Export selected ({count})", fa: "خروجی انتخاب‌شده‌ها ({count})" },
  "servers.exportAll": { en: "Export all ({count})", fa: "خروجی همه ({count})" },
  "servers.export.description": {
    en: "{count} configs, one link per line. Paste or import these into another device.",
    fa: "{count} کانفیگ، هر خط یک لینک. این‌ها را در دستگاه دیگری وارد یا الصاق کنید.",
  },
  "servers.export.skipped": {
    en: "{count} were left out — this subscription does not give them share links.",
    fa: "{count} مورد کنار گذاشته شد — این اشتراک برای آن‌ها لینک اشتراک‌گذاری نمی‌دهد.",
  },
  "servers.export.base64": { en: "Base64", fa: "Base64" },
  "servers.export.download": { en: "Save to file", fa: "ذخیره در فایل" },
  "servers.export.copied": { en: "{count} configs copied", fa: "{count} کانفیگ کپی شد" },
  "settings.allowLan": { en: "Share on the local network", fa: "اشتراک روی شبکهٔ محلی" },
  "settings.allowLan.description": {
    en: "Let other devices on this network use this connection — a phone or a television on the same wifi or hotspot. Point them at the address shown on the dashboard once connected.",
    fa: "بگذارید دستگاه‌های دیگر روی این شبکه از این اتصال استفاده کنند — گوشی یا تلویزیون روی همان وای‌فای یا هات‌اسپات. بعد از اتصال، آن‌ها را به آدرسی که در صفحهٔ اصلی نشان داده می‌شود وصل کنید.",
  },
  "settings.allowLan.warning": {
    en: "Anyone else on this network can use it too — nothing asks them for a password. Turn this on for a hotspot or a home network you trust, not for wifi you are a guest on.",
    fa: "هر کس دیگری هم که روی این شبکه باشد می‌تواند از آن استفاده کند — از کسی رمز پرسیده نمی‌شود. این را برای هات‌اسپات خودتان یا شبکهٔ خانگی مورد اعتماد روشن کنید، نه روی وای‌فایی که مهمان آن هستید.",
  },
  "settings.tunnel": { en: "Tunnel (TUN)", fa: "تونل (TUN)" },
  "settings.tunnel.description": {
    en: "The tunnel carries every program on the machine. Turning it on asks for Administrator when connecting, because creating the network adapter needs it. Left off, only programs pointed at the local proxy are carried.",
    fa: "تونل ترافیک همهٔ برنامه‌های دستگاه را حمل می‌کند. روشن کردنش هنگام اتصال دسترسی Administrator می‌خواهد، چون ساختن آداپتور شبکه به آن نیاز دارد. اگر خاموش باشد، فقط برنامه‌هایی که به پراکسی محلی وصل شده‌اند حمل می‌شوند.",
  },
  "settings.killSwitch": { en: "Kill switch", fa: "قطع‌کنندهٔ اضطراری" },
  "settings.killSwitch.description": {
    en: "The kill switch is not built yet, so it stays off. Enforcing it means a firewall rule that has to be removed again on exit, after a crash and on uninstall — a rule that outlives the app would leave you with no internet and no visible cause.",
    fa: "قطع‌کنندهٔ اضطراری هنوز ساخته نشده، پس خاموش می‌ماند. اعمال آن یعنی یک قانون فایروال که باید هنگام خروج، پس از کرش و هنگام حذف برنامه دوباره برداشته شود — قانونی که از خود برنامه عمر بیشتری کند شما را بدون اینترنت و بدون دلیل آشکار رها می‌کند.",
  },

  "settings.security.title": { en: "Security", fa: "امنیت اتصال" },
  "settings.security.description": {
    en: "Checks applied to a server before it is trusted with traffic.",
    fa: "بررسی‌هایی که پیش از سپردن ترافیک به یک سرور انجام می‌شود.",
  },
  "settings.tlsIntegrity": { en: "TLS integrity", fa: "یکپارچگی TLS" },
  "settings.tlsIntegrity.description": {
    en: "After connecting, checks that certificates still verify through the tunnel. A node where they do not is being read, and is refused.",
    fa: "بعد از اتصال بررسی می‌کند که گواهی‌ها از داخل تونل معتبر بمانند. سروری که این بررسی را رد کند در حال شنود شدن است و پذیرفته نمی‌شود.",
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
  "settings.fronting.description": {
    en: "Reach a server through a different address while keeping its name. Up to {max}.",
    fa: "رسیدن به سرور از راه آدرسی دیگر، بدون تغییر نامش. حداکثر {max} مورد.",
  },
  "settings.fronting.tooMany": {
    en: "Up to {max} fronting addresses can be used.",
    fa: "حداکثر {max} آدرس جایگزین می‌توان استفاده کرد.",
  },
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
  "settings.splitTunnel.mode": { en: "Mode", fa: "حالت" },
  "settings.splitTunnel.program": { en: "Program", fa: "برنامه" },
  "settings.splitTunnel.programHint": {
    en: "Matched on the executable's file name, so two programs installed under the same name cannot be told apart.",
    fa: "تطبیق بر اساس نام فایل اجرایی است، پس دو برنامه‌ای که با یک نام نصب شده باشند از هم قابل تشخیص نیستند.",
  },
  "settings.splitTunnel.empty": { en: "No programs selected.", fa: "برنامه‌ای انتخاب نشده." },

  "settings.noise.title": { en: "Obfuscation", fa: "Amnezia Noise" },
  "settings.noise.description": {
    en: "Pad the connection with noise so its shape is less recognisable. Applies to WireGuard servers only — it has no effect on any other kind.",
    fa: "اتصال را با نویز پر می‌کند تا الگویش کمتر قابل تشخیص باشد. فقط روی سرورهای WireGuard اثر دارد و روی بقیهٔ انواع هیچ تأثیری ندارد.",
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
  "settings.language.hint": {
    en: "Persian lays the interface out right to left. The theme is on the button beside the app name.",
    fa: "فارسی چیدمان را راست‌به‌چپ می‌کند. پوستهٔ برنامه روی دکمهٔ کنار نام برنامه است.",
  },


  "common.add": { en: "Add", fa: "افزودن" },
  "common.remove": { en: "Remove", fa: "حذف" },
} satisfies Record<string, Entry>;

export type StringKey = keyof typeof strings;

// What a screen is handed. Named so that adding a parameter to a string does
// not mean widening a signature written out in every page's props.
export type TranslateFn = (key: StringKey, params?: Record<string, string | number>) => string;

export function translate(language: Language, key: StringKey, params?: Record<string, string | number>): string {
  const entry = strings[key];
  if (!entry) {
    return key;
  }
  // Persian falls back to English rather than to the key: a screen part-way
  // through translation should read as mixed language, not as identifiers.
  const text = language === "fa" ? entry.fa || entry.en : entry.en;
  if (!params) {
    return text;
  }
  // `{name}` rather than concatenation at the call site: a sentence with a
  // number in it does not put that number in the same place in both languages,
  // and only the translator can say where it goes.
  return text.replace(/\{(\w+)\}/g, (whole, name: string) => {
    const value = params[name];
    return value === undefined ? whole : String(value);
  });
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
