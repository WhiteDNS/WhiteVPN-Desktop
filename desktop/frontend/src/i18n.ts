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
  "vpn.metric.frontingIp": { en: "Fronting IP", fa: "آی‌پی جایگزین" },
  "vpn.metric.download": { en: "Download", fa: "دریافت" },
  "vpn.metric.upload": { en: "Upload", fa: "ارسال" },
  "vpn.metric.traffic": { en: "Traffic", fa: "ترافیک" },
  "vpn.frontingAuto": { en: "IP fronting auto", fa: "آی‌پی جایگزین خودکار" },
  "vpn.alert.settingsRequired": { en: "Engine settings required", fa: "تنظیمات موتور لازم است" },
  "vpn.alert.settingsRequired.description": {
    en: "Choose a valid local proxy port on the engine settings page before connecting.",
    fa: "پیش از اتصال، در صفحهٔ تنظیمات موتور یک پورت پراکسی محلی معتبر انتخاب کنید.",
  },

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
  "subs.inUse": { en: "In use", fa: "در حال استفاده" },
  "subs.disconnectFirst": { en: "Disconnect first", fa: "اول قطع کنید" },

  // The Servers page: the workbench.
  "servers.description": {
    en: "The same nodes the VPN connects through. Test them, sort them, share them.",
    fa: "همان سرورهایی که وی‌پی‌ان از آن‌ها وصل می‌شود. آزمایش، مرتب‌سازی و اشتراک‌گذاری.",
  },
  "servers.subscription": { en: "Subscription", fa: "اشتراک" },
  "servers.notInUse": { en: "not connected through", fa: "اتصال از این اشتراک نیست" },
  "servers.notInUse.hint": {
    en: "You are looking at another subscription's servers. Connecting through one of them switches to it.",
    fa: "در حال دیدن سرورهای اشتراک دیگری هستید. اتصال از یکی از آن‌ها، اشتراک را هم به همان تغییر می‌دهد.",
  },
  "servers.empty": { en: "This subscription has no servers to show.", fa: "این اشتراک سروری برای نمایش ندارد." },
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
  "servers.copy": { en: "Copy link", fa: "کپی لینک" },
  "servers.copied": { en: "Link copied.", fa: "لینک کپی شد." },
  "servers.option.reachTimeout": { en: "Reachable timeout (ms)", fa: "مهلت در دسترس بودن (ms)" },
  "servers.option.reachWorkers": { en: "Reachable at once", fa: "همزمانی در دسترس بودن" },
  "servers.option.delayTimeout": { en: "Delay timeout (ms)", fa: "مهلت تأخیر (ms)" },
  "servers.option.delayWorkers": { en: "Delay at once", fa: "همزمانی تأخیر" },
  "servers.option.speedBudget": { en: "Speed budget (ms)", fa: "بودجهٔ سرعت (ms)" },
  "servers.option.speedUrl": { en: "Speed test file", fa: "فایل آزمون سرعت" },
  "servers.option.hint": {
    en: "Reachable dials the address directly, without the VPN and without an engine — so a node blocked from where you are fails it while still working through the engine. Delay and speed run on an engine of their own, so they never disturb a live connection, and speed is one node at a time, so it is capped at 25.",
    fa: "«در دسترس» آدرس را مستقیم می‌زند، بدون وی‌پی‌ان و بدون موتور — پس سروری که از محل شما مسدود است در این آزمون رد می‌شود، در حالی که از راه موتور کاملاً کار می‌کند. تأخیر و سرعت روی موتور جداگانه‌ای اجرا می‌شوند و هرگز اتصال زنده را مختل نمی‌کنند، و سرعت هر بار یک سرور است، پس تا ۲۵ مورد محدود می‌شود.",
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
  "settings.language.hint": {
    en: "Persian lays the interface out right to left. The theme is on the button beside the app name.",
    fa: "فارسی چیدمان را راست‌به‌چپ می‌کند. پوستهٔ برنامه روی دکمهٔ کنار نام برنامه است.",
  },

  "settings.engine.title": { en: "Engine settings", fa: "تنظیمات موتور" },
  "settings.engine.description": {
    en: "Listen port, inbound type and the rest of the engine plumbing, which the phone does not expose.",
    fa: "پورت شنود، نوع ورودی و بقیهٔ جزئیات موتور، که نسخهٔ گوشی آن‌ها را نشان نمی‌دهد.",
  },
  "settings.engine.open": { en: "Open engine settings", fa: "باز کردن تنظیمات موتور" },

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
