# پلن اجرایی افزودن ۶ موتور اتصال به WhiteVPN Desktop — Windows

تاریخ بازنگری: ۲۰۲۶-۱۰-۰۴ — ویرایش ۲، پس از بررسی سورس، مرجع انتشار و baseline Windows؛ وضعیت: پلن اجرا، پیش از پیاده‌سازی محصول.

اجرای پلن آغاز شده است؛ وضعیت تحویل و کارهای باقی‌مانده در [گزارش اجرای شش موتور](/E:/projects/WhiteVPN-Desktop/docs/implementation/SIX-ENGINES-STATUS_FA.md) ثبت می‌شود. وجود این پلن به معنی تکمیل مراحل نیست.

پروژهٔ مقصد: `E:\projects\WhiteVPN-Desktop`؛ پروژهٔ مرجع: `E:\projects\WhiteVPN`.

هدف قطعی: **هر شش خانوادهٔ SSH، Psiphon، Tor، DNS tunnels، AmneziaWG و IKEv2 به‌صورت موتور قابل استفاده به نسخهٔ دسکتاپ ویندوز اضافه شوند**؛ کاربر بتواند پروفایل بسازد، ذخیره/ویرایش/حذف کند، انتخاب کند و با آن اتصال واقعی برقرار کند. خانوادهٔ DNS شامل DNSTT، VayDNS و MasterDNS است. Mihomo موتور موجود باقی می‌ماند و جزو این شش موتور جدید شمرده نمی‌شود.

اتصال‌های فعلی Mihomo، ساب‌اسکریپشن‌ها و امکانات اختصاصی دسکتاپ حفظ شوند. خروجی پایه باید هر شش خانواده را با حداقل قابلیت‌های جدول بخش ۳.۱ تحویل دهد؛ فرم، placeholder یا نام یک موتور با backend همیشه unavailable، تحویل آن موتور محسوب نمی‌شود. برابری کامل همهٔ زیرقابلیت‌های اندروید، خروجی تکمیلی همین برنامه با پذیرش جداست.

## ۱. مرجع تثبیت‌شده و شواهد بررسی

مرجع سورس Android، commit **`bf4adc5f72b36b9443ae5457782f4f1648984efc`** با `versionName=1.7.0-beta.1` و `versionCode=86` است. [صفحهٔ رسمی انتشار](https://github.com/WhiteDNS/WhiteVPN/releases/tag/v1.7.0-beta.1) همین commit را معرفی می‌کند. checkout مربوط در `E:\projects\WhiteVPN\build\engines\pr-integration` موجود است، اما working tree آن تغییرات پس از انتشار دارد؛ فایل مرجع با `git show <commit>:<path>` خوانده شود.

checkout اصلی Android با نسخهٔ 1.6.7/code83 و HEAD `5f05cde…` فقط سابقهٔ بررسی است. در مقایسهٔ ۱۵ فایل اصلی آن با commit انتشار، ۱۳ فایل برابر و دو فایل IKE controller و SavedProfilesUi متفاوت بودند. تغییرات بعدی مانند AmneziaTuning بدون بررسی مستقل وارد محدودهٔ مرجع نمی‌شوند.

| مبنا | وضعیت هنگام بررسی |
| --- | --- |
| Android release | `bf4adc5f72b36b9443ae5457782f4f1648984efc`؛ سورس immutable، نسخهٔ 1.7.0-beta.1/code86 |
| Desktop HEAD | `ee482dc8a7638e4ece21adb2bbe05b31ae1dff94`؛ پیش از ایجاد این سند، working tree تمیز بود |
| مشخصات تغییرات اندروید | `docs/specs/connection-engines.md` در commit انتشار، همراه manifestها و patchهای همان commit |
| معماری دسکتاپ | Go، Wails v2، React/TypeScript؛ ماژول فعلی Wails در `desktop/go.mod` نسخهٔ `v2.15.0` دارد |
| سند parity قدیمی | `desktop/ANDROID-PARITY.md`؛ به‌عنوان سابقهٔ رفتار فعلی استفاده شود، نه فهرست کامل امکانات جدید |

دو APK محلی ARM64 با version/code یکسان وجود دارند: خروجی مطابق رکورد publication محلی با SHA-256 `c703c66183fb0e0149e193266c65c5ee7cd6f0d5a0de5cd9d0439250d4e01494` و rebuild دیگر با `a99e1e82049497c6af304b1bab7cfa92fda35a17f9f8c65ed1f0cae4abb118c0`. metadata و امضای هر دو بررسی شده؛ hash asset جاری GitHub مستقلاً دریافت نشده است. P0 باید artifact منتخب و این محدودیت را در manifest ثبت کند؛ شمارهٔ نسخه به‌تنهایی هویت artifact نیست.

گزارش مبنا: [بررسی کامل](/E:/projects/WhiteVPN-Desktop/docs/reviews/WINDOWS-ANDROID-1.7.0-BETA1-REVIEW_FA.md) و [شواهد و روش اجرای baseline](/E:/projects/WhiteVPN-Desktop/docs/reviews/windows-android-1.7.0-beta1-baseline/README.md). در بازنگری، Desktop build/vet، TypeScript و frontend build موفق بودند؛ ۵۸۱ تست پاس، صفر شکست و ۸ skip ثبت شد. این نتایج پذیرش شبکهٔ واقعی یا بستهٔ release نیستند.

یادداشت‌های README و `memory.md` در بعضی موارد از کد عقب‌تر هستند. برای مثال، کد فعلی `mihomoconf/config.go` گزینهٔ `AllowLAN` را اعمال می‌کند؛ پس LAN را نباید قابلیت کاملاً غایب فرض کرد. در مقابل، در مسیر بررسی‌شدهٔ Render احراز هویت LAN تولید نمی‌شود و به تکمیل نیاز دارد. همچنین وجود مدل‌ها و لاگ‌های قدیمی MasterDNS، اثبات وجود backend فعال و هم‌ارز نسخهٔ جدید نیست.

## ۲. دامنه و قواعد اصلی

### در دامنهٔ این انتقال

- صفحهٔ یکپارچهٔ «پروفایل‌ها» برای منابع Mihomo، لینک‌های اتصال و پروفایل‌های موتورهای مستقل.
- ساخت، ویرایش، حذف، انتخاب و تست SSH، Psiphon، Tor، DNS tunnels، AmneziaWG و IKEv2.
- تنظیمات متناسب با موتور انتخاب‌شده، همراه با توضیح گزینه‌های غیرفعال.
- import فایل `.conf` و لینک `vpn://` برای AmneziaWG.
- نگهداری امن اطلاعات حساس، مالکیت واحد اتصال، پاک‌سازی تأییدشده و حذف اثر callbackهای قدیمی.
- نمایش صادقانهٔ آمادگی اتصال، سرعت، خطا، وضعیت پشتیبانی معماری و محدودیت UDP.
- فرم‌های فارسی/انگلیسی، روشن/تاریک و اصلاح رفتار فیلدهای طولانی و دکمهٔ نمایش رمز.
- ساخت و بسته‌بندی Windows x64 و Windows ARM64، همراه با جدول پشتیبانی واقعی هر موتور.

هدف محصول در این سند Windows است. x64 مسیر اول تحویل و ARM64 هدف تحویل مستقل با همان شش خانوادهٔ پایه است. بستهٔ x64 می‌تواند پس از پذیرش خودش release candidate شود؛ تا تکمیل پذیرش ARM64، پروژهٔ دو معماری کامل محسوب نمی‌شود. macOS/Linux در این انتقال تعهد افزودن شش موتور ندارند؛ build و رفتار فعلی آن‌ها حفظ می‌شود.

### قواعدی که نباید تغییر کنند

1. **Save، Select و Connect سه عمل جدا هستند.** ذخیرهٔ پروفایل اتصال یا انتخاب خودکار ایجاد نمی‌کند.
2. انتخاب یک پروفایل هنگام اتصال، فقط انتخاب بعدی را تغییر می‌دهد؛ اتصال جاری تا اقدام صریح کاربر ادامه دارد. «انتخاب‌شده» و «در حال استفاده» باید جدا نمایش داده شوند.
3. خطا در یک موتور باعث انتخاب موتور دیگر یا اتصال DIRECT پنهانی نمی‌شود. fallback فعلی در مسیر ساب‌اسکریپشن Mihomo از این قاعده مستقل است و فقط در همان محدودهٔ فعلی باقی می‌ماند.
4. حذف پروفایل انتخاب‌شده، انتخاب را unresolved می‌کند؛ برنامه سرور دیگری انتخاب نمی‌کند. حذف/ویرایش پروفایل فعال باید تا توقف اتصال مسدود باشد یا با اقدام صریح توقف و سپس ویرایش انجام شود.
5. در هر زمان فقط یک اتصال اصلی مالک proxy، TUN، route و DNS است. تست مستقل مالک اتصال اصلی نیست و حق تغییر شبکهٔ سیستم را ندارد.
6. controller و listener داخلی DNS روی loopback می‌مانند. اشتراک LAN فقط برای proxy ورودیِ مجاز و با احراز هویت فعال می‌شود.
7. حالت native به Proxy یا Proxy-only تبدیل نمی‌شود. انتخاب نامعتبر قبل از توقف اتصال جاری توضیح داده و رد می‌شود.
8. تغییر موتور، تنظیمات قبلی DNS، routing، country، chain و WireGuard override را پاک یا بازنویسی نمی‌کند؛ تنها اثرگذاری آن‌ها تغییر می‌کند.
9. محدودیت‌های اندروید که ناشی از API/ABI آن هستند، عیناً به ویندوز تحمیل نمی‌شوند؛ قابلیت ویندوز با build و تست خودش تعیین می‌شود.

### خارج از این کار یا پروژهٔ مستقل

- استقرار سرورهای کاربر، مهاجرت خودکار کلیدهای Android Keystore، و sync بین دستگاه‌ها.
- cross-engine chain و fallback بین موتورهای مستقل؛ chain و Automatic node selection فعلی، Mihomo-only می‌مانند.
- افزودن OpenConnect؛ در اندروید بازنشسته شده و فقط خواندن/حذف رکورد قدیمی آن مجاز است.
- بازگرداندن مسیر Xray/sing-box، انتقال UI گوشی/TV یا Quick Settings اندروید، و افزودن Firebase به دسکتاپ.
- اجرای کامل این قابلیت‌ها روی macOS/Linux؛ build و رفتار فعلی آن‌ها باید بدون regression باقی بماند و گزینه‌های Windows-only صریحاً unavailable باشند.
- ساخت kill switch جدید، قابلیت مستقلی با طراحی WFP و پذیرش جداست. این انتقال نباید scaffolding فعلی را به‌عنوان حفاظت فعال نمایش دهد یا آن را هنگام تعویض موتور دور بزند.

## ۳. فهرست قابلیت‌ها و فاصلهٔ فعلی ویندوز

| قابلیت مرجع اندروید | وضعیت مشاهده‌شدهٔ دسکتاپ | خروجی مورد نیاز |
| --- | --- | --- |
| Profiles یکپارچه | صفحهٔ ساب‌اسکریپشن و Servers وجود دارد؛ مجموعهٔ جدید engine profiles وجود ندارد | یک فهرست و یک انتخاب اصلی، با حفظ workbench سرورها |
| کارت Profile در Home | کنترل‌های انتخاب منبع/نود قدیمی | یک ردیف Profile؛ تنظیمات نود، location و chain در جای مرتبط با Mihomo |
| CRUD و تست موتورهای مستقل | API و lifecycle عمومیِ این مجموعه وجود ندارد | مدل نوع‌دار، vault، Wails API و UI مشترک |
| SSH مستقل | backend هم‌ارز در مسیر فعال دیده نشد | رمز/کلید خصوصی، تأیید fingerprint، SOCKS TCP |
| Psiphon | backend هم‌ارز دیده نشد | Auto/CDN/Direct، انتخاب کشور و bootstrap امضاشده |
| Tor | backend هم‌ارز دیده نشد | Direct/default/custom bridges، obfs4/Snowflake/Conjure و progress |
| DNSTT و VayDNS | backend هم‌ارز دیده نشد | adapter ویندوز zeddns و resolver transports |
| MasterDNS | مدل/import/test و اجزای قدیمی موجودند | بررسی reuse، adapter واقعی و هماهنگی با session manager |
| AmneziaWG native v3 | WireGuard outbound/noise در Mihomo موجود است؛ native backend جدا نیست | backend مستقل، driver، route/DNS/MTU و import |
| IKEv2 native | controller هم‌ارز وجود ندارد | controller ویندوز و نگاشت واقعی احراز هویت |
| انتخاب کشور Psiphon | location موجود مربوط به Mihomo است | dropdown مستقل با metadata کشورها |
| ذخیرهٔ رمزگذاری‌شدهٔ engine profiles | state و backup فعلی JSON هستند | vault جدا؛ API عمومی بدون secret |
| قابلیت‌های مؤثر هر موتور | تنظیمات فعلی عمدتاً Mihomoمحور | capability policy مشترک backend/frontend/tray |
| traffic هر موتور | metrics Mihomo و samplerهای دیگر موجودند | منبع مشخص، session ID، timestamp و unavailable صریح |
| shutdown و switch امن | مسیر `stopMihomo` فعلی برای چند backend طراحی نشده | توقف تأییدشده، state machine و journal منابع |
| LAN authenticated | `AllowLAN` و bind فعلی وجود دارند | تکمیل authentication و محدودیت firewall/listener |
| فرم‌های یکدست و رمز طولانی | React و RTL فعلی موجودند | editor مشترک با regression تصویری و رفتار draft |

### ۳.۱. حداقل تحویل الزامی هر موتور

در جدول، «الزامی» برای Windows x64 و ARM64 است و باید با artifact همان معماری و runtime واقعی پذیرفته شود. هر شش خانواده required هستند. unavailable فقط وضعیت توسعه یا زیرقابلیت تکمیلی حل‌نشده است؛ جایگزین تحویل خانواده نیست.

| موتور | backend و حداقل قابلیت الزامی | زیرقابلیت تکمیلی برای parity |
| --- | --- | --- |
| SSH | adapter Go؛ password و private key/passphrase، host-key trust، SOCKS TCP، Proxy/Proxy-only/TUN از Mihomo | corpus همهٔ فرمت‌های کلید پذیرفته‌شدهٔ مرجع |
| Psiphon | worker مستقل؛ Auto/CDN/Direct، کشور خروج، bootstrap امضاشده، SOCKS TCP و سه mode دسکتاپ | تطبیق همهٔ notice/configهای مؤثر مرجع |
| Tor | Tor daemon و transport process؛ Direct، default/custom bridges، obfs4 و Snowflake، SAFECOOKIE، progress و SOCKS TCP | Conjure پس از Windows port و پذیرش واقعی |
| DNS tunnels | worker با DNSTT، VayDNS و MasterDNS؛ فیلدهای فعال مرجع، resolver transports مرتبط و SOCKS TCP | گزینه‌های فقط partner که در مسیر فعال مرجع نیستند، خارج از تعهد parity اولیه |
| AmneziaWG | helper native AWG v3؛ `.conf`/`vpn://` import، TUN، TCP/UDP، AllowedIPs، DNS، MTU و counter واقعی | app split با include/exclude و راهکار WFP اثبات‌شده |
| IKEv2 | Windows VPN/RAS؛ EAP-MSCHAPv2 و یک مسیر certificate-based اثبات‌شده، identity/CA validation، native routing و توقف owned session | PSK و سایر identity/authهای مرجع که نیازمند backend جایگزین باشند |

برای IKEv2، مسیر دقیق certificate-based در P0b با fixture انتخاب و ثبت می‌شود؛ EAP-TLS و machine certificate معادل فرض نشوند. در صورت شکست مسیر platform، کار رفع یا adapter جایگزین تعریف شود؛ خانواده از برنامه حذف نشود. همین قاعده برای Tor core ARM64 نیز اعمال می‌شود.

### ۳.۲. آنچه اکنون دربارهٔ build می‌دانیم

با Go 1.26.5، `CGO_ENABLED=0` و target Windows، پکیج‌های Psiphon، zeddns، MasterDNS و AWG `device/tun` برای x64/ARM64 کامپایل شدند؛ executableهای obfs4 و Snowflake نیز ساخته شدند. این‌ها helper نهایی یا پذیرش runtime نیستند.

Conjure در هر دو target به‌علت استفادهٔ `int(fd.Fd())` در API Windowsِ `syscall.SetsockoptInt` در dependency DTLS شکست خورد. کار اجرایی آن: patch جدا برای socket/NAT، تست semantics Windows، rebuild هر دو معماری و سپس آزمون end-to-end. تا آن زمان زیرقابلیت Conjure unavailable است، ولی Tor با transportهای الزامی باید تحویل شود.

Tor C core در این بررسی ساخته نشده است. بستهٔ رسمی Windows ARM64 در صفحهٔ upstream مشاهده نشد؛ build native ARM64 با OpenSSL/libevent، hash/licence و تست سخت‌افزار، task الزامی ARM64 است. fallback به اجرای x64 روی ARM64، تأیید پشتیبانی native محسوب نمی‌شود.

### ۳.۳. هم‌ترازی Mihomo پیش از اتصال موتورهای جدید

Desktop فعلی Mihomo 1.19.29 با FlClash pin/patch قدیمی دارد؛ مرجع انتشار Android از Mihomo 1.19.30، upstream `ac017cdd246ce8bd547653d927e7bf77d7ee73d5`، FlClash `ac2f6b919ec1ad395b61b4bb1e714a39c750babe`، patchهای محلی و Go 1.26.8 استفاده می‌کند.

کار P0c: استخراج delta رفتار AWG3 outbound، config/controller policy، socket cleanup و سلامت اتصال؛ انتخاب baseline core سازگار Windows و ثبت patchها. محدودیت‌های ثابت port/TUN/DNS اندروید مستقیماً منتقل نشوند؛ dynamic port و native TUN دسکتاپ حفظ شوند. معیار پذیرش، golden config و رفتار است، همراه نسخه/commit دقیق. اگر core جدید انتخاب شد، regression موجود پیش از integration پاس شود.

## ۴. معماری پیشنهادی

### ۴.۱. مدل انتخاب و پروفایل

- `RouteProfileRef` به‌صورت union نوع‌دار: `mihomo {sourceId, nodeFingerprint}` یا `engine {profileId}`. مقدار پیش‌فرض در migration باید همان انتخاب قبلی باشد.
- `EngineProfile` با UUID ثابت، `schemaVersion`، `kind`، نام و config نوع‌دار. نوع‌های config: SSH، Psiphon، Tor، DNS، AmneziaWG و IKEv2؛ secretها از metadata عمومی جدا باشند.
- منابع ویژهٔ فعلی مانند `all`، `manual` و دو catalogue داخلی حفظ شوند؛ مجموعهٔ `all` فقط منابع Mihomo را جمع می‌کند و موتورهای مستقل را وارد pool خودکار نمی‌کند.
- انتخاب Mihomo حتی با source ID قبلی باید reference موتور مستقل را پاک کند؛ stale engine ID نباید بر انتخاب جدید غالب بماند.
- profile version نامعتبر و kind ناشناخته با خطای روشن متوقف شوند؛ رکورد legacy OpenConnect قابل حذف و unavailable باشد.
- مدل `EngineAvailability` شامل علت دقیق: binary missing، architecture unsupported، driver missing، auth unsupported، certificate unavailable، retired و experimental/unverified.
- `EngineCapabilities` و `EffectiveSettings` در Go محاسبه شوند و تنها همین نتیجه به UI و tray برود؛ frontend مستقلاً قواعد پشتیبانی را حدس نزند.

- `ActiveSessionPlan` snapshot ثابت از RouteProfileRef، profile revision، node/country انتخاب‌شده، mode، effective settings و resource owner باشد. watchdog و traffic از این snapshot بخوانند؛ selected state قابل تغییر، policy اتصال فعال را تغییر ندهد.
- APIهای فعلی `SaveWhiteVPNSelection` و `SelectSubscription` بازنویسی شوند: اولی اکنون انتخاب را به live session اعمال می‌کند و دومی انتخاب هنگام اتصال را رد می‌کند. هر دو انتخاب بعدی را ثبت کنند. جابه‌جایی اتصال فعال فقط با Connect/Switch صریح انجام شود؛ workbench نیز همین قرارداد را مصرف کند.

### ۴.۲. اتصال و مالکیت منابع

یک `SessionManager` جایگاه مشترک اتصال اصلی باشد و مسیر فعلی Mihomo از طریق adapter به آن وصل شود. backendها حداقل قرارداد زیر را داشته باشند:

```text
Validate(profile, platform) -> validation
Preflight(profile, requestedMode) -> availability + effectiveSettings
Prepare(sessionID, profile) -> preparedResources
Start(sessionID, preparedResources) -> cancellable startup
WaitReady(sessionID) -> routed readiness evidence
Traffic(sessionID) -> scoped sample | unavailable
Stop(sessionID) -> confirmed cleanup | release pending
```

state machine: `Disconnected -> Connecting -> Connected -> Stopping -> Disconnected`؛ خطا به `Failed` می‌رود، اما مالکیتِ نامطمئن همچنان `release pending` باقی می‌ماند و شروع بعدی را مسدود می‌کند.

روال switch: snapshot هدف و preflight بدون دست‌زدن به اتصال جاری؛ لغو و join تست/startupهای درگیر؛ توقف اتصال قدیمی؛ تأیید آزادشدن همهٔ منابع؛ سپس Prepare/Start هدف. عملیات serialize شود. rollback یعنی حذف منابع ایجادشده در تلاش ناموفق؛ restart اتصال قبلی یا تغییر موتور باید اقدام صریح کاربر باشد.

هر event، probe و metric شامل `sessionID`/generation باشد. نتیجهٔ دیررس startup قبلی، شمارندهٔ backend قدیمی یا پاسخ تست حذف‌شده نتواند اتصال جدید را Connected کند. context شروع با context عمر اتصال جدا باشد؛ اتمام درخواست Wails نباید core موفق را بکشد.

adapter Mihomo باید خطای Close را به manager برگرداند؛ `stopMihomo` فعلی که owner را پاک و خطا را نادیده می‌گیرد، مستقیماً reuse نشود. session بعدی فقط پس از تأیید پایان قبلی adopt شود. timeout توقف، owner و journal را حفظ کند و حالت `release pending` بدهد؛ status Failed اجازهٔ reset/restore/start جدید نیست.

یک coordinator برای تست‌های جدید، node workbench، V2Ray profile tests و validator ایجاد شود؛ لغو همراه join و deadline باشد. ResetAppData، ImportBackup، حذف profile فعال و shutdown از gate مالکیت مشترک استفاده کنند. control operationها serialize شوند، ولی mutex عمومی AppState هنگام انتظار UAC/network/stop نگه داشته نشود. نتیجهٔ async پیش از commit با generation دوباره تطبیق داده شود.

### ۴.۳. مسیرهای ترافیک

```text
Mihomo source -> session فعلی Mihomo -> proxy/system-proxy یا TUN
SSH/Psiphon/Tor/DNS -> SOCKS روی loopback -> پروفایل synthetic Mihomo -> proxy یا TUN
AmneziaWG -> helper native -> adapter/route/DNS مستقل
IKEv2 -> Windows VPN controller -> اتصال متعلق به WhiteVPN
```

برای SOCKS، config مصنوعی فقط همان endpoint را داشته باشد؛ گروه Automatic/fallback به serverهای دیگر ساخته نشود. ترافیک proxyشدهٔ UDP باید reject شود. اگر کاربر DIRECT rule صریح دارد، اثر آن جداگانه و با ترتیب rule مشخص تست شود. DoH/DoT برنامه‌ها از مسیر انتخاب‌شده عبور کند؛ UDP مربوط به bootstrap/transport خود موتور با UDP برنامه‌ها یکسان فرض نشود.

### ۴.۴. process و دسترسی ویندوز

- UI و WebView2 با `asInvoker` اجرا شوند؛ فقط helper مورد نیاز TUN/route/driver elevated باشد.
- SSH می‌تواند در Go با adapter داخلی شروع شود؛ Psiphon/DNS/Tor/AWG ترجیحاً helper یا subprocess مستقل داشته باشند. JNI، `.aar` و controllerهای Android مستقیماً منتقل نمی‌شوند.
- چند runtime یا کتابخانهٔ native ناسازگار در یک DLL مشترک بارگذاری نشوند. دلیل جداسازی در ویندوز عمدتاً lifecycle، crash isolation و مرز دسترسی است؛ محدودیت خاص چند Go runtime اندروید الزام یکسانی برای Go دسکتاپ نیست.
- IPC با named pipe تصادفی، ACL کاربر دقیق + SYSTEM/Administrators و handshake شامل nonce/sessionID/version باشد؛ هویت peer و PID helper بررسی شود. secrets در argv، environment عمومی یا فایل log ارسال نشوند.
- helper elevated از مسیر دارای ACL مناسب و مالکیت مورد انتظار اجرا شود؛ verification باینری و جلوگیری از جایگزینی آن بین verify و exec لازم است. صرف hash روی فایل user-writable، مرز privilege امن نمی‌سازد.
- مسیر protected helper و نصب/به‌روزرسانی آن در P2 آماده شود؛ استخراج فعلی زیر AppData کاربر برای این مرز کافی نیست. MSI فایل privileged را در محل محافظت‌شده قرار دهد؛ ZIP برای mode نیازمند elevation، bootstrap نصب protected داشته باشد. UI همچنان asInvoker است. آماده‌شدن این primitive به P9 موکول نشود.
- از Job Object برای process tree استفاده شود؛ رفتار childهای elevated و UAC با admin account متفاوت باید روی ویندوز اثبات شود. در صورت استفاده از Kill-on-close، خروج والد کل درخت را خاتمه می‌دهد؛ اما پاک‌شدن route/DNS جداگانه تأیید شود. [مستند Microsoft Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- launchها hidden باشند؛ cancel کردن UAC به خطای قابل فهم و بدون تغییر شبکه منجر شود.
- فایل journal منابع شامل owner، sessionID، adapter ID، routeهای افزوده و تغییرات DNS باشد؛ secret در آن ذخیره نشود. recovery فقط منابع متعلق به WhiteVPN را پاک کند و تنظیمات سایر VPNها را تغییر ندهد.
- intent و شناسهٔ owner پیش از mutation ثبت و پس از هر مرحله durable شود؛ crash بین ایجاد resource و نوشتن نتیجه با owner identifier قابل reconciliation باشد. Job Object باید روی process handle مسیر elevated هم اعمال شود؛ callback فعلی مخصوص `exec.Cmd` برای اثبات این مسیر کافی نیست.

## ۵. ذخیره‌سازی امن، migration و backup

### طراحی vault

**تصمیم scope:** در Windows، secretهای شش موتور جدید و credentialهای ذخیره‌شدهٔ موجود که برای اتصال استفاده می‌شوند، به vault منتقل شوند؛ افزودن secret جدید به AppState عمومی ممنوع است. inventory شامل encryption key، UUID/password اتصال‌های manual/link، SOCKS password، tokenهای subscription URL و raw config حاوی کلید است. اطلاعات عمومی node/source/preferences در metadata باقی می‌ماند.

مدل داخلی persistence با `PublicAppState` جدا شود؛ GetAppState، خروجی save APIها و eventها فقط DTO عمومی بدهند. editor و export صریح، API محدود خودشان را داشته باشند. frontend برای ویرایش credential موجود به API editor متکی شود و مقدار masked/حذف‌شده را روی credential سالم overwrite نکند. برای macOS/Linux تغییر Public DTO و API به‌صورت سازگار اعمال شود؛ persistence فعلی آن‌ها حفظ می‌شود و ادعای DPAPI یا vault جدید برای آن‌ها نمی‌شود. شش backend جدید در این مرحله Windows-only هستند.

metadata نسخهٔ جدید فقط شناسه، نام، kind، version، انتخاب‌ها و preferenceهای عمومی را نگه دارد. vault زیر مسیر config خود WhiteVPN و برای هر کاربر با DPAPI user scope محافظت شود؛ `CRYPTPROTECT_LOCAL_MACHINE` استفاده نشود. DPAPI معمولاً به همان credential کاربر و دستگاه وابسته است؛ رفتار roaming profile نیز در پیام بازیابی لحاظ شود. [مستند CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)

- حفاظت کل payload حساس یا envelope با کلید تصادفی AES-GCM که توسط DPAPI محافظت شده؛ تصمیم نهایی پس از نمونهٔ اولیه و تست ذخیرهٔ atomic ثبت شود.
- DACL محدود، write به فایل موقت و replace اتمیک؛ قطع برق یا disk-full نباید نسخهٔ سالم قبلی را از بین ببرد.
- corruption، key loss یا کاربر نامعتبر باید fail closed شود؛ رفتار فعلی Store که بعضی خطاهای JSON را به state پیش‌فرض تبدیل می‌کند، برای vault تکرار نشود.
- decrypt در context کاربر اصلی انجام شود؛ helper elevated با حساب دیگر نباید به decrypt همان vault وابسته باشد. secret لازم تنها از IPC احراز‌شده به session مربوط ارسال شود.
- `GetAppState`، eventها، لیست پروفایل‌ها و previewها هیچ رمز/کلید/config کامل نداشته باشند. editor با API محدود و فقط هنگام بازکردن فرم اطلاعات لازم را دریافت کند؛ draft در حافظه باشد و در localStorage/sessionStorage ذخیره نشود.
- رمز، key passphrase، private key، PSK، AWG config، Tor cookie و raw native errors از diagnostics حذف شوند. تضمین پاک‌کردن کامل همهٔ کپی‌های secret از heap Go/JavaScript داده نشود؛ طول عمر و تعداد کپی‌ها محدود شود.

### تراکنش persistence و محافظ downgrade

storage جدید در مسیر versioned مانند `state-v2/` قرار گیرد؛ binary قدیمی همان `state.json` legacy را می‌شناسد و به مسیر جدید دسترسی منطقی ندارد. check نسخه در binary جدید لازم است، اما به‌تنهایی محافظ downgrade نیست.

قرارداد پیشنهادی commit: هر revision دارای metadata و vault immutable همان generation باشد؛ ابتدا vault جدید نوشته و decrypt/verify شود، سپس metadata همان generation و در پایان pointer کوچک `current.json` با replace اتمیک commit شود. reader فقط generation کاملِ اشاره‌شده را بخواند. writeها زیر lock واحد انجام شوند؛ generation قبلی تا commit و تأیید recovery حفظ شود. crash پیش از pointer، state قبلی را نگه دارد؛ crash بعد از pointer، pair جدید را انتخاب کند. حذف generation orphan فقط پس از بررسی reference و retention انجام شود. Windows flush/replace و disk-full با fault injection اثبات شوند؛ atomic یک فایل به معنی atomic دو فایل نیست.

pointer یا generation خراب به default state یا import خودکار legacy تبدیل نشود؛ خطای recovery نمایش داده شود و تنها generation قبلیِ کامل و verified طبق سیاست ADR قابل بازیابی باشد. دادهٔ خراب برای تشخیص نگه‌داری شود و write جدید روی آن انجام نشود.

تصمیم به envelope واحد encrypted برای کل catalog به‌جای pair، فقط اگر همان تضمین‌ها و API عمومی را ساده‌تر و با evidence حفظ کند در ADR ثبت شود. save، delete، migration و restore همگی از یک transaction primitive استفاده کنند.

### migration بدون از دست رفتن داده

1. schema جدید را versioned و idempotent تعریف کن؛ state نسخهٔ قبلی را بخوان و snapshot بازیابی را با DPAPI رمزگذاری و محدود به همان کاربر ذخیره کن.
2. source ID، node fingerprint، chain، hidden nodes، resolverها، manual profiles و preferenceهای فعلی را عیناً نگه دار.
3. اگر credential قدیمی MasterDNS به vault منتقل می‌شود، ابتدا vault را بنویس و دوباره decrypt/verify کن، سپس pointer جدید را commit کن و plaintextِ منبع را حذف کن؛ rollback نباید صرفاً به state پیش‌فرض ختم شود.
4. برای profileهای ناقص، duplicate و orphan گزارش migration ارائه کن؛ دادهٔ نامعتبر به موتور دیگری تبدیل نشود.
5. upgrade دوم همان نتیجه را بدهد. reader جدید بعد از commit دوباره legacy را به‌طور خودکار import نکند. اجرای نسخهٔ قدیمی می‌تواند فایل legacy خودش را بنویسد، اما دادهٔ `state-v2` و vault جدید را overwrite نمی‌کند. import تغییرات بعدی legacy فقط اقدام صریح کاربر باشد.
6. پس از تأیید commit جدید، plaintext credential در فایل legacy و snapshot غیررمزگذاری‌شدهٔ متعلق به برنامه حذف/جایگزین شود. تضمین secure erase فیزیکی SSD داده نشود. رفتار downgrade ممکن است ورود دوبارهٔ credential در نسخهٔ قدیمی لازم داشته باشد؛ دادهٔ جدید سالم باقی بماند. این رفتار با binary قدیمی واقعی تست شود.

### backup/export

API backup فعلی کل AppState را JSON می‌کند و باید به DTO export جدید تغییر کند. backup عمومی پیش‌فرض هیچ credential، raw link/config حساس یا token URL ندارد؛ restore برای credentialهای حذف‌شده unresolved/credential required ایجاد کند و داده را silently ناقص اجرا نکند. backup قدیمی با secret، در Windows به transaction vault import شود. export لینک اتصال یا config با credential، فقط API و اقدام صریح مخصوص همان profile است؛ وارد event/list/backup عمومی نشود.

backup قابل انتقال همراه credential، خروجی صریحِ password-encrypted با schema مستقل، KDF مناسب و authenticated encryption و تست tampering باشد؛ DPAPI به‌تنهایی قابل حمل نیست. این خروجی تکمیلی است؛ backup عمومی و import امن legacy در P1 الزامی‌اند. انتقال vault Android Keystore به Windows ادعا نشود. فایل runtime مانند YAML دارای ACL محدود و عمر session باشد و پس از stop/recovery حذف شود.

## ۶. جزئیات اجرای موتورهای مستقل

### ۶.۱. SSH

- فیلدهای هدف: نام، host، port با پیش‌فرض 22، username، password یا private key و passphrase.
- adapter Go با APIهای موجود `golang.org/x/crypto/ssh`؛ پشتیبانی واقعی فرمت‌های کلید در fixtureهای مشترک اندروید/ویندوز تعیین شود. تغییر dependency صرفاً برای این کار بدون نیاز انجام نشود.
- TCP forwarding به SOCKS5 loopback؛ verify واقعی SOCKS handshake، domain target و authentication؛ listener آماده به‌تنهایی Connected نیست.
- first use: نمایش host/port و SHA-256 fingerprint و انتظار پاسخ صریح؛ key تغییرکرده reject شود. trustِ host از credential مستقل ذخیره و update آن اقدام روشن جدا باشد.
- لغو dialog، timeout احراز هویت، secret غلط، قطع server و reconnect ده‌باره بدون leaked goroutine/socket تست شوند.
- UDP proxy برای این مسیر unavailable و reject باشد؛ server و credential واقعی کاربر برای توسعه استفاده نشود.

### ۶.۲. Psiphon

- همان semantics اندروید: `auto`، `cdn`، `direct`، کشور خروج، CDN IP و SNI. Direct فیلدهای CDN را پنهان کند و تغییر mode، draft کشور را از بین نبرد.
- source و config builder با pinهای مرجع اندروید شروع شود؛ build مستقل Windows helper و callback/notice adapter نوشته شود. `.aar` Android قابل استفادهٔ مستقیم نیست.
- فقط bootstrap عمومیِ امضاشده؛ تطبیق کلید verify عمومی، server-list، protocol allowlist و غیرفعال‌بودن Inproxy طبق builder مرجع. پیاده‌سازی نباید به serverهای اختصاصی ZedSecure وابسته شود.
- readiness پس از notice آماده + SOCKS قابل استفاده + HTTPS معتبر از همان مسیر؛ cache و working directory برای session/profileهای جدا تداخل نداشته باشند.
- worker protocol شامل start/cancel/stop/notice/ready/traffic باشد؛ دریافت start acknowledgment برابر readiness نیست. secret فقط از IPC وارد worker شود؛ noticeها قبل از event sanitise شوند. process بدون دسترسی اضافی اجرا شود، مگر نیاز مشخصی که در ADR ثابت شود.
- dropdown کشور: Automatic اول، ISO uppercase، نام محلی با sort زبان جاری؛ کد قبلی خارج از catalogue حفظ شود؛ noticeهای available regions محدود و غیرحساس cache شوند.
- انتخاب کشور درخواست است، نه تضمین خروج از آن کشور؛ کشور مشاهده‌شدهٔ اتصال جدا نمایش داده شود.
- تست Auto/CDN/Direct، حفظ region، bootstrap آفلاین/نامعتبر، kill helper، cancel و traffic واقعی.

### ۶.۳. Tor

- modes: direct، پل پیش‌فرض، پل سفارشی؛ transports: obfs4، Snowflake و Conjure.
- Tor Windows و pluggable transportها با pin، hash، licence و executable architecture مشخص بسته‌بندی شوند. منابع Android به فایل اجرایی Windows تبدیل فرض نشوند؛ availability هر transport برای x64 و ARM64 جدا ثبت شود.
- SAFECOOKIE control authentication، تأیید cookie path/ACL، `TAKEOWNERSHIP`، bootstrap progress و subprocess supervision.
- custom bridge input فقط ساختار bridge مجاز را بپذیرد؛ تزریق torrc از طریق newline، path، control directive و quote رد شود.
- تمام فرآیندهای transport پس از Stop/Crash جمع شوند؛ SOCKS/control port روی loopback باشد؛ خاموش‌شدن Tor فقط از نبود port نتیجه‌گیری نشود.
- Conjure در مرجع اندروید هنوز پذیرش اتصال نهایی ندارد. هدف انتقال آن در پلن حفظ می‌شود، اما تا ثبت HTTPS واقعی در Windows و شبکهٔ مناسب، experimental/unverified نمایش داده شود؛ build یا station registration برابر Connected نیست.
- Conjure اکنون Windows build failure مشخص دارد؛ taskهای port dependency DTLS/NAT، build هر دو target و fixture transport قبل از پذیرش عمومی انجام شوند. Tor Direct/obfs4/Snowflake به رفع Conjure وابسته نشوند. برای ARM64، Tor core native و dependencyهای C جدا ساخته و package شوند؛ این کار prerequisite تحویل Tor روی ARM64 است.
- امکان بسته‌بندی Windows از upstream وجود دارد، اما پوشش ARM64/transport باید با artifact و runtime ثابت شود؛ دانلود upstream تضمین پشتیبانی همهٔ ترکیب‌ها نیست. [صفحهٔ رسمی Tor](https://download.torproject.org/tor/)

### ۶.۴. DNS tunnels: DNSTT، VayDNS، MasterDNS

- خانوادهٔ مشترک DNS با نوع صریح و validation جدا؛ DNSTT/VayDNS: domain، کلید عمومی 64-hex، resolver transport، resolver/DoH URL و SOCKS username/password.
- DNSTT/VayDNS از adapter zeddns با UDP، TCP، DoT و DoH؛ MasterDNS با domains، numeric UDP resolvers، encryption methodهای واقعی 0 تا 5 و encryption key.
- تست parity بر فیلدهای مؤثر `EngineFields` و `DnsCoreEngineBackend` انجام شود؛ فیلدهای پیشرفته‌ای که فقط در مدل partner وجود دارند اما فرم/مسیر فعال استفاده نمی‌کند، به‌عنوان قابلیت قطعی مرجع حساب نشوند.
- reuse کد MasterDNS فعلی پس از تطبیق wire protocol/config؛ صرف وجود import `masterdns://` اثبات سازگاری نیست. scanner و resolver workbench فعلی از backend اتصال مستقل بمانند.
- DNS راه‌اندازی تونل از DNS برنامه‌ها جدا باشد. DoT با numeric IP نیازمند certificate verification مطابق IP SAN است؛ local patch مرجع و تست رد resolver نامعتبر منتقل شود، نه غیرفعال‌کردن verify.
- DNS transport می‌تواند UDP باشد، اما مسیر SOCKS برنامه‌ها همچنان TCP-only است؛ UI این تفاوت را توضیح دهد.
- fixture local سازگار برای هر سه نوع با کلیدهای disposable و resolver TLS آزمایشی فراهم شود؛ سپس تست شبکهٔ واقعی با server سازگار انجام شود.

### ۶.۵. AmneziaWG مستقل

- backend native مجزا از WireGuard outbound و صفحهٔ noise override Mihomo؛ نام و توضیح هر دو باید تفاوت آن‌ها را روشن کند.
- مبنا: pin فعلی `amneziawg-go/v3 v3.1.20260814` در مرجع؛ قابلیت Windows این upstream وجود دارد، اما سازگاری pin، helper و driver منتخب باید با build/test ثابت شود. [مخزن رسمی amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go)
- مسیر پیشنهادی: helper مستقل با Go core v3 و driver سازگار Windows؛ انتخاب بین integration module و service upstream پس از spike ثبت شود. DLL فعلی `cores/wintun.dll` برای ARM64 یا backend جدید بدون بررسی PE architecture/ABI کافی فرض نشود.
- baseline driver، Wintun رسمیِ signed با artifact جدا برای AMD64/ARM64 است؛ سازگاری با pin AWG در P0b تأیید شود. ساخت driver اختصاصی پایه الزام پیش‌فرض نیست. [توزیع رسمی Wintun](https://www.wintun.net/) نسخه‌های signed دو معماری دارد؛ licence همان distribution رعایت شود. هزینهٔ driver احتمالی WFP app split جداست.
- import offline: UTF-8 سخت‌گیرانه، BOM/CRLF، `.conf` خام، فایل حاوی `vpn://`، Base64 URL-safe با padding اختیاری، Qt qCompress/zlib و container JSON با دقیقاً یک config متمایز AWG.
- decoded data حداکثر 64 KiB؛ حد encoded input مطابق مرجع؛ سقف nesting 16 و خروجی decompression محدود؛ duplicate/unknown attributes و دادهٔ administration/API/subscription یا پروتکل دیگر رد شوند.
- import هیچ URL fetch، DNS resolve، Save، Select یا Connect خودکار انجام ندهد. cancel/invalid input باید draft موجود را نگه دارد.
- `Address`، `DNS`، peer endpoint، `AllowedIPs` و MTU طبق parser مرجع؛ پشتیبانی `Jc/Jmin/Jmax`، `S1-S4`، `H1-H4`، `I1-I5` و تمام فیلدهای v3 پذیرفته‌شدهٔ واقعی parser/core با golden fixture اثبات شود؛ field ناشناخته silently ignore نشود.
- app lists داخل config رد شوند؛ policy برنامه‌ها از WhiteVPN بیاید. route، DNS و MTU مؤثر با خلاصهٔ بدون کلید نمایش داده شوند.
- endpoint hostname پیش از TUN روی شبکهٔ فیزیکی resolve شود؛ bind/route استثنای محدود endpoint قبل از default route ایجاد شود. IPv4/IPv6، rebind پس از تغییر شبکه و route cleanup تست شوند.
- آمادگی: adapter + route/DNS صحیح + HTTPS معتبر از مسیر owned tunnel؛ handshake یا process start به‌تنهایی کافی نیست. TCP، UDP، download و native byte counters تست شوند.
- برای AllowedIPs خصوصی/محدود، probe endpoint سازگار با همان routes در profile/test policy تعریف شود؛ HTTPS عمومی خارج از tunnel معیار موفقیت نیست. interface/LUID و route متعلق به session در evidence ثبت شوند. profile بدون مسیر probe سازگار، آمادگی verification را unavailable نشان دهد و silently DIRECT probe نکند.
- **تفکیک برنامه‌ها یک dependency واقعی است:** ruleهای process در Mihomo به native AWG منتقل نمی‌شوند. spike WFP/per-app routing با semantics include/exclude لازم است؛ نیاز احتمالی به callout driver امضاشده و هزینهٔ بسته‌بندی مشخص شود. اگر راه‌حل بدون driver ممکن نیست، workstream مستقل لازم است. تا پیاده‌سازی و تست، این گزینه unavailable است و برابری کامل AWG app split ادعا نمی‌شود.

### ۶.۶. IKEv2 ویندوز

- controller اختصاصی برای APIهای Windows VPN/RAS و Certificate Store؛ profileهای ساخته‌شده owner/name ثابت WhiteVPN و ID مستقل داشته باشند.
- مسیر پایه، اتصال user-scoped با APIهای RAS و phonebook متعلق به برنامه باشد؛ operationهای نیازمند elevation از helper احراز‌شده عبور کنند. اجرای فرمان با credential در argv ممنوع است. create/update/start/stop بر ID و handle اتصال matching اعمال شود؛ نام نمایشی به‌تنهایی owner نیست.
- spike اول: create/start/state/stop، EAP-MSCHAPv2، certificate/CA validation، server identity و local identity در Windows 10/11 و ARM64.
- Windows built-in VPN روش‌های EAPِ رمز و certificate را مستند می‌کند؛ این موضوع اثبات پشتیبانی PSKِ IKEv2 یا برابری دقیق همهٔ identityهای Android نیست. [مستند Windows VPN authentication](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/vpn/vpn-authentication)
- PSK و identityهای بدون نگاشت قطعی نباید silently به auth دیگر تبدیل شوند. نتیجهٔ spike باید یکی باشد: پشتیبانی native اثبات‌شده؛ backend مستقل سازگار با licence و privilege review؛ یا گزینهٔ صریح unavailable در بتا با ثبت فاصله از parity.
- حداقل موتور IKEv2 با EAP-MSCHAPv2 و مسیر certificate اثبات‌شده الزامی است؛ unavailable شدن PSK به معنی حذف موتور نیست. `L2tpPsk` در [Add-VpnConnection](https://learn.microsoft.com/en-us/powershell/module/vpnclient/add-vpnconnection?view=windowsserver2025-ps) اثبات PSK برای IKEv2 نیست. EAP-TLS، machine certificate و identityهای Android با test server جدا نگاشت شوند.
- certificate alias Android به reference معتبر Windows Certificate Store با thumbprint/store context تبدیل می‌شود؛ certificate کاربر باید از picker واقعی انتخاب و وجود private key بررسی شود. CA عمومی کاربر بدون اقدام روشن وارد trust سراسری سیستم نشود.
- timeout، credential غلط، cert نامعتبر، server-name mismatch، UAC denied، session خارجی و disconnect بی‌اثر تست شوند.
- Windows VPN ممکن است بعد از خروج UI باقی بماند؛ journal و recovery باید مالکیت اتصال را تشخیص دهند. دیگر VPNهای سیستم قطع نشوند.
- `RasHangUp` فقط آغاز توقف است؛ completion با polling deadlineدار status تا پایان handle و سپس route/DNS evidence تأیید شود. [مستند RasHangUpW](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rashangupw) پایان فوری state machine را تضمین نمی‌کند. timeout، owner را release pending نگه دارد.
- Connected فقط با state متعلق به profile + route evidence + HTTPS از رابط همان VPN؛ تست native فقط روی اتصال matching فعال و بدون جایگزین‌کردن اتصال دیگری.
- برای VPN خصوصی/split route، endpoint probe متعلق به شبکهٔ مقصد انتخاب شود و interface/LUID اتصال matching در evidence بیاید؛ خروجی HTTPS روی رابط فیزیکی تأیید این VPN نیست.
- traffic به‌صورت پیش‌فرض unavailable؛ فقط اگر API اختصاصی همان session ثابت شد فعال شود، نه با جمع ترافیک دستگاه.
- برای metric، spike روی `RasGetConnectionStatistics(HRASCONN)` انجام شود؛ در صورت اعتبارسنجی با transfer واقعی، sample به همان sessionID وصل شود. نبود آمار معتبر مانع اتصال پایه نیست و صفر ساختگی نمایش داده نشود.

## ۷. ماتریس تنظیمات مؤثر

| گزینه | Mihomo | SSH / Psiphon / Tor / DNS | AmneziaWG native | IKEv2 Windows |
| --- | --- | --- | --- | --- |
| TUN/VPN | موجود | از طریق synthetic Mihomo | native | platform |
| System proxy / Proxy-only | موجود | قابل ارائه | unavailable | unavailable |
| destination rules و DNS WhiteVPN | طبق مسیر فعلی | با synthetic Mihomo | از `.conf`؛ override جهانی خاموش | profile/platform؛ override جهانی خاموش |
| split برنامه‌ها | process rules فعلی | process rules + جلوگیری از loop | هدف parity؛ نیازمند spike و implementation مستقل | unavailable مطابق محدودیت مرجع؛ policy platform جدا |
| LAN proxy با auth | تکمیل مسیر موجود | همان ورودی synthetic | unavailable | unavailable |
| Automatic node / chain / location Mihomo | موجود | unavailable | unavailable | unavailable |
| انتخاب کشور Psiphon | نامرتبط | فقط Psiphon | نامرتبط | نامرتبط |
| IP fronting و TLS integrity انتخاب نود | موجود | کنترل عمومی خاموش؛ CDN/Tor گزینهٔ خود موتور دارند | unavailable | unavailable |
| Mihomo WireGuard override | فقط candidateهای مرتبط | unavailable | گزینه‌ها در config خودش | unavailable |
| UDP برنامه‌ها | وابسته به پروتکل | proxied UDP reject | native؛ مطابق config | platform؛ نیازمند تست |
| سرعت آپلود/دانلود | metric core | counter synthetic Mihomo | counter native | unavailable مگر API معتبر |

Preflight، فرم، Settings، Home، tray و تست‌ها همگی همین policy را مصرف کنند. فیلد غیرفعال فقط خاکستری نشود؛ دلیل کوتاه داشته باشد. backend نیز استفاده از گزینهٔ ناسازگار را رد کند. درخواست تغییر mode از tray برای native connection قبل از mutation رد شود؛ preference سازگار قبلی محفوظ بماند.

برای SOCKS + TUN، مسیر engine/bootstrap باید از capture شدن مجدد جلوگیری کند؛ استثنا به helper/process path/endpointهای مشخص محدود باشد. probe برنامه عمداً از synthetic Mihomo عبور کند و به‌علت همین bypass از VPN خارج نشود. عدم loop و عدم bypass ناخواسته باید با capture شبکه اثبات شود.

LAN: حالت پیش‌فرض خاموش، listenerهای controller/DNS همچنان loopback، credentials جدا در vault، rule firewall محدود به شبکه/ورودی مورد نیاز و cleanup متعلق به WhiteVPN. تغییر network profile و اتصال دستگاه دومِ بدون auth تست شود. بازکردن LAN بدون auth، parity این انتقال محسوب نمی‌شود.

احراز هویت mixed HTTP/SOCKS نباید system proxy یا probeهای محلی فاقد credential را بشکند. قرارداد پایه: auth برای LAN و exemption محدود به `127.0.0.1/32` و `::1/128`، یا listener جدا با اثر معادل. allowlist گسترده برای bypass auth ایجاد نشود. local client، IPv4/IPv6 loopback و دستگاه دوم با/بدون credential fixture مستقل داشته باشند.

## ۸. UI و API دسکتاپ

### ساختار صفحات

- navigation «Subscriptions» به «Profiles» تغییر کند؛ منابع داخلی، منابع کاربر و engine profiles در همان مقصد با یک selected badge باشند.
- Add شامل subscription/connection link و شش engine مستقل؛ منبع `all` و manual source دسکتاپ همچنان در محدودهٔ Mihomo کار کنند.
- هر کارت: نام، type، availability، selected/active state و Test/Edit/Delete متناسب؛ unavailable test واقعاً disabled باشد.
- کارت‌های ساب‌اسکریپشن action Connections را به workbench فعلی وصل کنند؛ location برای source منتخب Mihomo در Options باشد.
- Home یک ردیف Profile داشته باشد؛ engine provisioning از Home و Settings حذف شود. تنظیمات دسترسی در Connection settings قرار گیرد؛ انتخاب پروفایل کاربر را به VPN page برگرداند.
- close-to-tray، single instance، server sorting/export و endpointهای proxy فعلی باقی بمانند؛ tray همان active session و mode capability را نشان دهد.

### فرم‌ها و رفتار draft

- componentهای مشترک EngineEditor، SecretField، EngineTypeSelect، ProfileCard و TrustDialog؛ design system موجود React، font فارسی و رنگ‌های فعلی استفاده شود.
- schema فرم از configهای واقعی مرحلهٔ ۶ بیاید؛ hide/show auth، bridge، DNS transport و CDN بدون از دست رفتن draft.
- labels/layout در فارسی RTL، مقادیر فنی host/IP/URL/key/config در LTR؛ `vpn://` و `.conf` با bidi isolation.
- دکمهٔ eye فضای واقعی ثابت در layout رزرو کند؛ متن طولانی در hidden/revealed حالت زیر icon نرود. raw value، cursor/selection و multiline محتوا تغییر نکند.
- draft فقط در حافظهٔ component/session editor باشد؛ rerender یا تغییر theme آن را حفظ کند، بسته‌شدن editor یا process آن را پاک کند.
- modal scroll، focus trap، keyboard navigation، screen reader labels و scaling ویندوز 100/125/150/200 درصد بررسی شود؛ صفحهٔ 860×620 نیز قابل استفاده باشد.
- معادل `FLAG_SECURE` Android در WebView2 تضمین یکسانی ندارد. اگر screen-capture protection پیاده می‌شود، محدودیت واقعی Windows صریح تست/مستند شود؛ secret mask و عدم persistence الزام پایه است.

### APIهای پیشنهادی Wails

`ListEngineProfiles`، `GetEngineProfileForEdit`، `SaveEngineProfile`، `DeleteEngineProfile`، `SelectRouteProfile`، `GetEngineAvailability`، `GetEffectiveSettings`، `ImportAmneziaConfigFile`، `DecodeAmneziaLink`، `StartEngineProfileTest`، `CancelEngineProfileTest` و `AnswerSSHTrustPrompt`.

API editor برای credentialهای legacy/manual نیز تعریف شود. اتصال از یک مسیر مشترک `ConnectSelectedProfile`/`StopActiveSession` انجام شود و operationID قابل لغو بدهد؛ نام نهایی با API موجود تطبیق یابد. trust response به profile revision/sessionID و prompt nonce متصل شود؛ پاسخ dialog قدیمی روی تلاش جدید اثر نکند. save optimistic revision داشته باشد تا editor قدیمی تغییر جدید را overwrite نکند.

نام نهایی با convention موجود تطبیق داده شود. inputها server-side validate و size-limit داشته باشند؛ list/state/event پاسخ بدون secret بدهند. runtime event شامل sessionID، backend، profileID، stage و پیام sanitizeشده باشد. DTO و bindingهای frontend پس از تثبیت قرارداد تولید/به‌روز شوند.

## ۹. تست اتصال و آمار

- SOCKS profile وقتی stopped است، با session تستِ loopback مستقل و بدون system proxy/TUN قابل تست باشد؛ وقتی همان profile فعال است، تست از route فعال matching استفاده کند.
- native profile فقط پس از برقراری matching session تست شود؛ تست نباید VPN دیگری را قطع یا route سیستم را تعویض کند.
- subscription batch test هنگام engine session فعال مسدود شود؛ عملیات تست قدیمی هنگام switch cancel/join شود. concurrency batch فقط تنظیم Mihomo باشد.
- timeout و download size تنظیم‌شده روی engine test اعمال شود؛ cancel فایل موقت، socket، helper و goroutine را آزاد کند.
- metricها: `sessionID`، `source`، timestamp monotonic، total bytes و rates؛ نمونهٔ قدیمی‌تر از پنج ثانیه unavailable شود و هنگام stop پاک شود.
- آمار IKEv2 تا پذیرش API connection-scoped با unavailable نمایش داده شود؛ صفر ساختگی یا مجموع network adapter/device به‌عنوان engine speed استفاده نشود.
- readiness، country و speed probe باید واقعاً از مسیر مورد ادعا بگذرند؛ HTTPS با certificate validation، بدون fallback مستقیم و با deadline قابل لغو.

## ۱۰. نقشهٔ فایل‌ها

مسیرهای «جدید» در این جدول پیشنهاد هستند و اکنون ایجاد نشده‌اند. تغییرها در ماژول `desktop` متمرکز باشند؛ `WhitednsTC` فقط در صورت reuse اثبات‌شده تغییر کند.

| مسیر | کار پیشنهادی |
| --- | --- |
| `desktop/internal/model/types.go` و `whitevpn_settings.go` | RouteRef، DTO عمومی، capability/effective settings و runtime backend |
| `desktop/internal/engineprofiles/` — جدید | configهای نوع‌دار، validation، codec، profile schema و AWG import |
| `desktop/internal/securestore/` — جدید | DPAPI Windows، ACL، atomic vault و API platform unavailable |
| `desktop/internal/backends/` — جدید | contract و adapters Mihomo/SSH/Psiphon/Tor/DNS/AWG/IKEv2 |
| `desktop/internal/sessionmanager/` — جدید | ownership، state machine، leases، switch، cancellation، recovery |
| `desktop/internal/engine/` | reuse named pipe، launch/elevation و process supervision؛ بدون تغییر غیرضروری protocol Mihomo |
| `desktop/internal/session/` | adapter روی session فعلی و synthetic SOCKS session؛ حفظ رفتار Automatic/watchdog |
| `desktop/internal/mihomoconf/` | runtime synthetic، rule ordering، UDP rejection و LAN authentication |
| `desktop/internal/profiles/store.go` و `backup.go` | migration metadata، referenceها و حفاظت backup از secret |
| `desktop/app.go` و `mihomo_connect.go` | dispatch مشترک Connect/Stop و eventهای backend؛ رفع فرض Mihomo-only |
| `desktop/whitevpn_nodes.go`، `whitedns_vpn.go` و `whitevpn_settings.go` | انتخاب بعدی جدا از active snapshot؛ حذف اعمال ضمنی Select روی اتصال جاری |
| `desktop/manual_nodes.go`، `v2ray.go` و `whitevpn_measure.go` | API editor بدون secret در state؛ profile tests و node tests زیر coordinator مشترک |
| `desktop/reset.go` و API restore در `app.go` | gate owner/release pending؛ جلوگیری از حذف journal یا تعویض state حین مالکیت |
| `desktop/mihomo_watchdog.go`، `country.go`، `ping.go`، `logs.go` | scope metrics/probes/recovery و sanitize خطاها |
| `desktop/system_proxy.go`، `internal/sysproxy/`، `tray.go` | حفظ restore، policy mode، active vs selected و recovery |
| `desktop/frontend/src/App.tsx` | اتصال navigation/Profile row؛ استخراج بخش جدید به componentها |
| `desktop/frontend/src/components/engine-profiles/` — جدید | cards، editors، secret/trust/import/test dialogs |
| `desktop/frontend/src/types.ts`، `wails.ts`، `i18n.ts`، `styles.css` | DTO/binding و فارسی/انگلیسی/RTL |
| `desktop/cmd/engine-worker/` — جدید | helper Psiphon/DNS؛ بنابر نتیجهٔ spike، AWG helper جدا |
| `desktop/cmd/network-helper/` و `cmd/awg-worker/` — جدید، نام پیشنهادی | عملیات privileged احراز‌شده و AWG native؛ process handle/job و resource journal |
| `desktop/scripts/` و `desktop/cores/` | build/fetch/verify/package engine artifacts با architecture صحیح |
| `.github/workflows/ci.yml` و `desktop-release.yml` | checks، native build matrix و smoke tests Windows |
| `desktop/build/windows/installer/whitevpn.wxs` | helper/driver files، upgrade/uninstall/recovery |
| `THIRD_PARTY_NOTICES.md`، `licenses/`، `desktop/ANDROID-PARITY.md` و READMEها | source pins، licence، قابلیت واقعی و limitations به‌روز |

## ۱۱. ترتیب اجرا و خروجی هر مرحله

برآوردهای زیر **ظرفیت اولیهٔ برنامه‌ریزی به نفرروز مهندسی** هستند؛ از شکست/موفقیت compile، حجم integration و کارهای تعریف‌شده تخمین زده شده‌اند و اندازه‌گیری زمان اجرا نیستند. پس از P0b/P0c با ADR و خروجی spike اصلاح شوند. زمان انتظار سخت‌افزار/server، امضا یا شبکهٔ قابل تست جزو آن‌ها نیست.

| مرحله | محدوده و خروجی قابل بررسی | وابستگی | برآورد اولیه |
| --- | --- | --- | --- |
| P0a/P0b | ثبت مرجع و baseline موجود؛ manifest الزامی، fixture plan، spike IKE/cert، Wintun و Tor ARM64، تصمیم storage | ندارد؛ بخشی از evidence آماده است | ۴–۷ |
| P0c | تطبیق Mihomo/patchها و build artifact Windows؛ regression core و policy config | مرجع P0a | ۴–۷ |
| P1 | مدل داخلی/Public DTO، vault و تراکنش generation، مهاجرت credentialهای فعلی، downgrade و backup policy | تصمیم storage P0b | ۹–۱۴ |
| P2 | SessionManager، adapter Mihomo اصلاح‌شده، coordinator تست، helper protected، IPC/job/journal و synthetic SOCKS | P1/P0c | ۱۲–۱۸ |
| P3 | Profiles UI، editorهای legacy/engine، SSH و country dropdown زیرساخت | P1؛ اتصال واقعی پس از P2 | ۶–۹ |
| P4 | Psiphon Windows و metadata کشورها | P2/P3؛ feasibility در P0 | ۴–۶ |
| P5 | Tor core/transportها دو معماری، bootstrap/SAFECOOKIE و Direct/obfs4/Snowflake | P2/P3؛ مسیر ARM64 در P0b | ۸–۱۳ |
| P6 | DNSTT/VayDNS/MasterDNS، resolver fixture و DoT patch | P2/P3 | ۶–۹ |
| P7 | AWG v3، import، native routing/DNS، Wintun هر target و counters | P1/P2/P3؛ feasibility در P0b | ۹–۱۴ |
| P8 | IKEv2 platform controller، EAP-MSCHAPv2 و certificate path، ownership/recovery | P1/P2/P3؛ auth mapping در P0b | ۷–۱۱ |
| P9 | integration regression، LAN auth، package/CI، Windows x64/ARM64 acceptance و docs | همهٔ شش مسیر پایهٔ P3–P8 | ۸–۱۲ |

جمع ظرفیت اولیهٔ scope پایهٔ بازنگری‌شده: **۷۷–۱۲۰ نفرروز**، تقریباً ۱۶–۲۴ هفتهٔ کاری برای یک نفر تمام‌وقت. افزایش نسبت به ۵۲–۸۰ نفرروزِ ویرایش اول ناشی از scope روشن‌شدهٔ credential migration، اصلاح انتخاب/lifecycle قدیمی، helper امن، core delta و کار Tor ARM64 است. این بازه تضمین زمان تحویل نیست؛ شکست spikeهای الزامی باعث بازبرآورد task مربوط می‌شود، نه حذف موتور از تعهد. بستهٔ x64 ممکن است زودتر از تکمیل ARM64 به candidate برسد. کارهای مستقل پس از تثبیت قراردادها قابل تقسیم‌اند؛ اجرای موازی در این نوبت آغاز نمی‌شود.

**workstreamهای تکمیلی خارج از بازهٔ پایه:** T1، port و پذیرش Conjure؛ T2، AWG app split با WFP/per-app routing و driver احتمالی؛ T3، IKEv2 PSK/identityهای بدون mapping native؛ T4، backup قابل حمل رمزگذاری‌شده. برای T1–T3 پیش از ادعای full parity باید برآورد، implementation و acceptance جدا تکمیل شود. این تفکیک به معنای اختیاری‌شدن هیچ‌یک از شش خانوادهٔ پایه نیست.

### Gate هر مرحله

- P0a: release commit و manifest baseline ثبت؛ evidence موجود با hash/log نگه‌داری؛ required matrix هر شش خانواده برای دو target روشن.
- P0b: spike mapping IKEv2/cert و Wintun، مسیر build Tor ARM64 و fixtureهای هر engine؛ هر مانع یک task با evidence و اثر بر تاریخ target داشته باشد. DPAPI/catalog/downgrade ADR نهایی شود.
- P0c: core artifact همان target، policy config و regression Mihomo پاس؛ frontend placeholder یا embed بدون exe، gate release core را پاس نمی‌کند.
- P1: هیچ secret در PublicAppState/event/backup عمومی Windows؛ vault round-trip/corruption، تراکنش save/delete/restore و migration قدیمی/دوباره اجرا/قطع نوشتن پاس؛ binary قدیمی دادهٔ جدید را تغییر ندهد.
- P2: fake backend و adapter واقعی برای concurrent start/stop، stale event، cancellation، timeout cleanup، crash و unconfirmed release پاس؛ helper elevated protected/job/IPC اثبات شود؛ انتخاب B حین اتصال A، policy/watchdog اتصال A را تغییر ندهد.
- P3: Save بدون Select/Connect، Select بدون Connect، unresolved delete، trust SSH و navigation فارسی/انگلیسی پاس.
- P4–P6: Psiphon، Tor و هر سه DNS tunnel به‌تنهایی HTTPS/download/traffic و stop/cancel را ثابت کنند؛ تمام modes/transportهای پایهٔ جدول ۳.۱ required هستند. Conjure فقط پس از build معتبر وارد experimental شود.
- P7: AWG TCP/UDP/HTTPS، v3 import fixtures، native counters، route/DNS restore و سه reconnect پاس؛ app split وضعیت مستقل داشته باشد.
- P8: هر auth method تنها پس از server fixture موفق available شود؛ مالکیت native و recovery بدون دست‌زدن به VPN خارجی پاس.
- P9: هر شش خانواده روی target release قابل اتصال باشند؛ package نصب/upgrade/uninstall و ماتریس acceptance تکمیل شود؛ unavailable/experimental فقط برای ترکیب‌های خارج از حداقل تحویل با UI و release notes یکسان باشد. ARM64 بدون hardware acceptance تمام‌شده اعلام نشود.

### ۱۱.۱. اولین مجموعهٔ تغییرات قابل تحویل

پس از تکمیل تصمیم‌های P0، اولین مجموعهٔ implementation شامل P1 و P2 است: profile model/DTO و vault، fake backend، adapter Mihomo، انتخاب مستقل و release pending. هدف این تحویل، اتصال فعلی Mihomo با lifecycle جدید و CRUD شش نوع profile است. backendهای واقعی به‌ترتیب SSH، Psiphon و DNS، سپس Tor و native AWG/IKEv2 وارد acceptance شوند؛ ترتیب ورود ممکن است با آماده‌شدن fixture جابه‌جا شود، ولی هیچ خانواده‌ای حذف نمی‌شود.

برای هر مرحله یک checklist task، artifact/log و معیار fail ثبت شود. کار «ساخت worker»، «fixture server» و «قبولی شبکه» جدا ردیابی شود؛ compile pass روی library جای worker/runtime را نگیرد.

پیشنهاد تقسیم تغییرات برای review: P1، P2، UI+SSH، Psiphon، Tor، DNS، AWG، IKEv2 و release/integration به PRهای قابل تست جدا تبدیل شوند. branchها از prefix `codex/` و نام متناسب استفاده کنند. تغییر build version دسکتاپ پس از تثبیت release انجام شود؛ شمارهٔ نسخهٔ اندروید الزاماً شمارهٔ release دسکتاپ نیست.

## ۱۲. برنامهٔ تست و پذیرش

### تست خودکار معنی‌دار

- مدل/config: type mismatch، unknown fields، اندازه/نسخه، invalid port/URL، identity و legacy retired.
- AWG golden corpus مشترک: raw/vpn/qCompress/JSON، BOM/CRLF، malformed UTF-8، zip/decompression bomb، ambiguity و fieldهای v3. هیچ fixture از credential واقعی کاربر ساخته نشود.
- vault: کاربر دیگر، corruption، tampering، key loss، failure atomic write و backup بدون secret.
- persistence transaction: قطع بین vault/metadata/pointer، disk-full، save/delete/restore نیمه‌کاره، generation orphan، دو writer و recovery تکراری؛ downgrade با binary قبلی واقعی.
- session: start cancel، late readiness، هم‌زمانی Connect/Stop، stop دوباره، target preflight fail، stop fail، crash هنگام switch و جلوگیری از adoption session قدیمی.
- SSH: password/key/passphrase، fingerprint first-use/reject/change، auth fail و ده reconnect با server local.
- policy: هر engine × mode × setting، backend/frontend/tray یکسان؛ گزینهٔ ناسازگار در API هم رد شود.
- شبکه: packet capture در fixtureها برای bootstrap loop، proxied UDP reject، DIRECT rule صریح، application DNS routed و negative HTTPS certificate test.
- UI: form preservation، invalid/cancelled import، key/secret length، eye icon، focus و responsive RTL؛ harness سبک browser برای componentها کافی است و تست native picker در Wails روی Windows جدا انجام شود.
- native: helper death، disconnect timeout، UAC cancel، adapter/route/DNS ownership، crash-restart و conflicting foreign VPN.
- integration انتخاب: A فعال/B منتخب، تغییر country/node، watchdog/network recovery، tray، reset/restore در Failed+release pending، shutdown حین node test و callback قدیمی بعد از profile edit/delete.

### ماتریس سیستم‌عامل و سخت‌افزار

| محیط | پذیرش لازم |
| --- | --- |
| Windows 10 x64 | نصب، هر شش خانواده با حداقل جدول ۳.۱، DNS/route cleanup |
| Windows 11 x64 | هر شش خانواده، UAC دو حالت حساب، sleep/resume و network switch |
| Windows 11 ARM64 واقعی | هر شش خانوادهٔ پایه، PE/driver architecture و runtime بدون اتکا به cross-build یا emulation |
| کاربر استاندارد و administrator | UI unelevated؛ helper elevated فقط در مسیر لازم؛ رد UAC بدون mutation |
| شبکه‌های Wi-Fi/Ethernet/Hotspot | reconnect و endpoint rebind؛ LAN auth؛ عدم route/DNS نشت ناخواسته |
| شبکهٔ محدود ایران | تست Psiphon، Tor bridges و DNS tunnel با server سازگار؛ ثبت تاریخ و شرایط شبکه |

برای هر engine available: connect/disconnect سه دور، cancel حین startup، timeout readiness، helper crash، HTTPS، دانلود حداقل 5 MB و traffic scoped. AWG/IKEv2 برای UDP نیز fixture لازم دارند؛ SOCKS برای رد UDP. network change، IPv6/dual-stack، loss/recovery، sleep/resume و exit-to-tray باید تست شوند.

زیرساخت fixture: SSH server disposable؛ gateway AWG v3 با IPv4/IPv6 و AllowedIPs خصوصی/کامل؛ IKEv2 server با EAP-MSCHAPv2 و certificate disposable؛ server سازگار هر DNS tunnel همراه resolver UDP/TCP/DoT/DoH؛ endpoint HTTPS با certificate معتبر و negative certificate case. برای Psiphon/Tor، fixture کنترل lifecycle/bridge با پذیرش واقعی شبکه تکمیل شود؛ موفقیت شبکه به تاریخ، transport و محیط آزمون متصل باشد. fixtureها credential کاربر را مصرف نکنند و از host Windows آزمون‌گر قابل دسترس باشند. نبود fixture مورد required، پذیرش آن موتور را متوقف می‌کند و با mock جبران نمی‌شود.

### regression امکانات فعلی

دو catalogue داخلی، `all` و manual source، انواع لینک فعلی، refresh/hidden nodes، Automatic/manual selection، country/protocol filters، chain، TLS integrity، fronting، noise override، split process rules، DNS privacy، تست batch، fixed proxy-only port، tray mode و system-proxy crash restore.

### commands هنگام پیاده‌سازی

```powershell
Set-Location 'E:\projects\WhiteVPN-Desktop\desktop'
go build ./...
go vet ./internal/... .
go test ./internal/... .
Set-Location 'E:\projects\WhiteVPN-Desktop\desktop\frontend'
npx tsc --noEmit --noUnusedLocals
npm run build
```

در CI لینوکسِ دارای dependencyهای Wails، `go test -race ./internal/... .` نیز اجرا شود. `main.go`، `frontend/dist` را embed می‌کند؛ frontend باید ساخته شده باشد یا مانند CI placeholderِ فقط تست فراهم شود. native end-to-endها جدا از unit suite با helpers واقعی و fixtureهای disposable اجرا شوند. یادداشت قدیمی «چهار تست Windows از قبل fail هستند» بدون baseline جدید پذیرفته نشود؛ هر failure باید دوباره reproduce و طبقه‌بندی شود.

**baseline در بازنگری ۲۰۲۶-۱۰-۰۴ اجرا شد:** Go build/vet، TypeScript و frontend build پاس؛ ۵۸۱ تست Go پاس، صفر شکست، ۸ skip؛ cross-build پکیج‌های داخلی Windows ARM64 موفق. Go 1.26.5، Node 24.19.0 و npm 11.17.0 استفاده شد. پنج تست live به‌علت environment اجرا نشدند؛ یک تست macOS و دو تست core override مخصوص مسیرهای دیگر نیز skip بودند. race، MSI/ZIP، UAC و native live پذیرش نشده‌اند. در `desktop/cores` فعلی Mihomo exe وجود ندارد و Wintun موجود AMD64 است. جزئیات در evidence بخش ۱ موجود است. passهای Android، گزارش مرجع هستند و اثبات Windows نیستند.

## ۱۳. build، dependency و انتشار

- `native/engines/sources.json` و `tor-inputs.json` Android مبنای provenance باشند؛ manifest مستقل Windows شامل URL/commit/version، local patches، Go/CGO/toolchain، architecture، hash و licence تولید شود.
- pinها: Psiphon `83aa73b9b982e7421e00117f5b0c5aceb5dda452`؛ MasterDNS `50b447bc41e6c930a0027507a1a9f492b6fc63b9`؛ VayDNS `a0ff70110d5e96686ab8f4c8e1c44cd09be07a75`؛ AWG v3 طبق مرحلهٔ ۶. pinهای Tor/lyrebird/Snowflake/Conjure از manifest مرجع خوانده شوند و نسخهٔ Windows به‌طور مستقل verify شود.
- source pin تنها شروع parity است؛ patch لازم برای Windows با diff، علت و test ثبت شود. تغییر upstream بدون بررسی config/wire parity انجام نشود.
- برای هر target، PE machine type، DLL imports/runtime dependencies، licence files، helper protocol version و hashesِ فایل‌های نهایی داخل MSI/ZIP بررسی شوند.
- `native/engines/windows-sources.json` و release capability manifest ایجاد شوند؛ هر entry شامل engine، transport/auth، target، required tier، runtimeKind، source/patch hash، helper protocol، binary/DLL hash و evidence پذیرش باشد. IKEv2 platform API نیز entry مستقل داشته باشد، حتی اگر exe موتور جدا ندارد. «شناخته‌شدن نوع profile» از «available بودن اتصال» جدا باشد.
- artifacts ناقص در هر یک از شش خانوادهٔ پایه سبب fail release build همان target شوند. workstream تکمیلی بدون artifact/evidence باید unavailable باشد؛ موتور required همیشه unavailable، محصول نهایی این برنامه نیست. UI feature flag جای اثبات runtime نیست.
- افزایش حجم/زمان startup/RAM با baseline مقایسه شود؛ استخراج helpers با hash و ACL، عدم overwrite نسخهٔ درحال اجرا و cleanup نسخه‌های قدیمی رعایت شود.
- MSI: update، rollback، uninstall، driver/helper lifecycle و cleanup شبکه؛ ZIP: پیش‌نیاز driver و elevation صریح. certificateهای کاربر یا trust store مشترک در uninstall حذف نشوند.
- `desktop-release.yml` فعلی tagهای `v*` را مصرف می‌کند؛ tag convention از workflow جاری گرفته شود، نه README قدیمی `vpn-v*`.
- label نمایشی prerelease و version عددی MSI/Windows metadata نگاشت مشخص داشته باشند؛ string `beta.1` مستقیماً در product version عددی Windows قرار نگیرد.
- امضای Authenticode برنامه/helpers و امضای driver در صورت نیاز، با credentialهای release موجود یا workstream جدا انجام شود؛ build unsigned به‌عنوان signed اعلام نشود.
- release آزمایشی ابتدا artifact محلی/CI و release candidate قابل بررسی تولید کند؛ انتشار بیرونی مرحلهٔ مستقل پس از پذیرش است.

## ۱۴. ریسک‌ها و تصمیم‌های باز

| موضوع | اقدام برای رفع ابهام | اثر بر انتشار |
| --- | --- | --- |
| دو APK با نسخهٔ یکسان | انتخاب artifact و ثبت hash/provenance؛ سورس bf4adc5 مبنا | نسخه به‌تنهایی artifact را تعیین نمی‌کند |
| اختلاف Mihomo core و patchها | P0c، golden config و regression Windows | prerequisite مسیر synthetic و حفظ اتصال فعلی |
| worker Windowsِ Psiphon/DNS | library compile موفق؛ worker/IPC/fixture/runtime هنوز لازم | خانواده‌ها required؛ نبود acceptance مانع پایان target |
| Tor core ARM64 | build native C/dependencies و hardware acceptance | مانع تحویل ARM64 تا رفع؛ Tor حذف نشود |
| Conjure build و شبکه | Windows socket/NAT patch، build، bootstrap و HTTPS | تکمیلی T1؛ unavailable تا artifact و experimental تا پذیرش |
| PSK/local identity در IKEv2 native | compatibility spike با server fixture | backend جایگزین یا محدودیت صریح؛ parity ناقص ثبت شود |
| AWG native app split | اثبات WFP/per-app routing و نیاز driver/signing | بدون حل، این زیرقابلیت کامل نیست |
| credentialهای قدیمی/backup plaintext | transaction migration و API عمومی redact | الزامی پیش از افزودن secretهای جدید |
| downgrade و تراکنش چند فایل | versioned path/generation pointer و تست binary قدیمی | gate P1؛ از دست‌رفتن داده پذیرفته نیست |
| انتخاب/live policy قدیمی | ActiveSessionPlan و اصلاح API/watchdog | gate P2/P3؛ انتخاب بعدی اتصال active را عوض نکند |
| helper elevated user-writable | protected install، IPC identity و Job Object واقعی | gate P2 پیش از mode privileged |
| orphan helper یا route/DNS | ownership journal + crash recovery + negative tests | blocker اتصال جدید در cleanup نامطمئن |
| LAN بدون auth در مسیر فعلی | تکمیل auth/firewall و دستگاه دوم | اشتراک engine جدید قبل از این تکمیل available نشود |
| تست واقعی DNS/IKEv2 بدون server | fixture disposable محلی + server سازگار واقعی | mock تنها، تأیید runtime نیست |

برای هر تصمیم P0، ADR کوتاه با گزینه‌ها، شواهد، انتخاب و limitation ایجاد شود. کارهای UI/model/vault مستقل از دسترسی server قابل پیشرفت‌اند؛ پذیرش live به fixture/شبکه نیاز دارد.

## ۱۵. معیار پایان کار

- [ ] مرجع دقیق Android 1.7.0 Beta 1 ثبت شده و این فهرست با آن reconcile شده است.
- [ ] Profiles و Home/navigation جدید با Save/Select/Connect مستقل کار می‌کنند.
- [ ] هر شش خانوادهٔ engine با حداقل جدول ۳.۱ اتصال واقعی دارند؛ DNSTT/VayDNS/MasterDNS هر سه پذیرفته شده‌اند؛ availability metadata جای backend نیست.
- [ ] Windows credentialهای جدید و فعلیِ inventory در vault هستند و PublicAppState، event، log، argv و backup عمومی secret ندارند؛ editor/export صریح API محدود دارند.
- [ ] migration داده و انتخاب قبلی را حفظ می‌کند؛ خرابی vault یا selected profile fallback پنهانی ایجاد نمی‌کند.
- [ ] save/delete/restore قطع‌شده recover می‌شوند و binary قدیمی state/vault جدید را overwrite نمی‌کند.
- [ ] switch، cancellation، stale event و cleanup uncertain بدون مالکیت هم‌زمان تست شده‌اند.
- [ ] proxy/TUN/readiness/DNS/UDP/traffic مطابق ماتریس engineها رفتار می‌کنند.
- [ ] import AWG و فیلدهای v3 با corpus واقعیِ غیرحساس و تست malformed ورودی پاس‌اند.
- [ ] native AWG route/DNS/driver/counters و وضعیت app split روشن و پذیرش‌شده است.
- [ ] IKEv2 auth mapping و native ownership با server واقعی/fixture سازگار اثبات شده است.
- [ ] LAN authenticated و controller/DNS loopback-only در همهٔ مسیرهای مربوط رعایت شده‌اند.
- [ ] فارسی/انگلیسی، themeها، رمزهای طولانی، keyboard و Windows scaling بررسی شده‌اند.
- [ ] regression فعلی Mihomo، tray، workbench و system-proxy restore پاس است.
- [ ] Windows x64/ARM64 MSI/ZIP، upgrade/uninstall، licence/hash و runtime acceptance بررسی شده‌اند.
- [ ] مستند parity، release notes و فهرست Known limitations با رفتار UI یکسان‌اند.

**پایان تحویل پایهٔ شش موتور:** تمام checklist بالا و جدول ۳.۱ روی x64 و ARM64 پذیرفته شده باشند. release candidate x64 تا آماده‌شدن ARM64 می‌تواند وضعیت جدا داشته باشد؛ ادعای اتمام دو معماری مجاز نیست. زیرقابلیت‌های T1–T3 می‌توانند وضعیت unavailable/experimental مستند داشته باشند، اما هیچ‌یک از شش خانوادهٔ پایه نباید صرفاً placeholder باشد.

**پایان full parity:** علاوه بر تحویل پایه، Conjure end-to-end، AWG app split، همهٔ auth/identityهای IKEv2 موجود در مرجع و corpus کامل config/form رفتار برابرِ اثبات‌شده داشته باشند. اگر زیرقابلیتی در خود بتای Android هم unverified است، وضعیت مرجع و Windows جدا ثبت شود؛ آزمایشی‌بودن مرجع به معنی قبولی Windows نیست.

## ۱۶. منابع برای ادامهٔ اجرا

### فایل‌های مرجع اندروید در commit انتشار

ریشهٔ مرجع: `E:\projects\WhiteVPN\build\engines\pr-integration`، با خواندن از commit `bf4adc5f72b36b9443ae5457782f4f1648984efc`. مسیرهای زیر نسبت به این ریشه‌اند؛ working tree و تغییرات جدید بدون بررسی استفاده نشوند.

- `app/build.gradle.kts` — version/code انتشار و dependencies.
- `docs/specs/connection-engines.md` — scope، رفتار و پذیرش گزارش‌شده؛ محدودیت‌های Conjure/DNS/IKEv2.
- `app/src/main/java/com/whitedns/vpn/EngineProfiles.kt`، `EngineSettingsPolicy.kt` و `BackendOwnership.kt` — انتخاب، validation، capabilities و lease.
- `EngineProfileStore.kt`، `EngineProfileTester.kt`، `EngineRuntimeYaml.kt` و `EngineTrafficState.kt` در همان مسیر — storage/test/synthetic/metrics.
- `SavedProfilesUi.kt`، `EngineProfilesUi.kt`، `EngineFormStyle.kt` و `PsiphonRegions.kt` — navigation، فیلدهای واقعی و country selector.
- `AmneziaConfigImport.kt`، `AmneziaEngineBackend.kt`، `SshEngineBackend.kt`، `TorEngineBackend.kt`، `TorControlConnection.kt`، `MobileEngineBackends.kt` و `PlatformIkev2Controller.kt` — رفتار backendها.
- `native/engines/sources.json`، `tor-inputs.json`، `zeddns-dot-validation_test.go`، `native/amneziawg/go.mod` و `native/amneziawg/test-gateway/README.md` — pins، patch و fixture.
- `scripts/build-flclash-core.sh`، `scripts/patches/flclash-v1.19.30.patch` و `scripts/patches/mihomo-v1.19.30-flclash.patch` — core delta، policy و build provenance.
- `app/src/test/java/com/whitedns/vpn/` و `app/src/androidTest/java/com/whitedns/vpn/` — تست‌های config/import/ownership/policy و navigation/native acceptance.

### فایل‌های بررسی‌شدهٔ مقصد در `E:\projects\WhiteVPN-Desktop`

`desktop/ANDROID-PARITY.md`، `desktop/app.go`، `desktop/mihomo_connect.go`، `desktop/main.go`، `desktop/internal/session/session.go`، `desktop/internal/engine/{spawn.go,pipe_security.go}`، `desktop/internal/profiles/{store.go,backup.go}`، `desktop/internal/model/{types.go,whitevpn_settings.go}`، `desktop/internal/mihomoconf/config.go`، `desktop/internal/firewall/firewall.go`، `desktop/frontend/src/{App.tsx,types.ts,wails.ts,i18n.ts}`، `desktop/Makefile`، `.github/workflows/{ci.yml,desktop-release.yml}`، README و `memory.md`.

فایل‌های integration اضافه: `desktop/whitevpn_nodes.go`، `whitedns_vpn.go`، `whitevpn_settings.go`، `manual_nodes.go`، `v2ray.go`، `whitevpn_measure.go` و `reset.go`؛ تغییر انتخاب، public DTO و gate مالکیت باید مسیرهای آن‌ها را پوشش دهد.

**اقدام اول برای اجرا:** evidence موجود را در P0a ثبت کن؛ ADRهای P0b و core delta در P0c را ببند؛ سپس P1/P2 را با fake backend و adapter اصلاح‌شدهٔ Mihomo تحویل بده. پس از آن هر شش backend واقعی با fixture و gate خودش وارد محصول شود. محدودیت upstream به task رفع/port یا زیرقابلیت تکمیلی تبدیل شود؛ موجب حذف یکی از شش موتور پایه نشود.

## ۱۷. backlog اجرایی موتورهای شش‌گانه

این taskها بعد از قرارداد P1/P2 اجرا شوند؛ هر ردیف خروجی قابل بررسی دارد.

| شناسه | کار اجرایی | خروجی پذیرش |
| --- | --- | --- |
| SSH-1 | config/validation و trust store مستقل؛ password/key/passphrase | fixture کلید/رمز و host-key first-use/change |
| SSH-2 | client، SOCKS TCP، cancellation و synthetic integration | HTTPS و سه mode؛ ده reconnect بدون نشت |
| PSI-1 | config parity و bootstrap/public verification keys؛ worker build دو target | artifact/protocol manifest و notice sanitisation |
| PSI-2 | region UI/cache، Auto/CDN/Direct و lifecycle | HTTPS/traffic/stop واقعی و کشور requested/observed جدا |
| TOR-1 | build/fetch Tor core، transportها و دادهٔ geoip با pin/licence | x64 و native ARM64 package صحیح |
| TOR-2 | torrc generator، bridge validation، SAFECOOKIE و process tree | Direct/obfs4/Snowflake، progress، cancel/stop و route proof |
| TOR-3 | port Conjure dependency و transport fixture | تکمیلی T1، artifact دو target و HTTPS واقعی |
| DNS-1 | worker DNSTT/VayDNS/MasterDNS و typed config/DoT patch | build/protocol و golden builder هر سه نوع |
| DNS-2 | server/resolver fixture و synthetic integration | transportهای مؤثر، TLS negative، HTTPS و shutdown |
| AWG-1 | importer/corpus v3 و editor؛ secret-free preview | ورودی معتبر/malformed بدون fetch یا Save خودکار |
| AWG-2 | worker/Wintun، endpoint exclusion، adapter/route/DNS/MTU owner | native TCP/UDP، full/private routes و counters |
| AWG-3 | app split design و implementation | تکمیلی T2، include/exclude و driver/signing در صورت نیاز |
| IKE-1 | typed auth mapping، phonebook/controller و certificate picker | EAP-MSCHAPv2 و certificate fixture موفق |
| IKE-2 | session handle، native readiness، stop/recovery و stats spike | owned route proof، عدم قطع foreign VPN و release pending |
| IKE-3 | PSK/identity mapping یا backend جایگزین | تکمیلی T3 با config/wire parity و licence/privilege review |

## ۱۸. ADRها و وضعیت تصمیم‌ها

| ADR | تصمیم برنامه | شواهد باقی‌مانده برای بستن |
| --- | --- | --- |
| A01: مرجع | سورس immutable bf4adc5/code86 | artifact منتخب و delta checklist |
| A02: storage | Windows vault برای credentialهای جدید و موجود؛ Public DTO جدا؛ مسیر versioned/generation commit | prototype DPAPI/replace، fault injection و binary downgrade |
| A03: lifecycle | SessionManager واحد؛ active snapshot ثابت؛ stop تأییدشده و release pending | adapter واقعی و fake-backend failure matrix |
| A04: privilege | UI asInvoker؛ helper protected، named pipe authenticated و Job Object | elevation با دو نوع حساب و crash/UAC cancel |
| A05: core | delta Mihomo 1.19.30/patchهای مرجع با adaptation Windows | انتخاب commit نهایی، artifact و regression |
| A06: AWG | helper v3 و Wintun signed هر معماری؛ app split تکمیلی | native route/DNS/ABI و feasibility WFP |
| A07: IKE | native RAS برای حداقل EAP/password و certificate؛ PSK تکمیلی | server mapping/identity، stop completion و stats |
| A08: Tor | Direct/obfs4/Snowflake required؛ Conjure Windows port تکمیلی؛ Tor core ARM64 required | C build ARM64 و hardware؛ Conjure socket/NAT/runtime |

تصمیم‌های این جدول مبنای implementation هستند؛ جای evidence را نمی‌گیرند. اگر prototype انتخاب را رد کرد، ADR با دلیل و مسیر جایگزین بازنگری شود و task تحویل موتور همچنان باز بماند.
