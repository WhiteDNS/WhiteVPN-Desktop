**گزارش بررسی فنی پلن انتقال Android 1.7.0-beta.1 به Windows**

تاریخ: ۲۰۲۶-۱۰-۰۴. سند بررسی‌شده: [پلن اصلی](/E:/projects/WhiteVPN-Desktop/WINDOWS-ANDROID-1.7.0-BETA1-PLAN_FA.md). مقصد: Desktop commit `ee482dc8a7638e4ece21adb2bbe05b31ae1dff94`.

**نتیجه: معماری پیشنهادی قابل دفاع است؛ سند با اصلاحات زیر برای اجرا آماده می‌شود. در وضع فعلی، تأیید برنامهٔ کامل یا تعهد به برابری کامل با اندروید توصیه نمی‌شود.** آماده‌سازی قراردادها و زیرساخت قابل شروع است؛ دامنهٔ امنیت داده، مرجع انتشار، قرارداد توقف و جدول امکانات الزامی باید پیش از تثبیت P1/P2 روشن شوند.

این گزارش از خواندن تمام ۱۶ بخش سند، تطبیق کدهای مؤثر Android/Desktop، بررسی مرجع انتشار، اجرای بررسی‌های فعلی Windows و آزمایش کامپایل dependencyهای اصلی تهیه شده است. موارد زیر شامل نقص سند، ناسازگاری کد موجود با رفتار هدف و ریسک‌های هنوز اثبات‌نشده هستند؛ همهٔ آن‌ها باگ پیاده‌سازی جدید محسوب نمی‌شوند. سند اصلی و کد محصول تغییر نکرده‌اند.

**۱. مرجع واقعی انتشار پیدا شد**

ابهام بخش ۱ سند اکنون تا سطح سورس قابل رفع است. [صفحهٔ رسمی انتشار](https://github.com/WhiteDNS/WhiteVPN/releases/tag/v1.7.0-beta.1) نسخهٔ Experimental را با commit `bf4adc5` معرفی می‌کند؛ این انتشار روی مبنای 1.6.10 ساخته شده است. checkout جداگانهٔ محلی نیز همان commit کامل را دارد:

| موضوع | نتیجهٔ بررسی |
| --- | --- |
| Android release commit | `bf4adc5f72b36b9443ae5457782f4f1648984efc` |
| مسیر checkout انتشار | `E:\projects\WhiteVPN\build\engines\pr-integration` |
| نسخه در سورس commit | `1.7.0-beta.1`، `versionCode=86` |
| checkout اصلی مورد استفادهٔ پلن | HEAD `5f05cde…`، نسخهٔ 1.6.7/code83، با تغییرات محلی |
| وضعیت checkout انتشار | دارای تغییرات پس از انتشار؛ برای مرجع باید `git show bf4adc5:…` استفاده شود |
| APK محلی مطابق رکورد ذخیره‌شدهٔ publication | SHA-256: `c703c66183fb0e0149e193266c65c5ee7cd6f0d5a0de5cd9d0439250d4e01494` |
| rebuild محلی دیگر با همان نسخه | SHA-256: `a99e1e82049497c6af304b1bab7cfa92fda35a17f9f8c65ed1f0cae4abb118c0` |

هر دو APK ARM64 با ابزار Android بررسی شدند: version/code یکسان و امضای v2 معتبر با certificate SHA-256 `9a6d44c8b8d2a8b6ed56bdfc7259b41e817520428cb823a12857b445ad8d27b6`. یکسان‌بودن نسخه، یکسان‌بودن artifact را ثابت نمی‌کند. digest نخست با رکورد publication محلی تطبیق دارد؛ hash فایل جاری روی GitHub در این بررسی مستقلاً دریافت و تأیید نشده است، چون اطلاعات assets صفحه در دسترس نبود.

در مقایسهٔ ۱۵ فایل کلیدی working tree اصلی با سورس immutable انتشار، پس از یکسان‌سازی line ending، ۱۳ فایل برابر بودند؛ `PlatformIkev2Controller.kt` و `SavedProfilesUi.kt` اختلاف داشتند. بنابراین فهرست قابلیت‌های سند عمدتاً معتبر است، ولی مبنای build/runtime و جزئیات integration باید با commit انتشار reconcile شوند. تغییرات جدید `AmneziaTuning` در checkout کثیفِ انتشار، جزو این مرجع immutable نیستند.

شواهد: [هویت مرجع](/E:/projects/WhiteVPN-Desktop/docs/reviews/windows-android-1.7.0-beta1-baseline/reference-identity.json)، [مقایسهٔ سورس](/E:/projects/WhiteVPN-Desktop/docs/reviews/windows-android-1.7.0-beta1-baseline/android-source-comparison.json)، [بررسی امضای APK](/E:/projects/WhiteVPN-Desktop/docs/reviews/windows-android-1.7.0-beta1-baseline/published-android-beta-apk-signature.log).

**۲. baseline فعلی Desktop واقعاً اجرا شد**

| بررسی | نتیجه | حدود نتیجه |
| --- | --- | --- |
| TypeScript: `tsc --noEmit --noUnusedLocals` | موفق | بررسی نوع و متغیرهای بلااستفاده |
| frontend: `npm run build` | موفق | هشدار اندازهٔ chunk؛ مانع build نیست |
| `go build ./...` | موفق | روی Windows AMD64 فعلی |
| `go vet ./internal/... .` | موفق | تحلیل ایستای مسیرهای مشخص |
| `go test -json -count=1 -timeout 180s ./internal/... .` | ۵۸۱ پاس، صفر شکست، ۸ skip؛ ۱۱ package موفق | تست‌های live منتخب اجرا نشدند |
| Windows ARM64: `go build ./internal/...` | موفق | فقط cross-compile پکیج‌های داخلی؛ نه UI کامل یا runtime |
| `desktop/cores/wintun.dll` | PE AMD64، امضای Authenticode معتبر | artifact فعلی ARM64 نیست |

ابزارها: Go `1.26.5`، Node `v24.19.0` و npm `11.17.0`. test race اجرا نشد. هشت skip شامل یک تست مخصوص macOS، پنج تست نیازمند catalogue/live environment و دو تست override/absence core است که در Windows عمداً skip می‌شوند.

در پوشهٔ فعلی `desktop/cores` فایل Mihomo executable وجود ندارد؛ `.keep` و `wintun.dll` موجودند. embed/build موفق، بستهٔ اجرایی کامل یا اتصال واقعی Mihomo را ثابت نمی‌کند. MSI/ZIP، UAC، تغییر شبکه، آزمون فیزیکی ARM64 و اتصال سرور واقعی در این بررسی انجام نشده‌اند.

شواهد: [نتایج تجمیعی](/E:/projects/WhiteVPN-Desktop/docs/reviews/windows-android-1.7.0-beta1-baseline/checks.json)، [تعداد و علت skipها](/E:/projects/WhiteVPN-Desktop/docs/reviews/windows-android-1.7.0-beta1-baseline/summary.json)، [خروجی کامل تست Go](/E:/projects/WhiteVPN-Desktop/docs/reviews/windows-android-1.7.0-beta1-baseline/go-test.jsonl).

**۳. امکان ساخت dependencyهای اصلی روی Windows بررسی شد**

آزمایش‌ها با `GOOS=windows`، دو مقدار `GOARCH=amd64/arm64`، `CGO_ENABLED=0`، Go 1.26.5 و module cache موجود، بدون تغییر سورس مرجع انجام شدند. برای Psiphon/DNS، moduleهای probe از build اندروید و local replaceهای pin‌شده استفاده کردند. این آزمایش helper نهایی، IPC، driver یا routing را پیاده‌سازی نمی‌کند.

| ورودی آزمایش | x64 | ARM64 | تفسیر |
| --- | --- | --- | --- |
| Psiphon package، pin `83aa73b…` | کامپایل موفق | کامپایل موفق | مانع اولیهٔ کامپایل در این مسیر مشاهده نشد |
| zeddns با patch DoT موجود | کامپایل موفق | کامپایل موفق | runtime هر سه DNS tunnel هنوز باید اثبات شود |
| MasterDNS mobile package، pin `50b447b…` | کامپایل موفق | کامپایل موفق | تطبیق wire/config و server fixture باقی است |
| AWG v3 `v3.1.20260814`، پکیج‌های `device` و `tun` | کامپایل موفق | کامپایل موفق | اثبات helper و مسیر native نیست |
| obfs4 از lyrebird، pin `ad08585…` | executable ساخته شد | executable ساخته شد | handshake/network و مالکیت process هنوز آزموده نشده |
| Snowflake `v2.14.1`، client | executable ساخته شد | executable ساخته شد | اتصال واقعی هنوز آزموده نشده |
| Conjure client، pin `505cb48…` | شکست کامپایل | شکست کامپایل | ناسازگاری Windows در dependency DTLS |
| Tor C core | در این بررسی ساخته نشد | در این بررسی ساخته نشد | پشتیبانی کامل Tor از نتایج transportها نتیجه نمی‌شود |

خطای مشخص Conjure در `github.com/refraction-networking/conjure@v0.7.10/pkg/transports/connecting/dtls/nat.go:61,73` رخ می‌دهد: `int(fd.Fd())` به `syscall.SetsockoptInt` داده شده، درحالی‌که Windows در این API `syscall.Handle` می‌خواهد. این failure ناشی از کمبود module در cache نیست. صرف cast‌کردن هم صحت رفتار NAT/DTLS روی Windows را ثابت نمی‌کند؛ port/patch باید با آزمون transport انجام شود. در این وضعیت Conjure artifact معتبر Windows ندارد و پیش از رفع build باید unavailable باشد؛ experimental قابل اجرا مرحلهٔ بعد است.

در [صفحهٔ رسمی Tor](https://download.torproject.org/tor/) هنگام بررسی، expert bundle برای Windows i686/x86_64 درج شده بود و Windows ARM64 درج نشده بود. این مشاهده اثبات ناممکن‌بودن build ARM64 نیست؛ داشتن transport ARM64 به‌تنهایی جای Tor core ARM64 را نمی‌گیرد.

شواهد: [Psiphon/DNS](/E:/projects/WhiteVPN-Desktop/docs/reviews/windows-android-1.7.0-beta1-baseline/engine-build-probes.json)، [AWG](/E:/projects/WhiteVPN-Desktop/docs/reviews/windows-android-1.7.0-beta1-baseline/awg-build-probes.json)، [Tor transports](/E:/projects/WhiteVPN-Desktop/docs/reviews/windows-android-1.7.0-beta1-baseline/tor-build-probes.json)، [خطای Conjure](/E:/projects/WhiteVPN-Desktop/docs/reviews/windows-android-1.7.0-beta1-baseline/tor-conjure-amd64.log).

**۴. اصلاحات اولویت‌دار سند**

اولویت «بالا» یعنی تصمیم یا قرارداد باید پیش از تحویل زیرساخت مربوط ثبت شود؛ به معنی اثبات آسیب‌پذیری قابل بهره‌برداری نیست.

**R1 — بالا: مرجع بخش ۱ و P0 را از working tree به commit انتشار تغییر دهید.**

سند خطوط ۱۱–۱۹ و ۴۱۲ هنوز انتشار را نامشخص می‌داند. اکنون commit/code واقعی معلوم است. acceptance: یک manifest immutable شامل commit، patchها، toolchain، hash artifact منتخب و delta نسبت به checkout اولیه؛ تغییرات پس از انتشار جدا ثبت شوند. قسمت مربوط به hash asset عمومی تا تأیید مستقل، با همین محدودیت نوشته شود.

**R2 — بالا: اختلاف Mihomo بخشی از انتقال است و باید work item مستقل داشته باشد.**

[setup فعلی Desktop](/E:/projects/WhiteVPN-Desktop/desktop/scripts/setup-mihomo-core.sh:18) مبنای Mihomo 1.19.29 و FlClash `7c831855…`/patch `80362fc…` دارد. build commit انتشار Android، Mihomo 1.19.30 با upstream `ac017cdd…`، FlClash `ac2f6b91…`، دو patch محلی و Go 1.26.8 را تثبیت می‌کند. delta شامل رفتار AWG3 outbound، policy config/controller و cleanup socket است؛ این موضوع فراتر از افزودن engine profile است.

انتقال مستقیم policy اندروید مناسب نیست: محدودیت‌های port/TUN/DNS آن با dynamic port و native TUN دسکتاپ فرق دارد. acceptance: ADR تطبیق رفتار core و patchها، golden config و regression سلامت اتصال/cleanup؛ version مساوی به‌تنهایی معیار parity نباشد. ابزار probe این گزارش Go 1.26.5 بوده و بازتولید toolchain رسمی Android ادعا نشده است.

**R3 — بالا: دامنهٔ vault و «AppState بدون secret» در سند مبهم است.**

خط ۱۳۹ state را فقط metadata می‌داند؛ خطوط ۱۴۵ و ۴۳۰ ممنوعیت secret در AppState/backup را عمومی بیان می‌کنند، ولی خط ۱۵۸ حذف پیش‌فرض را برای engine secrets می‌گوید. مدل فعلی در [types.go](/E:/projects/WhiteVPN-Desktop/desktop/internal/model/types.go:124) دارای encryption key، UUID/password اتصال و SOCKS password است. [GetAppState](/E:/projects/WhiteVPN-Desktop/desktop/app.go:200) کل مدل را برمی‌گرداند و [backup](/E:/projects/WhiteVPN-Desktop/desktop/internal/profiles/backup.go:31) state را serialize می‌کند.

دو scope ممکن است: vault فقط engineهای جدید با استثناهای صریح برای دادهٔ legacy، یا انتقال تمام credentialهای مرتبط و جداسازی مدل داخلی از Public DTO. سند باید یکی را دقیق انتخاب کند؛ «همه بدون secret» با تغییر فقط engineهای جدید محقق نمی‌شود. inventory باید لینک‌ها/URLهای دارای token، snapshot مهاجرت و فایل runtime را نیز پوشش دهد. در انتخاب scope دوم، رفتار macOS/Linux موجود هم باید حفظ شود. acceptance: جست‌وجوی secret marker در state/event/export/log و مسیرهای legacy، همراه با تست editor/export صریحِ مجاز.

**R4 — بالا: schema جدید به‌تنهایی محافظ downgrade نیست.**

خط ۱۵۴ تضمین می‌دهد نسخهٔ قدیمی نتواند state جدید را overwrite کند. [Store.Load فعلی](/E:/projects/WhiteVPN-Desktop/desktop/internal/profiles/store.go:38) با `json.Unmarshal` فیلد ناشناخته را نادیده می‌گیرد؛ binary قدیمی از check اضافه‌شده به binary جدید خبر ندارد و هنگام save می‌تواند فیلدهای جدید را حذف کند.

راهکار باید versioned storage path، جداسازی دادهٔ جدید از فایل legacy، یا سازوکار سازگار دیگری باشد که نیازمند همکاری نسخهٔ قدیمیِ منتشرشده نباشد. acceptance: اجرای واقعی binary قدیمی روی دادهٔ upgrade‌شده و اثبات حفظ فایل‌ها/credentialها؛ تست parser نسخهٔ جدید کافی نیست.

**R5 — بالا: تراکنش بین state و vault برای CRUD عادی هم تعریف شود.**

atomic replace یک فایل، save/delete/restore دو فایل را اتمیک نمی‌کند. ترتیب migration MasterDNS در خط ۱۵۲ مناسب است، اما crash میان تغییر metadata و vault می‌تواند reference بدون credential یا credential orphan بسازد. acceptance: protocol مبتنی بر generation/journal یا catalog authoritative و reconciliation، قفل مشخص و fault injection در مرز هر write/replace؛ تکرار recovery باید idempotent و بدون حذف secret سالم باشد. snapshot plaintext قدیمی نیز باید محدود و دارای سیاست پایان عمر باشد.

**R6 — بالا: selected/active صرفاً دو badge نیست؛ مسیرهای قدیمی رفتار متفاوت دارند.**

طبق خط ۴۱، Select هنگام اتصال نباید اتصال جاری را عوض کند. [SaveWhiteVPNSelection](/E:/projects/WhiteVPN-Desktop/desktop/whitevpn_nodes.go:165) اکنون `applySelectionToLiveSession` را اجرا می‌کند و مسیر live را جابه‌جا می‌کند؛ [SelectSubscription](/E:/projects/WhiteVPN-Desktop/desktop/whitedns_vpn.go:237) انتخاب حین اتصال را رد می‌کند. [watchdog](/E:/projects/WhiteVPN-Desktop/desktop/mihomo_watchdog.go:47) pinned بودن را از state انتخابی می‌خواند؛ تغییر selected می‌تواند policy اتصال active را هم عوض کند.

acceptance: ActiveSessionPlan ثابت شامل route/profile revision، selection و تنظیمات مؤثر؛ runtime/watchdog/tray از snapshot فعال استفاده کنند. تمام APIهای انتخاب منبع، node، country و mode باید با قاعدهٔ جدید reconcile شوند. اگر «تعویض node فعال» یک اقدام مستقل مجاز است، نام و trigger آن صریح باشد. تست: انتخاب B در زمان اتصال A، قطع شبکه و recovery؛ A و policy آن تا اقدام صریح ثابت بمانند.

**R7 — بالا: adapter Mihomo باید semantics توقف را اصلاح کند.**

سند مفهوم release pending را درست مطرح کرده؛ ولی reuse فعلی نیازمند تغییر واقعی است. [stopMihomo](/E:/projects/WhiteVPN-Desktop/desktop/mihomo_connect.go:409) owner را با `swap(nil)` کنار می‌گذارد، خطای Close را نادیده می‌گیرد و Disconnected اعلام می‌کند. [adoptSession](/E:/projects/WhiteVPN-Desktop/desktop/mihomo_connect.go:378) next را پیش از Close قبلی adopt می‌کند؛ خطای Close قبلی نیز کنار گذاشته می‌شود. [Session.Close](/E:/projects/WhiteVPN-Desktop/desktop/internal/session/session.go:655) به توقف process تکیه دارد و قرارداد جامع resource evidence نیست.

acceptance: حفظ owner تا تأیید stop/cleanup؛ خطای توقف اتصال بعدی را مسدود کند؛ startup قبلی cancel و join شود؛ route/DNS/proxy جدا تأیید شوند. تست‌های stop timeout، startup دیررس، UAC cancel و helper crash باید با adapter واقعی نیز انجام شوند. صرف پوشاندن API قدیمی با interface جدید کافی نیست.

**R8 — بالا: Reset/Restore و تست‌های قدیمی به ownership مشترک متصل شوند.**

[ResetAppData](/E:/projects/WhiteVPN-Desktop/desktop/reset.go:34) status و pointer Mihomo را بررسی می‌کند؛ [ImportBackup](/E:/projects/WhiteVPN-Desktop/desktop/app.go:288) حالت Failed را مجاز می‌داند. در طراحی جدید ممکن است Failed همراه با release pending باشد؛ reset/restore نباید journal لازم برای recovery را حذف یا مدل owner فعال را جایگزین کند.

[shutdown](/E:/projects/WhiteVPN-Desktop/desktop/app.go:192) مسیر V2Ray tests و validator را لغو می‌کند، اما مسیر مستقل [StartNodeTest/CancelNodeTest](/E:/projects/WhiteVPN-Desktop/desktop/whitevpn_measure.go:59) نیز باید inventory و cancel/join مشترک داشته باشد. acceptance: عملیات مخرب داده و همهٔ تست‌ها، gate مالکیت و drain مشترک داشته باشند؛ status نمایشی مبنای اجازه نباشد. نقشهٔ بخش ۱۰ باید `reset.go`، `whitevpn_nodes.go`، `whitevpn_settings.go`، `manual_nodes.go`، `v2ray.go` و `whitevpn_measure.go` را نیز پوشش دهد.

**R9 — بالا: تحویل امن helper پیش‌نیاز P2 است، نه جزئیات آخر بسته‌بندی.**

مرز UI unelevated/helper elevated و هشدار TOCTOU سند درست است. [استخراج core فعلی](/E:/projects/WhiteVPN-Desktop/desktop/mihomo_connect.go:592) زیر config کاربر انجام می‌شود؛ hash روی فایل user-writable به‌تنهایی اعتبار اجرای elevated را تضمین نمی‌کند. callback [Supervise](/E:/projects/WhiteVPN-Desktop/desktop/internal/engine/spawn.go:40) نیز برای `exec.Cmd` تعریف شده، درحالی‌که child elevated همین ساختار را ندارد.

acceptance P2: محل نصب protected، verification و ارتباط PID/session، اعمال واقعی Job Object روی مسیر elevation و UAC با حساب admin متفاوت. P9 می‌تواند installer نهایی را تکمیل کند، اما primitive امن اجرای helper نباید تا آن زمان عقب بیفتد. [مستند Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) مبنای رفتار process tree است؛ پاک‌شدن route/DNS همچنان بررسی جدا می‌خواهد.

**R10 — متوسط: LAN auth باید کلاینت‌های محلی فعلی را هم حفظ کند.**

سند به‌درستی LAN را پیش از auth unavailable می‌داند. مسیر [Render فعلی](/E:/projects/WhiteVPN-Desktop/desktop/internal/mihomoconf/config.go:395) AllowLAN را اعمال می‌کند ولی authentication نمی‌سازد. در [تنظیمات رسمی Mihomo](https://wiki.metacubex.one/en/config/general/)، authentication روی ورودی HTTP/SOCKS/mixed اثر دارد و skip-auth-prefixes وجود دارد؛ اضافه‌کردن auth عمومی ممکن است system proxy و probeهای محلی فاقد credential را قطع کند.

acceptance: قرارداد مشخص برای loopback، مثلاً exemption فقط `127.0.0.1/32` و `::1/128` یا listener جدا، بدون معاف‌کردن LAN؛ تست کلاینت محلی و دستگاه دوم authenticated/unauthenticated و تغییر profile شبکه. بسته‌شدن listener/controller/DNS و firewall cleanup نیز مستقل بررسی شوند.

**R11 — متوسط: readiness native برای split/private tunnel دقیق‌تر تعریف شود.**

خطوط ۲۱۲/۲۲۴ به‌درستی handshake را کافی نمی‌دانند، اما HTTPS عمومی ثابت برای پروفایل AllowedIPs محدود ممکن است هیچ route مجازی نداشته باشد. probe مستقیم خارج از تونل هم false positive ایجاد می‌کند. acceptance: endpoint probe سازگار با routeهای profile، هویت interface/LUID و شواهد route متعلق به session؛ حالت private/intranet و full tunnel جدا تعریف شوند. DNS probe و route endpoint فیزیکی نباید bypass پنهانی ایجاد کنند.

**R12 — متوسط: نگاشت IKEv2 و completion توقف به API مشخص وصل شوند.**

احتیاط سند دربارهٔ PSK صحیح است. [Add-VpnConnection](https://learn.microsoft.com/en-us/powershell/module/vpnclient/add-vpnconnection?view=windowsserver2025-ps) پارامتر `L2tpPsk` دارد؛ این اثبات پشتیبانی PSK برای IKEv2 نیست. certificate احراز هویت با EAP-TLS، machine certificate و keypair Android باید برای هر auth نوع‌دار و server fixture جدا نگاشت شود.

همچنین موفقیت [RasHangUpW](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rashangupw) به معنی پایان فوری state machine نیست. completion باید با polling محدودِ status و resource evidence تأیید شود؛ timeout همان release pending باشد. برای آمار، [RasGetConnectionStatistics](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasgetconnectionstatistics) آمار HRASCONN را می‌دهد؛ امکان استفادهٔ connection-scoped را می‌توان spike کرد. وجود API بدون نتیجهٔ fixture، اجازهٔ نمایش آمار معتبر نمی‌دهد.

**R13 — متوسط: هزینهٔ driver پایهٔ AWG را از app split جدا کنید.**

Wintun فعلی AMD64 است. [توزیع رسمی Wintun](https://www.wintun.net/) DLLهای امضاشدهٔ AMD64/ARM64 را ارائه می‌کند؛ برای backend مبتنی بر این artifactها، الزام ساخت و امضای driver اختصاصی از ابتدا نتیجه نمی‌شود. driver احتمالی WFP برای app split موضوع دیگری است. acceptance: stage جدا برای هر target، PE/DLL ABI/hash/signature/license و آزمون واقعی adapter؛ از یک DLL مشترک برای همهٔ معماری‌ها استفاده نشود.

**R14 — بالا برای تعهد انتشار: required/optional به جدول قابل اجرا تبدیل شود.**

خط ۴۲۹ همهٔ شش خانواده را معیار پایان می‌داند، خط ۴۴۳ زیرقابلیت unavailable را در بتا مجاز می‌داند و خط ۴۰۰ required را شرط fail build قرار می‌دهد؛ جدول دقیقی از requiredها وجود ندارد. acceptance: به ازای engine × transport/auth × architecture × mode یکی از Beta-required، Experimental/optional یا Full-parity-required ثبت شود؛ همان manifest در CI و UI مصرف شود. Conjure build، Tor ARM64، IKE PSK و AWG app split باید خانهٔ مستقل داشته باشند.

**۵. ارزیابی پوشش همهٔ بخش‌های سند**

| بخش | ارزیابی |
| --- | --- |
| ۱: مرجع | نیازمند اصلاح با release immutable؛ R1/R2 |
| ۲: دامنه و قواعد | مناسب؛ تعارض انتخاب قدیمی و scope امنیت باید حل شود |
| ۳: فاصلهٔ فعلی | عمدتاً مطابق کد؛ build probes و core delta به‌روز شوند |
| ۴: معماری | SessionManager/capabilities/ownership مناسب؛ R6–R9 معیار اجرایی آن هستند |
| ۵: storage/migration | DPAPI user scope مناسب؛ R3–R5 پیش‌نیاز پذیرش |
| ۶: موتورهای مستقل | جزئیات SSH/DNS/import خوب؛ Tor/Conjure/IKE/AWG همچنان conditional |
| ۷: تنظیمات مؤثر | policy مرکزی مناسب؛ loop bypass و auth local باید fixture شوند |
| ۸: UI/API | draft، RTL/LTR، secret field و availability مناسب؛ قرارداد DTO بعد از R3 |
| ۹: تست و آمار | تفکیک test session و main owner مناسب؛ R8/R11/R12 لازم |
| ۱۰: نقشهٔ فایل‌ها | مسیرهای انتخاب/test/reset قدیمی ناقص‌اند؛ R8 |
| ۱۱: مراحل | ترتیب کلی درست؛ وابستگی core و helper امن زودتر مشخص شود |
| ۱۲: پذیرش | ماتریس runtime قوی؛ baseline اجراشده و حدود آن جایگزین خط ۳۹۲ شود |
| ۱۳: build/release | provenance و architecture مناسب؛ required manifest و driver distinction لازم |
| ۱۴: ریسک‌ها | واقعی و مفید؛ build failure Conjure و storage downgrade اضافه شوند |
| ۱۵: پایان کار | نیازمند دو checklist مستقل «بتای قابل استفاده» و «برابری کامل» |
| ۱۶: منابع | مرجع checkout انتشار و فایل‌های integration Desktop اضافه شوند |

نقاط قوت اصلی سند: Save/Select/Connect جدا، عدم fallback پنهان، یک owner اصلی، stale event با generation، تفکیک UDP transport و UDP برنامه، محدودیت import/decompression، SSH fingerprint trust، عدم تحمیل محدودیت API اندروید به Windows و پذیرش واقعی ARM64. این اصول حفظ شوند.

**۶. ترتیب اجرای پیشنهادی پس از اصلاح**

1. P0a: ثبت commit/artifact منتخب و core delta؛ baseline این گزارش به‌عنوان evidence اولیه استفاده شود.
2. P0b: تصمیم storage scope و downgrade، feasibility native auth/app split، Tor core ARM64/Conjure و جدول Beta-required. کامپایل dependencyهایی که اینجا موفق بودند تکرار غیرضروری نشود؛ helper/runtime هنوز لازم است.
3. P1: DTO عمومی و catalog/vault transaction با migration/recovery و fault injection؛ خروجی بدون secret قابل بررسی شود.
4. P2: ownership واقعی، adapter Mihomo اصلاح‌شده، cancel/join مشترک، helper امن و journal. native start پیش از اثبات Stop/cleanup وارد مسیر اصلی نشود.
5. P3–P8: UI و موتورهای واقعی طبق manifest، با fixture و acceptance مستقل هر ترکیب. engine فاقد artifact یا auth اثبات‌شده unavailable بماند.
6. P9: regression کامل، LAN روی دستگاه دوم، package/signature، upgrade/uninstall و Windows واقعی x64/ARM64؛ سپس candidate قابل بررسی برای انتشار.

جمع ۵۲–۸۰ نفرروز از نظر حساب درست است؛ برای یک نفر تقریباً ۱۱–۱۶ هفتهٔ کاری. این عدد برآورد scope پایه است و تعهد full parity نیست. هزینهٔ Conjure Windows port، Tor ARM64، گسترده‌شدن credential migration، backend جایگزین IKEv2 و WFP app split هنوز تثبیت نشده است. P0 با مجموع build spikeها، تصمیم API/driver، fixture و سخت‌افزار را نباید صرفاً به ۲–۳ روزِ تضمین‌شده تبدیل کرد. برآورد تازه پس از ADRهای اثرگذار انجام شود؛ عدد جایگزین بدون evidence پیشنهاد نمی‌شود.

**۷. معیار تصمیم نهایی**

پایهٔ Desktop در بررسی‌های اجراشده سالم بود و برای بخشی از dependencyها امکان کامپایل Windows دو معماری تأیید شد. با این حال، هنوز شواهد کافی برای تأیید اجرای کامل شش خانواده، امنیت تمام credentialهای legacy، پشتیبانی runtime ARM64 یا برابری کامل با Android وجود ندارد. نتیجهٔ مناسب این بازبینی: **پذیرش جهت معماری، با اصلاح قراردادها و scope پیش از اجرای کامل؛ عدم تأیید ادعای parity یا آمادگی انتشار.**

SHA-256 سند اصلی هنگام بررسی: `6A9887EBB2D64011938924AB31421882D58B9A6CE005345E95829F420ED39A29`. گزارش و شواهد جدیدند؛ پلن اصلی و کد محصول دست‌نخورده‌اند.
