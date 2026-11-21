**وضعیت اجرای پلن شش موتور — ۲۰۲۶-۱۰-۰۴**

پلن: [برنامهٔ اصلی](/E:/projects/WhiteVPN-Desktop/WINDOWS-ANDROID-1.7.0-BETA1-PLAN_FA.md). اجرای implementation آغاز شده؛ این فایل وضعیت واقعی تحویل را نشان می‌دهد.

**تحویل فعلی: زیرساخت پروفایل‌های شش موتور، قرارداد اولیهٔ مدیریت session، مهاجرت state/cache فعلی Windows به DPAPI و قرارداد state عمومی/editor/backup نسخهٔ ۲.** اتصال واقعی backendهای جدید هنوز وارد مسیر محصول نشده است.

| مرحله | انجام‌شده | باقی‌مانده |
| --- | --- | --- |
| P0a | مرجع bf4adc5 و ورودی‌های source manifest ثبت؛ baseline قبلی موجود | manifest artifact نهایی و delta checklist |
| P0b/P0c | شواهد compile قبلی و انتخاب vault ثبت | IKE/certificate fixture، Tor core ARM64، protected helper و core adaptation |
| P1 | مدل نوع‌دار شش موتور، validation، policy اولیه، catalog رمزگذاری‌شدهٔ DPAPI، CRUD Wails و binding TypeScript؛ state/cache در vault و cleanup legacy؛ state عمومی، editor و Share صریح، backup v2 بدون credential و restore با credential-required | downgrade با executable قدیمی، transaction انتخاب route، backup metadata catalog جدید و faultهای چندفرایندی/قطع برق |
| P2 | manager مستقل با preflight-before-stop، عمر مستقل اتصال، generation، cancel/join و release pending؛ تست failure matrix | adapter Mihomo و اتصال به App/tray، journal durable، coordinator تست و helper privileged |
| P3–P8 | قراردادهای profile/editor آماده | UI پروفایل‌ها، importer کامل AWG و backend/fixture/runtime شش موتور |
| P9 | build/vet/frontend، race بسته‌های جدید و API پروفایل، cross-build پکیج‌های داخلی Windows ARM64 و Linux AMD64 پاس | package، UAC، شبکهٔ واقعی و سخت‌افزار ARM64 |

فایل‌های اصلی:

- [مدل و validation](/E:/projects/WhiteVPN-Desktop/desktop/internal/engineprofiles/profile.go)
- [catalog و optimistic revision](/E:/projects/WhiteVPN-Desktop/desktop/internal/engineprofiles/store.go)
- [snapshot رمزگذاری‌شده](/E:/projects/WhiteVPN-Desktop/desktop/internal/securestore/store.go)
- [DPAPI و ACL Windows](/E:/projects/WhiteVPN-Desktop/desktop/internal/securestore/windows.go)
- [API پروفایل‌ها](/E:/projects/WhiteVPN-Desktop/desktop/engine_profiles.go)
- [قرارداد مدیریت اتصال](/E:/projects/WhiteVPN-Desktop/desktop/internal/sessionmanager/manager.go)
- [تصمیم vault و حدود فعلی](/E:/projects/WhiteVPN-Desktop/docs/implementation/ADR-002-ENGINE-VAULT.md)
- [گزارش بخش دوم: مهاجرت state و cache](/E:/projects/WhiteVPN-Desktop/docs/implementation/LEGACY-VAULT-MIGRATION_FA.md)
- [گزارش بخش سوم: state عمومی، editor و backup](/E:/projects/WhiteVPN-Desktop/docs/implementation/PUBLIC-STATE-BACKUP_FA.md)

GetEngineAvailability فعلاً backendهای جدید را available اعلام نمی‌کند. وجود config، compile dependency یا manager با fake backend، تأیید اتصال واقعی نیست. مسیر فعلی Mihomo هنوز به manager جدید منتقل نشده و رفتار selected/active جدید نیز هنوز در UI اعمال نشده است.

تست‌های جدید شامل DPAPI واقعی، purpose mismatch، tampering، ACL، شکست commit، حفظ snapshot قبلی، عدم secret در list/event، editor قدیمی، save هم‌زمان، reset بدون بازگرداندن credential، cancellation، readiness دیررس، cleanup شکست‌خورده، preflight نامعتبر و callback متعلق به session قدیمی هستند.

آخرین بررسی کامل: **۶۶۰ تست پاس، صفر شکست، ۸ skip، ۱۴ package موفق**. [checks بخش سوم و حدود پذیرش](/E:/projects/WhiteVPN-Desktop/docs/implementation/public-state-checks.json)؛ [checks بخش دوم](/E:/projects/WhiteVPN-Desktop/docs/implementation/legacy-state-checks.json)؛ [checks زیرساخت اولیه](/E:/projects/WhiteVPN-Desktop/docs/implementation/engine-foundation-checks.json). build/vet، race بسته‌های model/storage/manager و APIهای مرتبط، TypeScript، frontend و cross-build کامل desktop در Windows ARM64 پاس شده‌اند. هفت سناریوی UI با Chrome و bridge آزمایشی Wails پاس شده است؛ اجرای package و اتصال واقعی شش موتور جزو این نتیجه نیستند.

ادامهٔ اجرای لازم: بستن تصمیم‌های P0b/P0c و gateهای باقیماندهٔ P1، سپس wiring manager/adapter Mihomo در P2؛ ورود backendهای واقعی با SSH و fixture محلی شروع شود و هر شش خانواده طبق حداقل تحویل پلن ادامه یابند.
