**بخش سوم اجرای پلن شش موتور: state عمومی، editor و backup — ۲۰۲۶-۱۰-۰۴**

قرارداد عمومی state فعلی دسکتاپ پیاده‌سازی شد. دریافت state و پاسخ‌های save/import، پیام‌های state و فهرست نودها اطلاعات اتصال خصوصی را به رابط کاربری نمی‌فرستند. اطلاعات کامل برای ویرایش و اشتراک‌گذاری از API صریح دریافت می‌شود. ذخیره‌سازی داخلی همچنان اطلاعات کامل را نگه می‌دارد و در Windows production به vault مرحلهٔ قبل می‌نویسد.

| مسیر | رفتار پیاده‌شده |
| --- | --- |
| `GetAppState` و پاسخ‌های شامل `AppState` | snapshot مستقل؛ بدون کلید DNS، SOCKS username/password، UUID/password/auth، کلید خصوصی/PSK WireGuard، raw outbound/stream/header/XHTTP، REALITY short ID و مسیرهای transport حساس |
| اشتراک‌ها | URL کامل حذف؛ فقط scheme و host برای نمایش باقی می‌ماند؛ مسیر، query و userinfo به جدول نمی‌روند |
| DNS سفارشی | endpoint کامل فقط در editor تنظیمات؛ تغییر عادی تنظیمات با state عمومی، endpoint ذخیره‌شده را پاک نمی‌کند |
| editor | نود دستی، اشتراک، تنظیمات و API پروفایل‌های legacy اطلاعات کامل را جداگانه دریافت می‌کنند؛ ذخیرهٔ profile/subscription با DTO عمومی رد می‌شود |
| فهرست نودها و event اندازه‌گیری | `link` خالی و `shareAvailable` موجود؛ لینک داخلی برای parser/cache حفظ می‌شود |
| Share و export گروهی | لینک فقط برای نام‌های درخواست‌شده از cache همان منبع؛ درخواست موجب fetch یا انتخاب منبع دیگر نمی‌شود |
| پیام‌ها | URLهای شناخته‌شده در state، log، خطای نود و eventهای متنی حذف می‌شوند؛ این ادعای پاک‌سازی هر secret دلخواه در هر متن نیست |

Public state کپی مستقل آرایه‌ها و mapها دارد. آرایه‌های ضروری تنظیمات حتی در حالت خالی `[]` هستند؛ smoke مرورگر نشان داد تبدیل آن‌ها به `null` dashboard را خراب می‌کند، بنابراین این رفتار با تست رگرسیون تثبیت شد. وضعیت cleared resolver در runtime همان قرارداد قبلی خود را حفظ می‌کند. مقایسهٔ memoized پروفایل‌های UI نیز تغییر `credentialRequired` و `credentialsReady` را در نظر می‌گیرد.

Backup پیش‌فرض schema قبلی `whitedns.desktop.backup` با **نسخهٔ ۲** است. رمزها، کلیدها، URL کامل اشتراک و raw configهای فوق در آن قرار نمی‌گیرند؛ runtime نیز reset می‌شود. متن فایل resolver پیش از خروجی به آدرس‌های معتبر محدود می‌شود. تنظیماتی که اطلاعات اتصالشان حذف شده است، با `credentialRequired` برمی‌گردند. URL خالی موجب حذف اشتراک یا تغییر انتخاب به اشتراک دیگر نمی‌شود؛ DNS سفارشی خالی به سرویس پیش‌فرض تبدیل نمی‌شود. اتصال، cache و fallback برای منبعی که اطلاعاتش ناقص است پیش از fetch متوقف می‌شوند. نود دستی ناقص در فهرست قابل ویرایش و حذف می‌ماند.

Import نسخهٔ ۱ برای backupهای قدیمی حفظ شده و در Windows production اطلاعات کامل آن را در vault ثبت می‌کند. نسخهٔ ۲ حتی اگر دستی با credential دستکاری شود، آن فیلدها را وارد نمی‌کند. Backup فاقد state یا دارای `state: null` رد می‌شود. Restore هنگام مالکیت session Mihomo نیز رد می‌شود، حتی اگر status اشتباهاً disconnected باشد. شکست خواندن resolver بعدی یا commit باعث حذف فایل‌های تازهٔ restore می‌شود؛ فایل‌ها و snapshot قبلی حفظ می‌شوند. این rollback شکست عادی برنامه را پوشش می‌دهد؛ اثبات قطع برق فیزیکی و journal چندفرایندی هنوز باقی است.

اطلاعات اتصال با واردکردن دوبارهٔ URL اشتراک یا ویرایش نود دستی تکمیل می‌شود. Share همچنان خروجی صریح حاوی اطلاعات اتصال است و عمداً با backup عمومی تفاوت دارد. در وضعیت فعلی اگر یکی از نودهای دستی به تکمیل اطلاعات نیاز داشته باشد، اتصال کل منبع manual مسدود است تا آن نود اصلاح یا حذف شود؛ این محدودیت محافظه‌کارانه به fallback پنهان اجازه نمی‌دهد.

فایل‌های اصلی:

- [قرارداد public state و JSON](/E:/projects/WhiteVPN-Desktop/desktop/internal/model/public_state.go)
- [APIهای editor و Share](/E:/projects/WhiteVPN-Desktop/desktop/public_editors.go)
- [backup نسخهٔ ۲ و rollback](/E:/projects/WhiteVPN-Desktop/desktop/internal/profiles/backup.go)
- [تست مرز API، restore و هم‌زمانی](/E:/projects/WhiteVPN-Desktop/desktop/public_state_test.go)
- [تست backup و شکست commit](/E:/projects/WhiteVPN-Desktop/desktop/internal/profiles/public_backup_test.go)
- [رابط کاربری](/E:/projects/WhiteVPN-Desktop/desktop/frontend/src/App.tsx)
- [smoke مرورگر قابل تکرار](/E:/projects/WhiteVPN-Desktop/desktop/scripts/public-state-ui-smoke.cjs)

بررسی مرورگر با Chrome headless و bridge شبیه‌سازی‌شدهٔ Wails انجام شد؛ fixture از API واقعی Go با credentialهای ساختگی تولید می‌شود. هفت سناریو پاس شدند: دریافت صرفاً state عمومی در dashboard، Share صریح، حفظ credential در editor نود دستی، export گروهی، کنارگذاشتن پاسخ دیررس Share پس از navigation، حفظ URL در editor اشتراک و ذخیره/بارگذاری مجدد تغییر صرفاً خصوصی DNS. خطای JavaScript یا promise ثبت نشد. این تست جای اجرای executable بسته‌بندی‌شدهٔ Wails یا اتصال شبکهٔ واقعی را نمی‌گیرد.

تکرار smoke از ریشهٔ پروژه در PowerShell، پس از build frontend:

```powershell
$env:GOCACHE = "$PWD/.cache/desktop-engines-go"
$env:WHITEVPN_PUBLIC_UI_FIXTURE_OUT = "$PWD/.cache/public-ui-fixture.json"
go -C desktop test . -run '^TestPublicUIFixture$' -count=1
Remove-Item Env:WHITEVPN_PUBLIC_UI_FIXTURE_OUT
node desktop/scripts/public-state-ui-smoke.cjs
```

Script از Chrome نصب‌شده، profile موقت اختصاصی و localhost استفاده می‌کند؛ به VPN یا دادهٔ واقعی کاربر وصل نمی‌شود. برای محدودیت محیط تست، sandbox داخلی همین Chrome آزمایشی غیرفعال است. نتیجه و تصویر در `.cache/public-state-ui/` ثبت می‌شوند.

بررسی نهایی: **۶۶۰ تست پاس، صفر شکست، ۸ skip و ۱۴ package موفق**؛ build/vet، race بسته‌های model/storage/manager و APIهای مرتبط، TypeScript/frontend و cross-build کامل Windows ARM64 و پکیج‌های داخلی Linux AMD64 پاس شدند. جزئیات در [checks بخش سوم](/E:/projects/WhiteVPN-Desktop/docs/implementation/public-state-checks.json) ثبت شده است.

P1 کامل بسته نشده است: اجرای downgrade با binary قدیمی، هماهنگی نوشتن چندفرایندی، faultهای واقعی دیسک/قطع برق، یک transaction برای انتخاب موتور و global state، و ورود metadata catalog جدید به backup عمومی باقی مانده‌اند. backup این مرحله catalog مستقل شش موتور را export یا replace نمی‌کند؛ رفتار آن محدود به state فعلی دسکتاپ است. مهاجرت manager به مسیر Mihomo و backendهای واقعی شش موتور نیز هنوز انجام نشده‌اند.
