**مهاجرت ذخیره‌سازی Windows — بخش دوم زیرساخت شش موتور**

تاریخ: ۲۰۲۶-۱۰-۰۴. وضعیت: پیاده‌سازی مسیر production و تست مهاجرت تکمیل شد؛ gate کامل P1 هنوز باز است.

در Windows، constructor واقعی برنامه اکنون `NewPlatformStore` را انتخاب می‌کند. state شامل credentialهای فعلی و URLهای subscription در `<configDir>/state-v2/desktop-state.vault` با DPAPI متعلق به کاربر جاری ذخیره می‌شود. مدل داخلی و معنای normalize قبلی حفظ شده‌اند. writer قدیمی `NewStore` برای سازگاری پلتفرم‌های دیگر و fixtureهای legacy باقی مانده؛ مسیر production Windows از آن استفاده نمی‌کند.

| داده | محل جدید | رفتار |
| --- | --- | --- |
| state فعلی، credential نودها، SOCKS و DNS، URLهای subscription | `state-v2/desktop-state.vault` | یک envelope نسخه‌دار؛ commit اتمیک و فقط ciphertext در فایل موقت |
| checkpoint نخستین commit | `state-v2/desktop-state-recovery.vault` | رمزگذاری‌شده و ثابت؛ بازیابی خودکار state قدیمی انجام نمی‌شود |
| آخرین body معتبر subscription | `state-v2/subscriptions/<hash>.vault` | cache آفلاین پس از restart حفظ می‌شود؛ هویت subscription و وجود نود دوباره بررسی می‌شوند |
| پایان مهاجرت cache | `state-v2/subscription-migration.vault` | مهاجرت اولیه فقط یک‌بار؛ فایل‌های بازساخته‌شده توسط writer قدیمی وارد cache جدید نمی‌شوند |
| فایل موقت قدیمی state یا cache | زیردایرکتوری `legacy-state-temporaries` یا `legacy-temporaries` | حفظ opaque و رمزگذاری‌شده برای بررسی دستی؛ هرگز state یا cache فعال نمی‌شوند |

ترتیب مهاجرت state:

1. اگر vault موجود باشد، همان مرجع خواندن است. corruption، نسخهٔ ناشناخته، state تهی یا خطای decrypt موجب خطا می‌شوند؛ legacy جایگزین آن نمی‌شود.
2. اگر vault و checkpoint هر دو غایب باشند، فایل legacy محدود از نظر اندازه و نوع خوانده و normalize می‌شود. فایل خراب به defaults تبدیل یا overwrite نمی‌شود.
3. snapshot کامل رمزگذاری و round-trip آن تأیید می‌شود؛ فقط ciphertext به فایل موقت می‌رود و replace اتمیک انجام می‌شود.
4. checkpoint رمزگذاری‌شده تأیید می‌شود؛ فایل‌های موقت شناخته‌شدهٔ writer قبلی پیش از حذف به آرشیو رمزگذاری‌شده می‌روند؛ سپس `state.json` متعلق به همین برنامه حذف می‌شود.
5. شکست checkpoint یا cleanup، startup و save را متوقف می‌کند. اجرای بعدی از vault commit‌شده ادامه می‌دهد. نبود main در حضور recovery نیازمند repair صریح است و نصب تازه تلقی نمی‌شود.

برای subscriptionها نیز ciphertext پیش از حذف source تأیید می‌شود. خطای مقصد در مهاجرت اولیه source را نگه می‌دارد. checkpoint پایان مهاجرت مانع بازگرداندن cache حذف‌شده توسط فایل‌های قدیمی می‌شود. فایل corrupt رمزگذاری‌شده به legacy fallback نمی‌کند؛ cache قابل استفاده فقط از snapshot معتبر یا fetch موفق شبکه حاصل می‌شود.

Reset به gate فایل‌های snapshot و engine profiles متصل شده و protected store را پس از حذف دوباره Load می‌کند. save پس از حذف یا خرابی غیرمنتظرهٔ main مجاز نیست. lock مربوط به snapshot پیش از log/event آزاد می‌شود تا مسیر حذف subscription با lock اپلیکیشن deadlock نکند.

Import backup قدیمی از همان writer محافظت‌شده عبور می‌کند؛ credentialهای آن در state جدید plaintext نمی‌شوند. فایل متعلق به WhiteDNS Desktop و backup ورودی کاربر تغییر نمی‌کنند. این تغییر ادعای پاک‌سازی فیزیکی SSD یا حذف فایل‌های export انتخابی کاربر ندارد.

تست‌ها: migration با حفظ state normalize‌شده، DPAPI واقعی در production constructor، startup کامل در configDir موقت، restart/cache آفلاین، تکرار مهاجرت، failure پیش از commit و هنگام checkpoint، commit ناموفق edit، corruption و حذف main، نسخهٔ ناشناخته، جلوگیری از overwrite توسط writer legacy، import backup قدیمی، حفظ فایل موقت ناقص، checkpoint خراب و reset بدون احیای credential.

حدود این تحویل:

- `PublicAppState` و eventهای legacy هنوز DTO بدون secret ندارند؛ editor و bindingهای UI باید همراه آن تغییر کنند. backup عمومی فعلی نیز هنوز می‌تواند credential داشته باشد و gate P1 را پاس نکرده است.
- isolation در برابر writer و format واقعی legacy تست شده است؛ اجرای executable قدیمی و پذیرش downgrade کامل هنوز انجام نشده‌اند.
- هماهنگی چند process، قطع برق واقعی و disk-full واقعی آزموده نشده‌اند. آرشیوها و checkpoint برای repair دستی‌اند و API recovery محصول هنوز پیاده‌سازی نشده است.
- state اصلی و engine catalog دو domain ذخیره‌سازی مستقل‌اند؛ transaction انتخاب route بین آن‌ها پیش از wiring manager باید بسته شود.
- backend واقعی شش موتور و adapter Mihomo هنوز وارد مسیر connection نشده‌اند. این تحویل storage foundation است.

ادامهٔ لازم: DTO عمومی سراسری و editorهای صریح؛ backup عمومی بدون secret و restore با credential-required؛ سپس اتصال manager به Mihomo و ورود backendهای شش موتور طبق پلن.
