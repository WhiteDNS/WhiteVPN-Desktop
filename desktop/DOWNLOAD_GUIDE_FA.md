# راهنمای سریع انتخاب نسخه WhiteDNS Desktop

اگر نمی‌دانید کدام فایل را باید دانلود کنید، از این راهنما استفاده کنید.

## ویندوز

### بیشتر کاربران ویندوز

اگر کامپیوتر یا لپ‌تاپ شما ویندوز ۱۰ یا ۱۱ معمولی دارد و پردازنده آن Intel یا AMD است، این فایل را دانلود کنید:

`WhiteDNS-Desktop-1.0.0-beta6-windows-x64.zip`

این گزینه برای بیشتر سیستم‌های ویندوزی درست است.

### ویندوز روی ARM

فقط اگر دستگاه شما Windows on ARM است، مثل بعضی مدل‌های Snapdragon یا Surface Pro X، این فایل را دانلود کنید:

`WhiteDNS-Desktop-1.0.0-beta6-windows-arm64-windows-on-arm.zip`

اگر این نسخه را روی ویندوز معمولی Intel یا AMD اجرا کنید، احتمالاً پیام `This app can't run on your PC` می‌بینید.

## macOS

### مک‌های جدید Apple Silicon

اگر مک شما M1، M2، M3، M4 یا مدل‌های جدیدتر Apple Silicon است، این فایل را دانلود کنید:

`WhiteDNS-Desktop-1.0.0-beta6-macos-arm64.zip`

### مک‌های Intel

اگر مک شما قدیمی‌تر و Intel است، این فایل را دانلود کنید:

`WhiteDNS-Desktop-1.0.0-beta6-macos-amd64.zip`

حتماً فایل ZIP را از بخش Release دانلود کنید. پوشه خام `.app` را از Artifacts گیت‌هاب دانلود نکنید، چون ممکن است برنامه با پیام `The application can't be opened` باز نشود.

## Linux

### ساده‌ترین گزینه برای Linux روی Intel/AMD

اگر می‌خواهید درگیر نصب بسته DEB یا RPM و مشکل دیپندنسی نشوید، ابتدا AppImage را امتحان کنید:

`WhiteDNS-Desktop-1.0.0-beta6-linux-amd64-webkit41.AppImage`

بعد از دانلود، فایل را executable کنید و اجرا کنید. AppImage هنوز به اجزای پایه سیستم مثل kernel/glibc و در بعضی سیستم‌ها FUSE یا حالت extract نیاز دارد، اما به نصب بسته RPM یا DEB برنامه نیاز ندارد.

### Debian و Ubuntu

اگر توزیع شما Debian یا Ubuntu است و کامپیوتر شما پردازنده Intel یا AMD دارد، فایل DEB را دانلود کنید:

`WhiteDNS-Desktop-1.0.0-beta6-linux-amd64.deb`

اگر Ubuntu 24.04 یا توزیع جدیدتری دارید که WebKitGTK 4.1 استفاده می‌کند، این فایل مناسب‌تر است:

`WhiteDNS-Desktop-1.0.0-beta6-linux-amd64-webkit41.deb`

برای دستگاه‌های ARM64 از این فایل استفاده کنید:

`WhiteDNS-Desktop-1.0.0-beta6-linux-arm64.deb`

### Fedora، RHEL، Rocky و توزیع‌های RPM

اگر توزیع شما از بسته‌های RPM استفاده می‌کند، نسخه RPM را دانلود کنید:

`WhiteDNS-Desktop-1.0.0-beta6-linux-amd64.rpm`

برای توزیع‌های جدیدتر که WebKitGTK 4.1 دارند، این نسخه انتخاب بهتر است:

`WhiteDNS-Desktop-1.0.0-beta6-linux-amd64-webkit41.rpm`

برای دستگاه‌های ARM64:

`WhiteDNS-Desktop-1.0.0-beta6-linux-arm64.rpm`

### بسته عمومی Linux

اگر بسته DEB یا RPM برای توزیع شما مناسب نیست، از فایل `tar.gz` استفاده کنید.

`WhiteDNS-Desktop-1.0.0-beta6-linux-amd64.tar.gz`

برای Linux amd64 با WebKitGTK 4.1:

`WhiteDNS-Desktop-1.0.0-beta6-linux-amd64-webkit41.tar.gz`

یا برای ARM64:

`WhiteDNS-Desktop-1.0.0-beta6-linux-arm64.tar.gz`

## انتخاب سریع

- ویندوز معمولی Intel/AMD: `windows-x64`
- Windows on ARM: `windows-arm64-windows-on-arm`
- مک M1/M2/M3/M4 و جدیدتر: `macos-arm64`
- مک Intel: `macos-amd64`
- لینوکس Intel/AMD با کمترین دردسر نصب: `linux-amd64-webkit41.AppImage`
- لینوکس Debian/Ubuntu روی Intel/AMD: `linux-amd64.deb`
- لینوکس Ubuntu 24.04+ روی Intel/AMD: `linux-amd64-webkit41.deb`
- لینوکس Debian/Ubuntu روی ARM64: `linux-arm64.deb`
- توزیع‌های RPM روی Intel/AMD: `linux-amd64.rpm`
- توزیع‌های RPM جدیدتر روی Intel/AMD: `linux-amd64-webkit41.rpm`
- توزیع‌های RPM روی ARM64: `linux-arm64.rpm`

اگر هنوز مطمئن نیستید، معمولاً این انتخاب‌ها درست هستند:

- برای ویندوز: `windows-x64`
- برای مک‌های جدید: `macos-arm64`
- برای مک‌های قدیمی Intel: `macos-amd64`
- برای لینوکس روی کامپیوتر معمولی Intel/AMD: `linux-amd64-webkit41.AppImage`
