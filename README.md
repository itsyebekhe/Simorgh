# 🦅 Simorgh Subscription (سیمرغ)

این ریپازیتوری به صورت خودکار پروکسی‌های V2Ray را جمع‌آوری، تست و مرتب‌سازی می‌کند. لینک‌های اشتراک زیر هر ساعت بروزرسانی می‌شوند.
<br>
This repository automatically collects, tests, and organizes V2Ray proxies. Subscription links are updated every hour.

## 📋 لینک‌های اشتراک (Subscription Links)

برای استفاده، لینک مورد نظر را کپی کرده و در برنامه خود وارد کنید.
<br>
**نکته:** اگر برنامه شما از لینک‌های عادی پشتیبانی نکرد، از لینک‌های **Base64** استفاده کنید.

| توضیحات (Description) | پروتکل (Protocol) | لینک اشتراک (Normal) | لینک کدگذاری شده (Base64) |
| :--- | :---: | :---: | :---: |
| **همه پروکسی‌ها (پیشنهادی)** | **Mixed** | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/normal/mixed) | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/base64/mixed) |
| **سرعت بالا (کمترین پینگ)** | **High Speed** | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/normal/high_speed) | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/base64/high_speed) |
| کانفیگ‌های VLESS | VLESS | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/normal/vless) | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/base64/vless) |
| کانفیگ‌های VMess | VMess | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/normal/vmess) | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/base64/vmess) |
| کانفیگ‌های Trojan | Trojan | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/normal/trojan) | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/base64/trojan) |
| کانفیگ‌های Shadowsocks | SS | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/normal/ss) | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/base64/ss) |
| کانفیگ‌های Hysteria 2 | Hy2 | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/normal/hy2) | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/base64/hy2) |
| کانفیگ‌های TUIC | TUIC | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/normal/tuic) | [لینک (Link)](https://raw.githubusercontent.com/itsyebekhe/Simorgh/main/subscriptions/base64/tuic) |

---

## 📱 آموزش استفاده (How to Use)

### 🤖 اندروید (Android) - برنامه v2rayNG
1. یکی از لینک‌های بالا (ترجیحاً `Mixed`) را کپی کنید.
2. برنامه **v2rayNG** را باز کنید.
3. روی منوی همبرگری (سه خط) در بالا سمت چپ کلیک کنید.
4. گزینه **Subscription Group Setting** را انتخاب کنید.
5. روی علامت `+` در بالا کلیک کنید.
6. در قسمت **Remarks** یک نام دلخواه (مثلاً `Simorgh`) بنویسید.
7. در قسمت **Optional URL** لینکی که کپی کرده‌اید را پیست کنید و ذخیره کنید (تیک بالا).
8. به صفحه اصلی برگردید. دوباره روی سه نقطه بالا سمت راست کلیک کنید و گزینه **Update Subscription** را بزنید.

### 🍎 آیفون (iOS) - برنامه V2Box یا Streisand
1. لینک اشتراک را کپی کنید.
2. برنامه **V2Box** را باز کنید.
3. معمولاً برنامه به صورت خودکار تشخیص می‌دهد که لینکی در کلیپ‌بورد دارید. اگر نه، به بخش **Configs** بروید.
4. دکمه `+` یا **Import** را بزنید و **Add Subscription** را انتخاب کنید.
5. لینک را جایگذاری کنید و **Add Subscribe** را بزنید.
6. منتظر بمانید تا لیست پروکسی‌ها آپدیت شود.

### 💻 ویندوز (Windows) - برنامه v2rayN
1. لینک اشتراک را کپی کنید.
2. برنامه **v2rayN** را باز کنید.
3. در نوار بالا روی **Subscription Group** کلیک کنید و **Add Subscription** را بزنید.
4. در کادر **URL** لینک را پیست کنید و `OK` کنید.
5. در صفحه اصلی، روی دکمه **Subscription** کلیک کنید و **Update Subscription (without proxy)** را انتخاب کنید.

---

## ✨ ویژگی‌ها (Features)
- 🌍 **شناسایی لوکیشن:** نام‌گذاری کانفیگ‌ها بر اساس کشور (با استفاده از دیتابیس GeoIP).
- ☁️ **تشخیص کلودفلر:** شناسایی خودکار IPهای کلودفلر (CF).
- ⚡ **تست سرعت:** حذف کانفیگ‌های کند و خراب.
- 🆔 **نام‌گذاری یکتا:** جلوگیری از تداخل نام در کلاینت‌ها.
- 🔄 **بروزرسانی ساعتی:** اجرای خودکار توسط GitHub Actions.

---
**Disclaimer:** This repository is for educational and research purposes only.