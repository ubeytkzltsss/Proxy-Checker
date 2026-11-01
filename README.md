# Proxy Checker

Python ile geliştirilmiş, proxy adreslerini hızlı ve kolay bir şekilde test etmenizi sağlayan hafif bir masaüstü uygulaması. Basit grafik arayüzü sayesinde proxy'lerin çalışma durumunu, bağlantı sürelerini ve çıkış IP adreslerini görüntüleyebilirsiniz.

## ✨ Özellikler

- SOCKS5, SOCKS4, HTTP ve HTTPS desteği
- Otomatik protokol algılama
- TXT ve JSON dosyası desteği
- Çoklu (Concurrent) proxy kontrolü
- Bağlantı süresi (Latency) ölçümü
- Proxy çıkış IP adresini görüntüleme
- Özelleştirilebilir Timeout ve Worker ayarları
- Çalışan proxy'leri TXT olarak kaydetme
- Tüm sonuçları CSV olarak dışa aktarma
- Kullanımı kolay grafik arayüz

## 📥 İndirme

Uygulamayı iki farklı şekilde kullanabilirsiniz.

**1. Hazır EXE (Önerilen)**

Python veya herhangi bir ek kurulumla uğraşmadan kullanabilirsiniz.

[Proxy Checker EXE İndir](https://github.com/ubeytkzltsss/Proxy-Checker/raw/refs/heads/main/proxy_checker.exe)

İndirdiğiniz `proxy_checker.exe` dosyasını çalıştırmanız yeterlidir.

**2. Kaynak Kodunu İndirme**

1. GitHub deposuna gidin.
2. `Code` butonuna tıklayın.
3. `Download ZIP` seçeneğini kullanın.
4. ZIP dosyasını bir klasöre çıkartın.

## ⚙️ Python ile Kurulum

Kaynak kodunu çalıştırmak için:

**Gereksinimler:**
- Python 3.10 veya üzeri
- pip

**1. Gerekli kütüphaneyi yükleyin:**

```bash
py -m pip install "requests[socks]"
```

**2. Proje klasörünü açın ve çalıştırın:**

```bash
py proxy_checker.py
```

Uygulama grafik arayüzüyle açılacaktır.

## 🚀 Kullanım

1. TXT veya JSON formatındaki proxy dosyanızı seçin.
2. Kontrol adresini belirleyin (Varsayılan: `https://api.ipify.org`).
3. Timeout ve eşzamanlı kontrol sayılarını ayarlayın.
4. **Kontrolü Başlat** butonuna basın.
5. Sonuçları arayüz üzerinden görüntüleyin.
6. Çalışan proxy'leri TXT, tüm sonuçları CSV olarak kaydedin.

**Desteklenen proxy formatları:**

```text
127.0.0.1:1080
socks5://127.0.0.1:1080
socks4://127.0.0.1:1080
http://127.0.0.1:8080
127.0.0.1:1080:username:password
```

## 🛠️ Teknolojiler

- Python
- Tkinter
- Requests
- Concurrent Futures

## ⚠️ Sorumluluk Reddi

Bu araç yalnızca eğitim, test ve yetkili proxy bağlantılarının kontrolü amacıyla geliştirilmiştir. Kullanıcıların kullandıkları proxy adresleri üzerindeki yetkilerinden kendileri sorumludur.

---

## In English

Proxy Checker is a lightweight Python desktop application for testing SOCKS5, SOCKS4, HTTP and HTTPS proxies. It supports automatic protocol detection, concurrent testing, latency measurement, exit IP detection and TXT/JSON imports with CSV/TXT exports.



<p align="center">
<img width="100" height="99" alt="resim" src="https://github.com/user-attachments/assets/7e14465d-bdef-421e-bc16-199a8646792e" />
</p>

<p align="center">
  Developed by <b>Ubeyt</b>.
</p>
