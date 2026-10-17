# HeaderScan

Verilen URL'nin HTTP güvenlik başlıklarını inceleyen sade bir Python CLI aracı.
Yalnızca Python standart kütüphanesini kullanır.

## Özellikler

- HSTS (`Strict-Transport-Security`), CSP (`Content-Security-Policy`),
  `X-Frame-Options`, `X-Content-Type-Options` ve `Referrer-Policy` kontrolü.
- Eksik ve riskli başlıklar için terminal çıktısı ve kısa öneriler.
- `--json` ile makine tarafından okunabilir çıktı.
- Yönlendirmeleri takip eder ve son yanıtı inceler; 4xx/5xx yanıtlarını da işler.
- HTTPS sertifikalarını doğrular; ağ işlemlerinde 10 saniyelik zaman aşımı kullanır.

## Kurulum

Python 3.9 veya üzeri yeterlidir. Ek paket kurulumu gerekmez.
`headerscan.py` dosyasının bulunduğu klasörde terminal açın.

## Örnek kullanım

```sh
python headerscan.py https://example.com
python headerscan.py https://example.com --json
python headerscan.py https://example.com --json > sonuc.json
python headerscan.py --help
```

URL, `http://` veya `https://` ile başlamalıdır. URL içinde kullanıcı adı ve
parola kabul edilmez. İstek GET yöntemiyle gönderilir; yanıt gövdesi okunmaz.

Terminalde her başlık `UYGUN`, `EKSİK` veya `RİSKLİ` olarak gösterilir.
JSON çıktısında `url`, `final_url`, `http_status` ve `results` alanları bulunur.
Her sonuç `header`, `value`, `status` (`ok`, `missing`, `risky`), `issues`
ve `recommendation` alanlarını içerir. Eksik başlığın değeri `null` olur.
İstek hataları JSON modunda `error` alanıyla standart çıktıya, normal modda
standart hata akışına yazılır.

Çıkış kodu tamamlanan taramalarda (bulgu olsa da) `0`, URL veya bağlantı
hatalarında `1`, komut satırı kullanım hatalarında `2` olur.

## Kontrollerin kapsamı

HSTS için en az bir yıllık `max-age` ve HTTPS aranır. CSP için `default-src`
veya `script-src` kısıtlaması aranır; geniş kaynaklar, `unsafe-inline` ve
`unsafe-eval` işaretlenir. X-Frame-Options için `DENY` veya `SAMEORIGIN`,
X-Content-Type-Options için `nosniff` beklenir. Referrer-Policy için son
tanınan politika değerlendirilir; URL bilgisini fazla paylaşabilen değerler
işaretlenir.

Bu kontroller temel sezgisel kontrollerdir; tam CSP çözümlemesi veya güvenlik
denetimi değildir. `UYGUN` sonucu sitenin güvenli olduğunu garanti etmez.
Örneğin CSP `frame-ancestors` ile korunmuş bir sitede X-Frame-Options eksikliği
raporlanabilir. Önerileri uygulamanın ihtiyaçlarına göre değerlendirin.
