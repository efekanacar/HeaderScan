#!/usr/bin/env python3
"""HTTP güvenlik başlıklarını standart kütüphaneyle incele."""

import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def inspect_headers(headers, url):
    results = []

    def record(name, risks, advice):
        value = headers.get(name)
        missing = value is None
        results.append({
            "header": name,
            "value": value,
            "status": "missing" if missing else "risky" if risks else "ok",
            "issues": ["Başlık eksik."] if missing else risks,
            "recommendation": advice if missing or risks else "",
        })

    value = headers.get("Strict-Transport-Security", "")
    directives = {}
    for part in value.lower().split(";"):
        key, _, argument = part.strip().partition("=")
        directives[key] = argument.strip()
    age = directives.get("max-age", "")
    risks = []
    if not age.isascii() or not age.isdigit() or int(age) < 31536000:
        risks.append("max-age geçersiz veya bir yıldan kısa.")
    if urlsplit(url).scheme.lower() != "https":
        risks.append("HSTS yalnızca HTTPS üzerinden etkilidir.")
    record("Strict-Transport-Security", risks,
           "HTTPS kullanın; HSTS max-age değerini en az 31536000 yapın.")

    value = headers.get("Content-Security-Policy", "")
    policy = {}
    for part in value.lower().split(";"):
        tokens = part.split()
        if tokens:
            policy.setdefault(tokens[0], tokens[1:])
    risks = []
    if not policy.get("default-src") and not policy.get("script-src"):
        risks.append("default-src veya script-src kaynak kısıtlaması yok.")
    sources = [source for items in policy.values() for source in items]
    for token in ("'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:", "https:"):
        if token in sources:
            risks.append("Geniş veya riskli CSP kaynağı: " + token)
    record("Content-Security-Policy", risks,
           "Uygulamaya uygun, dar kaynak listeleri tanımlayın; nonce veya hash kullanın.")

    value = headers.get("X-Frame-Options", "").strip().upper()
    record("X-Frame-Options",
           [] if value in {"DENY", "SAMEORIGIN"} else ["Değer DENY veya SAMEORIGIN değil."],
           "Gereksinime göre DENY veya SAMEORIGIN kullanın; CSP frame-ancestors da tanımlanabilir.")

    value = headers.get("X-Content-Type-Options", "").strip().lower()
    record("X-Content-Type-Options",
           [] if value == "nosniff" else ["Değer nosniff değil."],
           "X-Content-Type-Options: nosniff kullanın.")

    value = headers.get("Referrer-Policy", "").lower()
    valid = {"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
             "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}
    recognized = [item.strip() for item in value.split(",") if item.strip() in valid]
    effective = recognized[-1] if recognized else None
    risks = []
    if effective is None:
        risks.append("Geçerli bir Referrer-Policy değeri yok.")
    elif effective in {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"}:
        risks.append("Politika gereğinden fazla URL bilgisi paylaşabilir.")
    record("Referrer-Policy", risks,
           "strict-origin-when-cross-origin veya no-referrer kullanın.")
    return results


def main():
    parser = argparse.ArgumentParser(description="HTTP güvenlik başlıklarını kontrol eder.")
    parser.add_argument("url", help="http:// veya https:// ile başlayan URL")
    parser.add_argument("--json", action="store_true", help="Sonucu JSON olarak yazdır")
    args = parser.parse_args()
    try:
        parsed = urlsplit(args.url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Geçerli bir HTTP veya HTTPS URL'si girin.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URL içinde kullanıcı bilgisi kullanmayın.")
        request = Request(args.url, headers={"User-Agent": "HeaderScan/1.0"})
        try:
            response = urlopen(request, timeout=10)
        except HTTPError as error:
            response = error  # 4xx/5xx yanıtlarının başlıkları da incelenebilir.
        with response:
            final_url = response.geturl()
            report = {
                "url": args.url,
                "final_url": final_url,
                "http_status": response.code,
                "results": inspect_headers(response.headers, final_url),
            }
    except (ValueError, URLError, OSError) as error:
        message = "İstek başarısız: " + str(error)
        if args.json:
            print(json.dumps({"error": message}, ensure_ascii=False))
        else:
            print(message, file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"URL: {report['final_url']} (HTTP {report['http_status']})")
        labels = {"ok": "UYGUN", "missing": "EKSİK", "risky": "RİSKLİ"}
        for result in report["results"]:
            print(f"\n[{labels[result['status']]}] {result['header']}")
            if result["value"] is not None:
                print("  Değer: " + result["value"])
            for issue in result["issues"]:
                print("  " + issue)
            if result["recommendation"]:
                print("  Öneri: " + result["recommendation"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
