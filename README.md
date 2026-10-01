# BCT — Best Cyber Tools

<div align="center">

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗     ██╗  ██╗████████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██║ ██╔╝╚══██╔══╝
██║      ╚████╔╝ ██║  ██║█████╗  ██████╔╝    █████╔╝    ██║
██║       ╚██╔╝  ██║  ██║██╔══╝  ██╔══██╗    ██╔═██╗    ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║    ██║  ██╗   ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝   ╚═╝
```

**One command. Fifteen recon modules. Zero dependencies. Two modes.**

[English](#english) · [Türkçe](#türkçe)

</div>

---

## What this is

A reconnaissance toolkit for people who are **authorized** to test a system. It
answers one question fast: *what is exposed here, and what should I look at
first?*

It is not a exploit framework. It does not brute-force credentials, does not
attack, and does not touch anything outside the scope you declare.

```bash
git clone https://github.com/samansarmasik-alt/BCT.git
cd BCT
CYBERKIT.bat
```

That is the whole setup. No `pip install`, no virtualenv, no configuration.
Python 3.11+ and you are running.

---

## Why it is different

Most tools force you to remember flags and read a man page. This one asks.

| | |
|---|---|
| **Paste a URL, get a report** | `cyberkit https://site.com` — scope, modules and output are inferred |
| **Scope is enforced, not documented** | A target outside your declared scope *cannot* be scanned, by any module |
| **Two modes, one keystroke apart** | Basic for the curious, Advanced for the operator — animated transition included |
| **Speaks your language** | Turkish and English, auto-detected from the system locale |
| **Ambient audio** | Optional procedurally-generated background music that keeps playing when the window loses focus |
| **Single-file HTML report** | Self-contained, offline, printable, with severity filtering |
| **Zero dependencies** | Standard library only. Works on a locked-down machine with no internet. |

---

## The 15 modules

**Network and DNS**

| Module | What it finds |
|---|---|
| `dns` | A/AAAA, CNAME chains, reverse lookups, IPv6 reachability |
| `portscan` | Async TCP connect scan with banner and TLS fingerprinting |
| `subdomain` | 180-label wordlist, scope-gated before every query |

**Web surface**

| Module | What it finds |
|---|---|
| `http` | Live web services, stack disclosure, security header gaps |
| `crawl` | Bounded BFS crawl collecting paths and technologies |
| `wapp` | 30-technique fingerprinting from headers, HTML and asset paths |
| `apiprobe` | OpenAPI/Swagger specs, GraphQL consoles, exposed actuator endpoints |
| `jsanalysis` | Source maps, embedded keys, internal routes in first-party JS |

**Exposure and secrets**

| Module | What it finds |
|---|---|
| `secrets` | 14 credential patterns plus entropy analysis, values redacted |
| `wayback` | Historical paths, leaked credentials in URLs, forgotten subdomains |
| `vhost` | Wildcard and internal virtual hosts via Host-header diffing |
| `misconfig` | Exposed admin services, default credentials pages, info leaks |
| `vulns` | Inert, single-shot verification probes with a hard request budget |
| `tls` | Protocol, cipher, expiry, hostname mismatch, key strength |
| `lockout` | Login rate-limit and lockout posture, using inert markers only |

Every module declares what it will send before it sends it, caps its own
request count, and records a traffic note on the host so you can audit volume.

---

## Two modes

**Basic** — for someone who is not a pentester. Plain language prompts, a
curated high-signal module set, safer defaults, no jargon.

**Advanced** — for someone who does this for a living. All fifteen modules,
per-module selection, tunable concurrency and timeouts, raw counters.

Switching is a cinematic transition, not a settings dialog. Both modes report
the **same full finding set** — the mode changes how you ask and how you read,
never how much you see.

---

## Safety model

This is a recon tool, and the design reflects that:

- **Scope gate.** A run cannot touch a target outside the declared scope. The
  gate lives in the core, not in individual modules, so a new module cannot
  bypass it by accident.
- **Inert probes.** The `vulns` module sends single-character markers and looks
  for error strings. It never attempts blind injection, stacked queries, or
  authentication bypass.
- **The `lockout` module requires explicit opt-in**, uses randomly generated
  placeholder credentials rather than real ones, throttles itself to roughly
  one request per two seconds, and never stores or logs what it sent.
- **No payload delivery.** Nothing here can be pointed at a third party and
  turned into an attack tool without you rewriting it.

**Only use this on systems you own or have written permission to test.**

---

## Command line

The interactive shell is the front door, but everything is scriptable:

```bash
# simplest possible run
CYBERKIT-CLI.bat https://site.com

# full control
CYBERKIT-CLI.bat scan -t 10.0.0.5 -s scope.yaml -p 22,80,443 -c 300

# JSON to stdout
CYBERKIT-CLI.bat https://site.com --json

# what can it do
CYBERKIT-CLI.bat modules
```

---

## Reports

Output is a single self-contained HTML file. No CDN, no JavaScript
dependencies, nothing to host. Severity filters, per-host service tables, and
the complete JSON payload embedded at the bottom for scripting.

```bash
cyberkit https://site.com -o out/report.html
```

---

## Requirements

Python 3.11 or newer. Nothing else — no packages to install, ever.

Optional: `ffplay`, `mpv` or `vlc` for ambient audio. Absent audio support is
silent, not an error.

---

## Development

```bash
run-tests.bat              # 18 tests
py -3.13 -m ruff check cyberkit tests
py -3.13 -m mypy cyberkit
```

Type-checked and lint-clean across 36 source files.

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

<a name="türkçe"></a>

## Türkçe

**BCT — Best Cyber Tools**

Test etme yetkin olan sistemler için bir keşif aracı. Hızlıca şunu yanıtlar:
*burada ne açıkta, ilk neye bakmalıyım?*

Zararlı yazılım değildir. Kimlik bilgisi kırmaz, saldırmaz, bildiğiniz kapsam
dışındaki hiçbir şeye dokunmaz.

**Kurulum:** Python 3.11+ yeterlidir. `pip install` yoktur, sanal ortam yoktur.
Depoyu klonlayın ve `CYBERKIT.bat` dosyasına çift tıklayın.

**Kullanım:** Hedef adresi sorulur, kapsam otomatik belirlenir, tarama başlar.
Mod seçimi, ayarlar ve kapsam dosyası gelişmiş modda açılır.

**İki mod:**

- **Temel** — siber güvenlik uzmanı olmayanlar için. Sade dille sorular, seçilmiş
  modül kümesi, güvenli varsayılanlar.
- **Gelişmiş** — bu işi meslek olarak yapanlar için. 15 modülün tamamı,
  modül bazında seçim, ayarlanabilir eşzamanlılık ve zaman aşımı.

Modlar arasındaki geçiş animasyonludur. **Her iki mod da aynı tam bulgu
setini gösterir** — mod yalnızca nasıl sorduğunuzu ve nasıl okuduğunuzu
değiştirir, ne kadar gördüğünüzü değil.

**Modüller:** `dns`, `portscan`, `subdomain`, `http`, `crawl`, `wapp`,
`apiprobe`, `jsanalysis`, `secrets`, `wayback`, `vhost`, `misconfig`, `vulns`,
`tls`, `lockout`.

**Güvenlik modeli:**

- **Kapsam kapısı** — kapsam dışındaki bir hedefe hiçbir modül dokunamaz.
- **Zararsız problar** — `vulns` modülü tek karakterlik işaretler gönderir ve
  yalnızca hata mesajlarını arar. Kör enjeksiyon, zincirleme sorgu veya kimlik
  doğrulama atlatma denemez.
- **`lockout` modülü** açık onay gerektirir, gerçek yerine rastgele üretilmiş
  kimlik bilgileri kullanır ve yaklaşık 2 saniyede bir istek gönderir.
- **Yük taşıma yoktur** — hiçbir modül üçüncü taraflara saldırmak için
  yönlendirilemez.

**Yalnızca sahibi olduğunuz veya yazılı izin aldığınız sistemlerde kullanın.**

**Rapor:** Tek dosya HTML. Kapsayıcı bağımlılığı yok, çevrimdışı açılır, önem
seviyesine göre filtrelenir.

Arayüz dili sistem diline göre otomatik belirlenir; menüden değiştirilebilir.
