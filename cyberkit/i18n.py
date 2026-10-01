"""Translation layer for CyberKit.

Every user-facing string in the toolkit lives here, keyed by a dotted id such as
``menu.scan`` or ``result.critical``. English is the source language and doubles
as the fallback, so a partial Turkish catalog degrades to English instead of
blanking out.

Two strings per id are supported: a plain ``str``, or a ``(basic, advanced)``
tuple when the wording should differ between the plain and the expert mode.
Advanced strings stay terse and jargon-heavy on purpose - that is how pentesters
talk to each other.

Language detection is best effort and must never raise: explicit override first,
then POSIX locale environment variables, then Windows APIs through ``ctypes``,
then English.
"""

from __future__ import annotations

import locale
import os
from dataclasses import dataclass

# --- language catalogue -----------------------------------------------------


@dataclass(frozen=True, slots=True)
class Lang:
    """A supported interface language."""

    code: str
    label: str
    region: str

    @property
    def flag_glyph(self) -> str:
        """Two-letter regional indicator pair, or the region name if it cannot be rendered."""
        try:
            return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in self.region.upper()[:2])
        except Exception:
            return self.region


TR = Lang(code="tr", label="Turkce", region="TR")
EN = Lang(code="en", label="English", region="US")

_LANGS: dict[str, Lang] = {lang.code: lang for lang in (TR, EN)}

# --- strings ----------------------------------------------------------------
#
# Value is either ``str`` (same in both modes) or ``(basic, advanced)``.

_EN: dict[str, str | tuple[str, str]] = {
    # banners / titles
    "app.name": "CyberKit",
    "app.tagline": "Modular reconnaissance toolkit",
    "app.subtitle": "For authorized security assessments only",
    "app.version": "CyberKit v%(version)s",
    "app.rule": "Use only on systems you own or have written permission to test.",
    # mode selection
    "mode.select": ("Choose a mode", "Select mode"),
    "mode.basic": "Basic",
    "mode.basic_desc": ("Plain language, safer defaults, slower checks.", "Basic checks, safe defaults."),
    "mode.advanced": "Advanced",
    "mode.advanced_desc": ("More modules, tighter timeouts, raw output.", "Full module set, terse output, expert knobs."),
    "mode.switched": ("Mode set to %(mode)s.", "mode -> %(mode)s"),
    # menus
    "menu.scan": "Scan",
    "menu.modules": "Modules",
    "menu.scope": "Scope",
    "menu.settings": "Settings",
    "menu.report": "Report",
    "menu.language": "Language",
    "menu.exit": "Exit",
    "menu.custom": "Custom scan",
    "menu.quick": "Quick scan",
    "menu.back": "Back",
    "menu.main": "Main menu",
    "menu.choose": "Choose an option",
    "menu.title": "CyberKit - main menu",
    # prompts
    "prompt.target": "Target",
    "prompt.scope": "Scope file",
    "prompt.output": "Output path",
    "prompt.modules": "Modules (comma separated)",
    "prompt.ports": "Ports (comma separated)",
    "prompt.concurrency": "Concurrency",
    "prompt.timeout": "Timeout (seconds)",
    "prompt.ratelimit": "Rate limit (requests per second)",
    "prompt.confirm": ("Continue? [y/N]: ", "proceed? [y/N] "),
    "prompt.choice": ("Enter a number: ", "> "),
    "prompt.optional": "optional",
    # scan lifecycle
    "scan.starting": "Starting scan",
    "scan.module_start": "Running %(module)s",
    "scan.module_done": "Finished %(module)s in %(seconds).2fs",
    "scan.complete": "Scan finished in %(seconds).2fs",
    "scan.aborted": "Scan stopped after %(count)d error(s).",
    "scan.cancelled": "Scan cancelled by user.",
    "scan.no_targets": "No targets in scope.",
    "scan.seconds": "%(seconds).2fs",
    "scan.progress": "[%(done)s/%(total)s] %(name)s",
    # results
    "result.hosts": "%(count)d host(s)",
    "result.ports_open": "%(count)d open port(s)",
    "result.findings": "%(count)d finding(s)",
    "result.errors": "%(count)d error(s)",
    "result.none": "Nothing to report.",
    "result.severity": "%(count)d finding(s)",
    "result.critical": "critical",
    "result.high": "high",
    "result.medium": "medium",
    "result.low": "low",
    "result.info": "info",
    "result.report_written": "Report written to %(path)s",
    "result.service": "service",
    "result.banners": "banners",
    "result.elapsed": "elapsed %(seconds).2fs",
    # scope
    "scope.required": "A scope file is required before scanning.",
    "scope.loaded": "Loaded %(count)d target(s) from %(path)s",
    "scope.denied": "Target out of scope: %(target)s",
    "scope.hint": "Only hosts listed in the scope file may be scanned.",
    "scope.allow_all": "Scanning everything in scope.",
    "scope.private_blocked": "Private and reserved ranges need an explicit override.",
    # settings
    "settings.title": "Settings",
    "settings.concurrency": "Concurrency: %(value)s",
    "settings.timeout": "Timeout: %(value)s seconds",
    "settings.rate": "Rate limit: %(value)s req/s",
    "settings.tls": "TLS verification: %(value)s",
    "settings.output": "Output directory: %(value)s",
    "settings.theme": "Theme: %(value)s",
    "settings.saved": "Settings saved.",
    "settings.unchanged": "Unchanged.",
    # misc
    "misc.yes": "yes",
    "misc.no": "no",
    "misc.press_enter": "Press Enter to continue",
    "misc.goodbye": "Bye.",
    "misc.cancelled": ("Cancelled.", "cancelled"),
    "misc.error": ("Something went wrong: %(message)s", "error: %(message)s"),
    "misc.unknown_option": "Unknown option: %(option)s",
    "misc.exit_code": "Exit code: %(code)d",
    "misc.authorized_only": "Authorized targets only.",
    "misc.yes_no": "[y/n]",
    "misc.none": "none",
    "misc.off": "off",
    "misc.on": "on",
    "misc.try_again": "Try again.",
    "misc.invalid_value": "Invalid value: %(value)s",
    "misc.not_implemented": "Not available on this platform.",
    "misc.module": "module",
    "misc.target": "target",
    "misc.dry_run": "Dry run: no packets sent.",
    "misc.usage": "Usage: cyberkit %(command)s [options]",
    "misc.help": "Help",
    "misc.version": "Version %(version)s",
    "misc.summary": "Summary",
    "misc.details": "Details",
    "misc.hint_more": "Press SPACE for more, Q to quit.",
    # modules
    "module.discovery": "Host discovery",
    "module.ports": "Port scan",
    "module.banner": "Banner grab",
    "module.tls": "TLS inspection",
    "module.http": "HTTP probing",
    "module.dns": "DNS records",
    "module.ssl": "Certificate check",
    "module.fingerprint": "Service fingerprint",
    "module.vuln": "Vulnerability check",
    "module.config": "Misconfiguration check",
    "module.report": "Report writer",
    "module.skipped": "Skipped: %(name)s",
    "module.error": "%(name)s failed: %(message)s",
    "module.enabled": "Enabled: %(name)s",
    "module.disabled": "Disabled: %(name)s",
    # network / tls
    "net.timeout": "Timed out after %(seconds).2fs",
    "net.refused": "Connection refused",
    "net.unreachable": "Host unreachable",
    "net.dns_error": "Name resolution failed",
    "net.tls_handshake_error": "TLS handshake failed: %(message)s",
    "net.cert_invalid": "Invalid certificate: %(reason)s",
    "net.cert_expired": "Certificate expired on %(date)s",
    "net.cert_self_signed": "Self-signed certificate",
    "net.cert_weak_cipher": "Weak cipher suite: %(cipher)s",
    "net.encryption": "Encryption: %(value)s",
    "net.port_closed": "Port %(port)s closed",
    "net.host_alive": "Host is up",
    "net.host_down": "No response from host",
    # errors
    "error.syntax": "Syntax error in %(path)s line %(line)s",
    "error.recursion": "Recursion limit reached while parsing %(path)s",
    "error.timeout": "Operation timed out",
    "error.permission": "Permission denied",
    "error.file_not_found": "File not found: %(path)s",
    "error.parse": "Could not parse %(path)s",
    "error.dns": "DNS lookup failed for %(target)s",
    "error.tls": "TLS error: %(message)s",
    "error.unexpected": "Unexpected error in %(where)s",
    # shell chrome
    "menu.mode": "Mode",
    "menu.music": "Music",
    "music.on": "Music on",
    "music.off": "Music off",
    "music.unavailable": "Audio unavailable",
    "result.title": "Results",
    "result.ports": "%(count)d open port(s)",
    "table.host": "Host",
    "table.ports": "Ports",
    "table.findings": "Findings",
    "table.severity": "Severity",
    "table.title": "Finding",
    "table.target": "Target",
    "table.module": "Module",
    "table.tags": "Tags",
    "table.what": "What it does",
    "language.changed": "Language: %(label)s",
    "scope.not_found": "Scope file not found: %(path)s",
    "scope.invalid": "Scope file could not be read: %(error)s",
}

_TR: dict[str, str | tuple[str, str]] = {
    # banners / titles
    "app.name": "CyberKit",
    "app.tagline": "Modüler keşif ve güvenlik araç kutusu",
    "app.subtitle": "Yalnızca yetkili sistemlerde kullanılmak üzere",
    "app.version": "CyberKit s%(version)s",
    "app.rule": "Yalnızca sahibi olduğunuz veya test izni aldığınız sistemlerde kullanın.",
    # mode selection
    "mode.select": ("Bir mod seçin", "mod"),
    "mode.basic": "Temel",
    "mode.basic_desc": ("Anlaşılır diller, güvenli varsayılanlar, yavaş kontroller.", "temel kontroller, güvenli varsayılanlar"),
    "mode.advanced": "Gelişmiş",
    "mode.advanced_desc": ("Daha fazla modül, kısa zaman aşımı, ham çıktı.", "tüm modüller, kısa çıktı, uzman ayarları"),
    "mode.switched": ("Mod %(mode)s olarak ayarlandı.", "mod: %(mode)s"),
    # menus
    "menu.scan": "Tarama",
    "menu.modules": "Modüller",
    "menu.scope": "Kapsam",
    "menu.settings": "Ayarlar",
    "menu.report": "Rapor",
    "menu.language": "Dil",
    "menu.exit": "Çıkış",
    "menu.custom": "Özel tarama",
    "menu.quick": "Hızlı tarama",
    "menu.back": "Geri",
    "menu.main": "Ana menü",
    "menu.choose": "Bir seçenek girin",
    "menu.title": "CyberKit - ana menü",
    # prompts
    "prompt.target": "Hedef",
    "prompt.scope": "Kapsam dosyası",
    "prompt.output": "Çıktı yolu",
    "prompt.modules": "Modüller (virgülle ayrılmış)",
    "prompt.ports": "Portlar (virgülle ayrılmış)",
    "prompt.concurrency": "Eşzamanlılık",
    "prompt.timeout": "Zaman aşımı (saniye)",
    "prompt.ratelimit": "Hız sınırı (saniyede istek)",
    "prompt.confirm": ("Devam edilsin mi? [e/H]: ", "devam? [e/H] "),
    "prompt.choice": ("Bir numara girin: ", "> "),
    "prompt.optional": "isteğe bağlı",
    # scan lifecycle
    "scan.starting": "Tarama başlıyor",
    "scan.module_start": "%(module)s çalıştırılıyor",
    "scan.module_done": "%(module)s %(seconds).2fs sürdü",
    "scan.complete": "Tarama %(seconds).2fs içinde tamamlandı",
    "scan.aborted": "Tarama %(count)d hata sonrasında durduruldu.",
    "scan.cancelled": "Tarama kullanıcı tarafından iptal edildi.",
    "scan.no_targets": "Kapsamda hedef yok.",
    "scan.seconds": "%(seconds).2fs",
    "scan.progress": "[%(done)s/%(total)s] %(name)s",
    # results
    "result.hosts": "%(count)d ana makine",
    "result.ports_open": "%(count)d açık port",
    "result.findings": "%(count)d bulgu",
    "result.errors": "%(count)d hata",
    "result.none": "Gösterilecek bir şey yok.",
    "result.severity": "%(count)d bulgu",
    "result.critical": "kritik",
    "result.high": "yüksek",
    "result.medium": "orta",
    "result.low": "düşük",
    "result.info": "bilgi",
    "result.report_written": "Rapor %(path)s konumuna yazıldı",
    "result.service": "servis",
    "result.banners": "banner",
    "result.elapsed": "süre %(seconds).2fs",
    # scope
    "scope.required": "Taramadan önce bir kapsam dosyası gerekiyor.",
    "scope.loaded": "%(path)s içinden %(count)d hedef yüklendi",
    "scope.denied": "Kapsam dışı hedef: %(target)s",
    "scope.hint": "Yalnızca kapsam dosyasındaki ana makineler taranabilir.",
    "scope.allow_all": "Kapsamdaki her şey taranıyor.",
    "scope.private_blocked": "Özel ve ayrılmış aralıklar için açık izin gerekiyor.",
    # settings
    "settings.title": "Ayarlar",
    "settings.concurrency": "Eşzamanlılık: %(value)s",
    "settings.timeout": "Zaman aşımı: %(value)s saniye",
    "settings.rate": "Hız sınırı: %(value)s istek/sn",
    "settings.tls": "TLS doğrulama: %(value)s",
    "settings.output": "Çıktı dizini: %(value)s",
    "settings.theme": "Tema: %(value)s",
    "settings.saved": "Ayarlar kaydedildi.",
    "settings.unchanged": "Değişmedi.",
    # misc
    "misc.yes": "evet",
    "misc.no": "hayır",
    "misc.press_enter": "Devam etmek için Enter'a basın",
    "misc.goodbye": "Görüşmek üzere.",
    "misc.cancelled": ("İptal edildi.", "iptal"),
    "misc.error": ("Bir şeyler ters gitti: %(message)s", "hata: %(message)s"),
    "misc.unknown_option": "Bilinmeyen seçenek: %(option)s",
    "misc.exit_code": "Çıkış kodu: %(code)d",
    "misc.authorized_only": "Yalnızca yetkili hedefler.",
    "misc.yes_no": "[e/h]",
    "misc.none": "yok",
    "misc.off": "kapalı",
    "misc.on": "açık",
    "misc.try_again": "Tekrar deneyin.",
    "misc.invalid_value": "Geçersiz değer: %(value)s",
    "misc.not_implemented": "Bu platformda kullanılamıyor.",
    "misc.module": "modül",
    "misc.target": "hedef",
    "misc.dry_run": "Kuru çalıştırma: paket gönderilmiyor.",
    "misc.usage": "Kullanım: cyberkit %(command)s [seçenekler]",
    "misc.help": "Yardım",
    "misc.version": "Sürüm %(version)s",
    "misc.summary": "Özet",
    "misc.details": "Ayrıntılar",
    "misc.hint_more": "Daha fazla için BOŞLUK, çıkmak için Q.",
    # modules
    "module.discovery": "Ana makine keşfi",
    "module.ports": "Port taraması",
    "module.banner": "Banner yakalama",
    "module.tls": "TLS incelemesi",
    "module.http": "HTTP denetleme",
    "module.dns": "DNS kayıtları",
    "module.ssl": "Sertifika kontrolü",
    "module.fingerprint": "Servis parmak izi",
    "module.vuln": "Zafiyet kontrolü",
    "module.config": "Yapılandırma hatası kontrolü",
    "module.report": "Rapor yazıcı",
    "module.skipped": "Atlandı: %(name)s",
    "module.error": "%(name)s başarısız: %(message)s",
    "module.enabled": "Etkin: %(name)s",
    "module.disabled": "Devre dışı: %(name)s",
    # network / tls
    "net.timeout": "%(seconds).2fs sonra zaman aşımı",
    "net.refused": "Bağlantı reddedildi",
    "net.unreachable": "Ana makineye ulaşılamıyor",
    "net.dns_error": "Ad çözümlemesi başarısız",
    "net.tls_handshake_error": "TLS el sıkışması başarısız: %(message)s",
    "net.cert_invalid": "Geçersiz sertifika: %(reason)s",
    "net.cert_expired": "Sertifika %(date)s tarihinde sona erdi",
    "net.cert_self_signed": "Kendinden imzalı sertifika",
    "net.cert_weak_cipher": "Zayıf şifreleme paketi: %(cipher)s",
    "net.encryption": "Şifreleme: %(value)s",
    "net.port_closed": "%(port)s portu kapalı",
    "net.host_alive": "Ana makine yanıt veriyor",
    "net.host_down": "Ana makineden yanıt yok",
    # errors
    "error.syntax": "%(path)s dosyasının %(line)s satırında sözdizimi hatası",
    "error.recursion": "%(path)s ayrıştırılırken özyineleme sınırına ulaşıldı",
    "error.timeout": "İşlem zaman aşımına uğradı",
    "error.permission": "Yetki reddedildi",
    "error.file_not_found": "Dosya bulunamadı: %(path)s",
    "error.parse": "%(path)s ayrıştırılamadı",
    "error.dns": "%(target)s için DNS sorgusu başarısız",
    "error.tls": "TLS hatası: %(message)s",
    "error.unexpected": "%(where)s içinde beklenmeyen hata",
    # shell chrome
    "menu.mode": "Mod",
    "menu.music": "Müzik",
    "music.on": "Müzik açık",
    "music.off": "Müzik kapalı",
    "music.unavailable": "Ses kullanılamıyor",
    "result.title": "Sonuçlar",
    "result.ports": "%(count)d açık port",
    "table.host": "Ana makine",
    "table.ports": "Portlar",
    "table.findings": "Bulgular",
    "table.severity": "Önem",
    "table.title": "Bulgu",
    "table.target": "Hedef",
    "table.module": "Modül",
    "table.tags": "Etiketler",
    "table.what": "Ne yapar",
    "language.changed": "Dil: %(label)s",
    "scope.not_found": "Kapsam dosyası bulunamadı: %(path)s",
    "scope.invalid": "Kapsam dosyası okunamadı: %(error)s",
}

_STRINGS: dict[str, dict[str, str | tuple[str, str]]] = {"en": _EN, "tr": _TR}

# Locale variables consulted, in priority order.
_LOCALE_VARS = ("LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE")

_TR_LOCALE_ID = 0x041F  # Windows LANGID for Turkish (Türkiye)

_current: Lang = EN
_override: Lang | None = None
ADVANCED_MODE: bool = False
MISSING: list[str] = []


# --- language state ---------------------------------------------------------


def available_languages() -> list[Lang]:
    return [EN, TR]


def set_language(lang: Lang) -> Lang:
    """Force a language explicitly; this wins over every environment signal."""
    global _current, _override
    _current = lang
    _override = lang
    return _current


def set_language_code(code: str) -> Lang:
    """Force a language by code, falling back to English for unknown codes."""
    normalized = (code or "").strip().lower().replace("-", "_")
    for lang in available_languages():
        if lang.code == normalized.split("_", 1)[0]:
            return set_language(lang)
    return set_language(EN)


def current() -> Lang:
    """The active language, detecting it on first use."""
    global _current
    if _override is None and _current is EN:
        _current = detect_language()
    return _current


def toggle_language() -> Lang:
    """Flip between Turkish and English."""
    order = available_languages()
    try:
        index = order.index(_current)
    except ValueError:
        index = 0
    return set_language(order[(index + 1) % len(order)])


def set_advanced(value: bool) -> bool:
    """Switch the wording mode used to resolve ``(basic, advanced)`` tuples."""
    global ADVANCED_MODE
    ADVANCED_MODE = bool(value)
    return ADVANCED_MODE


# --- detection --------------------------------------------------------------


def _is_tr(value: str | None) -> bool:
    if not value:
        return False
    try:
        return value.strip().lower().replace("-", "_").split("_", 1)[0].startswith("tr")
    except Exception:
        return False


def _tr_from_environment() -> bool:
    for var in _LOCALE_VARS:
        try:
            if _is_tr(os.environ.get(var)):
                return True
        except Exception:
            continue
    return False


def _tr_from_windows() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes

        name = ctypes.windll.kernel32.GetUserDefaultLocaleName(None, 0)
        if name and _is_tr(str(name)):
            return True
        locale_id = ctypes.windll.kernel32.GetUserDefaultUILanguage()
        return int(locale_id) == _TR_LOCALE_ID
    except Exception:
        pass
    try:
        if locale.getdefaultlocale()[0] and _is_tr(locale.getdefaultlocale()[0]):
            return True
    except Exception:
        pass
    try:
        mapping = locale.windows_locale
        return any(
            int(lcid) == _TR_LOCALE_ID and _is_tr(name)
            for lcid, name in mapping.items()
            if isinstance(lcid, int) and isinstance(name, str)
        )
    except Exception:
        pass
    return False


def detect_language() -> Lang:
    """Best effort language detection. Never raises, never returns None."""
    try:
        if _override is not None:
            return _override
        if _tr_from_environment():
            return TR
        if _tr_from_windows():
            return TR
    except Exception:
        pass
    return EN


# --- lookup -----------------------------------------------------------------


def reset_missing() -> None:
    """Forget which keys could not be resolved."""
    MISSING.clear()


def _note_missing(key: str) -> None:
    if key not in MISSING:
        MISSING.append(key)


def _lookup(key: str, lang_code: str) -> str | tuple[str, str] | None:
    catalog = _STRINGS.get(lang_code, {})
    if key in catalog:
        return catalog[key]
    _note_missing(key)
    return None


def pick(key: str) -> tuple[str, str]:
    """Return ``(basic, advanced)`` wording for a key, for UI that picks itself."""
    resolved = _resolve(key)
    if isinstance(resolved, tuple):
        return resolved
    return resolved, resolved


def _resolve(key: str) -> str | tuple[str, str]:
    """Find a raw (unformatted) value for the key in the active language."""
    value = _lookup(key, current().code)
    if value is None:
        value = _lookup(key, EN.code)
    if value is None:
        return f"[{key}]"
    return value


def t(key: str, **kwargs: object) -> str:
    """Translate ``key`` into the active language and interpolate ``kwargs``."""
    value = _resolve(key)
    if isinstance(value, tuple):
        value = value[1] if ADVANCED_MODE else value[0]
    if not kwargs:
        return value
    try:
        return value % kwargs
    except (KeyError, ValueError, TypeError):
        # A missing or mismatched placeholder must not take the app down.
        return value


def language_line() -> str:
    """One-line language indicator for a menu footer."""
    origin = "auto" if _override is None else "set"
    return f"Dil: {TR.label} / Language: {EN.label}  ({origin})"
