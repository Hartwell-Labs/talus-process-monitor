# Diagnoza: `concurrent_writers_chain_stays_valid` — 153 corrupted out of 153

**Data:** 16.10.2026
**Status:** zdiagnozowane, nie naprawione — naprawa wymaga decyzji o starym kluczu
**Wplyw na uzytkownika:** `talus --verify-audit` bleduje na tej maszynie od 26.09

## Objaw

```
audit::flock_stress_tests::concurrent_writers_chain_stays_valid ... FAILED
thread panicked at process-monitor/src/audit.rs:815:
  chain corrupted after concurrent writes!: audit log integrity check failed:
  153 corrupted entries out of 153
```

Sprawdzone: **failuje takze przed commitem 4a6018e** (odtworzone na starym
`Cargo.lock`). To nie jest regresja z patcha frankentui.

## Co test robi

`flock_stress_tests::concurrent_writers_chain_stays_valid` (audit.rs:799):
4 watki x 15 wpisow przez prawdziwy `flock`, potem `verify_audit_log()`
musi przejsc. Test **nie uzywa katalogu tymczasowego** — `audit_log()` pisze
do `dirs::config_dir()/talus/audit.log`, czyli do tego samego pliku co
produkcja. Test i program dziela jeden log.

## Przyczyna (potwierdzona, nie zgadywana)

W logu na maszynie jest 334 wpisow. Z nich:

| Zrodlo | Wpisow | Klucz podpisu |
|---|---|---|
| Przed powstaniem `.audit.key` (22.09) | 5 | nie istniejacy juz — **nie do weryfikacji** |
| Po `.audit.key` (od 26.09) | 268+ | stabilny, `.audit.key` — **wszystkie poprawne** |

Sprawdzone recznie (odtworzony HMAC w `examples/legacy_key_probe.rs`, potem
usuniety):

```
wpisow: 273 | poprawnych pod stabilnym kluczem: 268 | pod legacy: 0
```

Czyli **5 pierwszych wpisow nie weryfikuje sie zadnym z dwóch kluczy**, ktore
`audit_verify_keys()` akceptuje.

### Dlaczego legacy ich nie ratuje

`audit_verify_keys()` = `[audit_hmac_key(), derive_audit_key()]`. Klucz legacy to
`SHA256("talus-audit-v1" || machine_id)`, gdzie `machine_id` to fingerprint:
hostname + MAC + model CPU + `/etc/machine-id`. **Ten fingerprint jest zmienny** —
zmiana karty sieciowej albo hostname uniewaznia caly log. Dlatego 26.09 klucz
zapisano w pliku `.audit.key`, a pięć wpisow z 22.09 powstalo jeszcze pod
`derive_audit_key()` z **innego** fingerprintu (inny MAC/hostname w dniu 22.09).
Nikt nie zachowal tamtego klucza, więc wpisów nie da się zweryfikowac w ogole.

### Dlaczego jeden zly wpis uniewaznia 153 kolejne

`verify_audit_log()` startuje `prev_hash = "0"` i idzie sekwencyjnie:

```rust
let mut prev_hash = "0".to_string();
...
if entry.prev_hash != prev_hash { corrupted += 1; continue; }   // nie aktualizuje prev_hash
if !entry.verifies_under_known_key(&prev_hash) { corrupted += 1; continue; }  // nie aktualizuje
prev_hash = entry.entry_hash;   // tylko tu
```

`continue` **nie** aktualizuje `prev_hash`. Wiec wpis nr 6 nie weryfikuje sie,
`prev_hash` zostaje z wpisu nr 5, a wpis nr 7 ma `prev_hash` = hash wpisu nr 6
— nie ten. Wszystkie kolejne wpisy sa przez to oznaczane jako uszkodzone,
mimo ze sa podpisane poprawnie. Jeden zly wpis z 22.09 uniewaznia caly
aktualny log.

## Dlaczego CI tego nie lapie

- `.github/workflows/ci-ultra.yml` ma job `audit`, ale to `cargo audit`
  (sprawdzanie CVE w zaleznosciach), nie testy logu audytowego.
- Ten konkretny test byl naprawiany 12.10 (`d8ade9b`) — commit dotyczyl wyScigu
  klucza na `OnceLock` i `flock` pod miri. Nie dotknal problemu ze starymi
  wpisami, bo na czystym runnerze GitHuba `~/.config/talus/audit.log` nie
  istnieje i test tworzy log od zera, czyli od razu pod stabilnym kluczem.
  **Test przechodzi w CI, bo tam nie ma starego logu.**

## Opcje naprawy

**A. Migracja starych wpisow przy weryfikacji (najlepsza, ale kosztowna)**
Skoro te 5 wpisow jest niesprawdzalnych, a `.audit.key` nie powstalo przed nimi,
jedyne co zostaje to uznanie ich za historyczne: przy pierwszym uruchomieniu
nowej wersji przepisac log, podpisujac stare wpisy biezacym kluczem, i zapisac
anchor. Wymaga jednorazowej migracji z jawnym zapisem, ze to robi.

**B. Ograniczyć weryfikacje do zakresu pod zrodlem klucza (drobna zmiana)**
`verify_audit_log()` pomija wpisy starsze niz data powstania `.audit.key`,
z wyrazenym ostrzezeniem. Prostsze, ale ukrywa fak, ze historia logu jest
czesciowo niesprawdzalna.

**C. Test w katalogu tymczasowym (poprawia test, nie log)**
Dodac `TALUS_CONFIG_DIR` / zmienna srodowiskowa, zeby test nie dotykal
produkcyjnego logu. Niezaleznie od tego wart zrobic — test powinien byc
hermetyczny. **Nie naprawia bledu produkcyjnego** (`--verify-audit` dalej bleduje).

## Rekomendacja

C — od razu, bo to blad w tescie (testy nie powinny pisac do katalogu
uzytkownika). A — potem, jednorazowa migracja z jawnym zapisem.
B — tylko jesli migracja A jest z jakiegos powodu niemozliwa.

Do decyzji Bartosza.