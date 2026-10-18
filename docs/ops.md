# Talus License Server — Ops Runbook

Gdzie co stoi, jak odtworzyć, jak testować failover. Sekrety NIGDY nie są
w tym pliku — tylko wskaźniki na `~/.secrets/talus/`.

## Topologia (stan na 2026-09-18)

```
                       ┌──────────────────────────────┐
  talus binary  ──●──► │ PRIMARY                       │
   (failover list      │ talus-license-server          │──┐
    w license.rs)      │ Cloudflare Worker (free)      │  │
                       └──────────────────────────────┘  │   ┌─────────────────────────┐
                       ┌──────────────────────────────┐  ├──► │ TURSO (libSQL, free)    │
  talus binary  ──●──► │ FAILOVER                      │──┘   │ talus-licenses          │
   (drugi element      │ talus-license-failover        │      │ aws-eu-west-1 (Irlandia)│
    listy)             │ Cloudflare Worker (free)      │      └─────────────────────────┘
                       └──────────────────────────────┘
                       ┌──────────────────────────────┐
                       │ D1  talus-licenses            │  FROZEN SNAPSHOT (backup,
                       │ 77c07193-…-616a25ad9fb9       │  nie obsługuje ruchu)
                       └──────────────────────────────┘
```

| Komponent | URL / lokalizacja | Storage | Rola |
|---|---|---|---|
| Primary | `https://lic.hartwell-labs.pl` | Turso (wspólny) | ruch produkcyjny |
| workers.dev alias | `https://talus-license-server.metaforicmail.workers.dev` | — | panel admina, awaryjnie |
| Failover | `https://talus-license-failover.metaforicmail.workers.dev` | Turso (wspólny) | automatyczny zapas |
| Baza | `https://talus-licenses-bartoszosiej.aws-eu-west-1.turso.io` | — | jedyne źródło prawdy |
| D1 snapshot | Cloudflare D1 `talus-licenses` (id `77c07193-9bc8-44e5-a31f-616a25ad9fb9`) | — | zamrożona kopia z 2026-09-18 |
| Klucz podpisujący | `~/.secrets/talus/license-keys/signing_key.json` (0600) | — | NIGDY nie opuszcza maszyny |

Oba serwery to **ten sam kod** (`license-server/src/`) — wybór storage robi
`src/db.js`: jest binding `DB` → D1; są `TURSO_*` → Turso po HTTP. Failover
nie ma bindingu D1 (`wrangler.failover.toml`), primary ma go obecnie
zakomentowanego w `wrangler.toml` (więc też używa Turso).

## Sekrety (wszystkie 0600, poza repo)

| Plik | Gdzie używane |
|---|---|
| `~/.secrets/talus/admin_token` | primary + failover (`ADMIN_TOKEN`), issue/revoke scripts |
| `~/.secrets/talus/totp_secret` | primary + failover (`TOTP_SECRET`) — ten sam seed, obie panele działać muszą |
| `~/.secrets/talus/turso_platform_token` | Platform API (turso.tech) — zarządzanie bazami |
| `~/.secrets/talus/turso_db_token` | token RW do bazy `talus-licenses` (exp. 1 rok) → sekret `TURSO_AUTH_TOKEN` na obu workerach |

Zmiana sekretu na workerze:

```bash
cd license-server
export CLOUDFLARE_API_TOKEN=$(cat ~/.cloudflare_token)
export CLOUDFLARE_ACCOUNT_ID=$(cat ~/.cloudflare_account | head -1)
npx wrangler secret put ADMIN_TOKEN                       # primary
npx wrangler secret put ADMIN_TOKEN -c wrangler.failover.toml
```

## Sprzedaż — Stripe Managed Payments (2026-10)

Talus Enterprise sprzedaje się przez Stripe. Stripe rozlicza sam (VAT, fraud,
wsparcie klienta) i **nie wydaje klucza sklepu** — dlatego webhook zapisuje
zwykły wiersz `pending` w `orders`, tak samo jak Polar, a klucz podpisuje
`scripts/issuer-daemon.mjs`.

```
Klient płaci  →  checkout.session.completed
              →  POST /api/v1/webhook/stripe   (podpis Stripe-Signature)
              →  orders(status='pending', customer_id, subscription_id, payment_intent)
              →  issuer-daemon   →  issue_license + bind + register
              →  e-mail z kluczem  (Resend, important@hartwell-labs.pl)
```

Do zapamiętania przy rozmowie z klientem: **klucz leci mailem, nie z webówki.**
Nigdy nie ufamy temu, co klient wpisał w przeglądarce — jedyne źródło prawdy to
wiersz w `orders`.

Sekrety (oba w `~/.config/hartwell/`, 0600):

```bash
npx wrangler secret put STRIPE_SECRET_KEY        # rk_live_... (restricted)
npx wrangler secret put STRIPE_WEBHOOK_SECRET   # whsec_... — pokazywany RAZ przy tworzeniu endpointu
```

**Sekret webhooka nie da się odzyskać.** Stripe pokazuje go jednorazowo przy
tworzeniu endpointu. Zgubiony = trzeba usunąć endpoint i utworzyć nowy, a wtedy
trzeba go od razu zapisać do pliku.

Zweryfikowanie, że webhook naprawdę działa (symulowany podpis, bez wpływu na
pieniądze ani na prawdziwe zamówienia):

```bash
node --test license-server/test/stripe-webhook-test.mjs
```

### Podatek — `not_collecting`, czyli nic nie jest pobierane

2026-10-18: kalkulacja dla polskiego klienta zwraca `taxability_reason:
not_collecting`, `tax_amount_exclusive: 0`. Powód: **konto nie ma ani jednej
rejestracji podatkowej** (`GET /v1/tax/registrations` → `[]`).

To jest najczęstszy błąd przy Stripe Tax i najbardziej podstępny: Stripe **nie
zwraca błędu**. Sesja ma `automatic_tax.enabled: true`, checkout wygląda
poprawnie, a VAT po prostu się nie pojawia. Stripe pobiera podatek wyłącznie
w jurysdykcjach, do których dodano rejestrację.

Dopóki rejestracji nie ma, żadna kwota nie jest doliczana do żadnego kraju.

Head office ma tylko `country: PL` (bez ulicy i kodu) — to wystarczy do
utworzenia rejestracji, ale warto uzupełnić, bo Stripe używa go jako punktu
wyjścia dla stawek.

Schemat rejestracji (OSS, standardowa vs. uproszczona) **nie jest wyborem
technicznym** — to decyzja księgowa. Ustala się ją z doradcą podatkowym.

Testy na żywo: poprawny podpis → 200, powtórzony event → 200 `already processed`
(idempotencja), podpis sprzed 2 h → 401, podpis innym sekretem → 401.

## Kluczowe komendy

```bash
cd license-server
export CLOUDFLARE_API_TOKEN=$(cat ~/.cloudflare_token)
export CLOUDFLARE_ACCOUNT_ID=$(cat ~/.cloudflare_account | head -1)

# deploy obu serwerów (ten sam kod, różne configi)
npx wrangler deploy
npx wrangler deploy -c wrangler.failover.toml

# health / stan
curl https://lic.hartwell-labs.pl/api/v1/health
curl https://talus-license-failover.metaforicmail.workers.dev/api/v1/health
curl -H "Authorization: Bearer $(cat ~/.secrets/talus/admin_token)" \
  https://lic.hartwell-labs.pl/api/v1/admin/stats
```

## Test failover (end-to-end, wykonany 2026-09-18 — OK)

```bash
# 1. wydaj klucz testowy
TALUS_KEYGEN_DIR=$HOME/.secrets/talus/license-keys \
  license-keygen/target/release/talus-keygen issue \
  --tier enterprise --organization "Hartwell Labs Test" --seats 1 --json

# 2. aktywuj z CELOWO martwym primary — binarka musi przeskoczyć na failover
TALUS_LICENSE_SERVER="https://127.0.0.1:1" \
TALUS_LICENSE_SERVER_FAILOVER="https://talus-license-failover.metaforicmail.workers.dev" \
  ./target/debug/process-monitor license activate "<KEY>"
# oczekiwane: "[talus] activation server ... unreachable; trying failover"
#             "[talus] ✓ license activated successfully"

# 3. dowód wspólnego storage: aktywacja widoczna na PRIMARY (inny worker!)
scripts/revoke-license.sh   # i revoke z poziomu primary
curl -H "Authorization: Bearer $(cat ~/.secrets/talus/admin_token)" ... /admin/stats

# 4. sprzątanie: deactivate binarką, revoke klucza, (opcjonalnie) unregister
```

## Odtwarzanie z katastrofy

**Padł primary worker** → nic nie robisz: binarka sama przeskakuje na
failover (wbudowany w liście serwerów).

**Padło konto Cloudflare (oba workery)** → wystaw ten sam kod gdziekolwiek
indziej (Deno Deploy / Vercel / drugie konto CF):

1. import `license-server/src/index.js` (Web-standard fetch, bez zależności),
2. env: `TURSO_DATABASE_URL`, sekrety `TURSO_AUTH_TOKEN`, `ADMIN_TOKEN`,
   `TOTP_SECRET`, `LICENSE_PUBLIC_KEY_HEX` (wartość jest w wrangler.toml),
3. gotowe — baza i tak jest na zewnątrz (Turso), workers są wymienne.

**Padła baza Turso** → przywróć z D1-snapshot (dane od 2026-09-18 wprawdzie
już nowsze mogą istnieć tylko w Turso — dlatego cotygodniowy eksport!):

```bash
# eksport aktualnego stanu Turso (rób to co tydzień — cron)
npx wrangler d1 export talus-licenses --remote --output=backup.sql  # stare narzędzie dla D1
# dla Turso: turso db shell talus-licenses .dump > backup.sql
# odtworzenie: schema.sql + backup.sql przez /v2/pipeline (analogicznie do migracji)
```

**Rollback primary na D1** (awaria Turso, użycie zamrożonego snapshotu):

1. w `wrangler.toml` odkomentuj `[[d1_databases]]`, usuń `[vars] TURSO_DATABASE_URL`,
2. usuń sekret `TURSO_AUTH_TOKEN` z primary workera,
3. `npx wrangler deploy` — primary z powrotem czyta D1 (stan z momentu snapshotu),
4. binarki klientów: `TALUS_LICENSE_SERVER_FAILOVER=""` wyłącza failover
   (żeby nie wskakiwały na serwer z innym stanem).

## Granice free tier (2026-09)

| Usługa | Limit | Ryzyko |
|---|---|---|
| Cloudflare Workers free | 100k req/dzień | przy 100+ aktywnych licencjach spokojnie; ataki zlewają się w rate limiter (5/5min/machine) |
| Turso free | 500 baz, 5 GB storage, 1 mld row-reads/mies. | dla license-server zapas ogromny; token exp. 1 rok → **ustawić przypomnienie na rotację ~2027-09** |
| Turso lokacje | tylko 6 lokacji AWS (w tym Irlandia) | brak WAW — akceptowalne |
| Deno Deploy free | 1 mln req/dzień | nieużywane (failover na CF); opcja awaryjna |

## Znane kompromisy / ryzyka

1. **Primary i failover na tym samym koncie Cloudflare** — wytrąca awarię
   D1/runtime, NIE awarii konta. Migracja na drugie konto = deploy
   `wrangler.failover.toml` z innym tokenem + ponowne sekrety (5 min).
2. **Turso `batch()` nie jest atomowy** (D1 jest) — używane tylko w akcjach
   admin (revoke/unrevoke/fulfill); kolejność statements i tak jest zachowana,
   a operacje są idempotentne.
3. **Jeden wspólny admin_token/TOTP seed na obu serwerach** — kompromis dla
   identycznego UX panelu; rotacja = dwa `wrangler secret put`.
4. **Token Turso wygasa po roku** — kalendarz: rotacja przed 2027-09-18.
