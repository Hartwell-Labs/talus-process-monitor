# Talus Pricing Tiers (structure — no amounts)

> Pricing **amounts** are set by the owner. This document fixes only the
> **structure**: what each tier contains, and which dimensions drive the
> price of an Enterprise license. Keep it free of numbers.

## Tiers

### Community — free, MIT-licensed
For individuals, homelabs and evaluation.

| Included | Not included |
|---|---|
| TUI dashboard (7 panels) | Web dashboard & REST API |
| Plain-text & JSON output | Auto-kill (EDR response mode) |
| Real-time eBPF monitoring | Kafka streaming |
| Ransomware detection alerts | ClickHouse analytics |
| Community support (GitHub issues) | MemGraph process graphs |
| | C FFI library |
| | Priority support |

### Enterprise — paid, per this licensing system
For teams and organizations that need response, integration and support.

Everything in Community, plus:

| Feature | Notes |
|---|---|
| Web dashboard & REST API | TLS, WebSocket stream, metrics |
| Auto-kill (EDR response mode) | Automatic process termination on alerts |
| Kafka streaming | lz4-compressed event stream |
| ClickHouse analytics | Long-term batch storage |
| MemGraph process graphs | Process relationship analytics |
| C FFI library | Embed Talus in other products |
| Priority support channel | Direct email to the maintainer |

## Price dimensions (owner decides values)

| Dimension | Values | Effect on price |
|---|---|---|
| Term | perpetual · 1 year · 3 year | longer term → higher price |
| Seats (machines) | 1 · 5 · 10 · unlimited | more seats → higher price |
| ~~Managed nodes (`max_nodes`)~~ | **not a pricing dimension** | unenforced — see below |
| Support level | best-effort · business hours · 48h SLA | higher SLA → higher price |
| Organization | individual · team · enterprise | volume discounts possible |

## Recommended starter bundles (structure only)

- **Single-seat, 1 year** — evaluation by a small team.
- **5 seats, perpetual** — small org standard.
- **Unlimited seats + unlimited nodes, perpetual, 48h SLA** — enterprise-wide.

## What actually shipped (2026-10)

Talus is sold **per machine**: one purchased key is one seat, and `max_seats`
is the only limit the server enforces. There is no separate node cap.

| Tier | Price | Minimum |
|---|---|---|
| Community | free (MIT) | — |
| Enterprise | 50 USD / year / machine | 1 machine |
| Enterprise Fleet | 30 USD / year / machine | 10 machines |

The 10-node fleet floor is enforced in the Worker, not by Stripe: this account
rejects graduated pricing (`tiering_config`) and `transform_quantity` accepts
only `divide_by` and `round`, so a Price cannot express a minimum quantity.

## Where to set the actual amounts

1. Decide amounts for each dimension above.
2. Fill them in on the Stripe Payment Link. Live links:
   - Enterprise $50/machine/yr, qty 1–9 — `buy.stripe.com/4gMaEY2JYae4ekV2np2Fa02`
   - Enterprise Fleet $30/machine/yr, qty 10–500 — `buy.stripe.com/dRmbJ270e5XO1y96DF2Fa07`
   Prices are USD for every customer; there is no PLN price list.
3. Do **not** commit amounts into this repository — this file stays structural.
