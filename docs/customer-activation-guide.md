# Customer Activation Guide

You bought a Talus Process Monitor **Enterprise** license — thank you!
This guide takes you from download to a running Enterprise installation.

---

## 1. What you received

After payment you received an email containing:

- **License key** — a long string of the form
  `<base64 payload>.<base64 signature>`, for example:

  ```
  eyJsaWNlbnNlX2lkIjoiVEFMVVMtLi4uIn0=.pcyuHYvdga4Z3IIqjkK+rUw3xRN0AuVl488XBoOXmmQp==
  ```

  Treat it like a password: anyone who has it can use one of your seats.

- The **EULA** (`docs/EULA.txt`) — activating the key means you accept it.

---

## 2. Download the binary

Grab the latest **Enterprise-capable** release from
[GitHub Releases](https://github.com/Hartwell-Labs/talus-process-monitor/releases).
Every release asset ships with SHA-256 checksums and Sigstore signatures —
verify before running:

```bash
sha256sum -c talus-x86_64-linux.tar.gz.sha256
```

## 3. Activate

On the machine you want to license (one key = one machine):

```bash
talus license activate <YOUR-KEY>
```

You should see:

```
[talus] contacting activation server: https://talus-license-server.metaforicmail.workers.dev
[talus] ✓ license activated successfully
[talus] license: TALUS-XXXX-XXXX-XXXX (enterprise)
```

## 4. Verify

```bash
talus license show
```

Check that the box shows:

- **Tier: enterprise**
- Your **organization** name
- The **expiry** date you purchased
- **Activation: ✓ activated**

Also confirm Enterprise features now start, e.g.:

```bash
talus monitor --web --auto-kill   # both require Enterprise
```

## 5. Day-to-day

| Task | Command |
|---|---|
| Show license status | `talus license show` |
| Check machine fingerprint | `talus license machine-id` |
| Move to a new machine | `talus license deactivate` on the old one, then activate on the new one |
| Backup your activation | `talus license backup ~/talus-license.bak` |
| Restore a backup | `talus license restore ~/talus-license.bak` |
| Export license info as JSON | `talus license export` |

Notes:

- The machine is fingerprinted from hostname, MAC addresses, CPU model and
  `/etc/machine-id`. Cloned VMs may look identical — deactivate the old clone
  first if you hit a machine mismatch.
- Activation needs internet access once. After that the binary runs offline
  (30-day offline grace, then re-activation is requested).
- If the activation server is unreachable, the binary still verifies your
  key's cryptographic signature locally.

## 6. Troubleshooting

| Symptom | Meaning | Fix |
|---|---|---|
| `license signature verification failed` | key was mistyped or damaged | copy the key again from the email, exactly as sent (it is one long line) |
| `seat limit reached (N)` | all seats are in use | free one with `talus license deactivate` on an old machine, or buy more seats |
| `license ... has been revoked` | key was revoked by the vendor | contact support with your order number |
| `license ... has expired` | term license past its date | renew to get a new key |
| `activation token has expired` | token refresh needed | run `talus license activate <KEY>` again |
| `license is activated for a different machine` | fingerprint changed (hardware change, VM clone) | deactivate and re-activate, or contact support |

Support: open a ticket via email (see your purchase email) or
[GitHub issues](https://github.com/Hartwell-Labs/talus-process-monitor/issues)
for non-sensitive questions.
