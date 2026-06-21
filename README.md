# Certify Lab — Secure SDLC Hands-On (.NET / NHibernate)

> **Secure SDLC · Session 4 — Backend Logic & Data Integrity · Session 5 — Infrastructure, Databases & Server Hardening**
> A hands-on companion to the slides. Unlike the Juice Shop demos (Node.js), this lab is **C# .NET Core + NHibernate** — *your* stack. The bugs, and the fixes, are in your own language.

**Session 4** — three backend flaws in the **Certify Insurance** portal, each a ❌ vulnerable / ✅ secure endpoint you flip with a toggle:

1. **HQL injection** — a logged-in customer tampers with a filter and reads **every** customer's policies.
2. **Race condition (double payout)** — firing simultaneous claim-payout requests pays the same claim **multiple times**.
3. **Insecure deserialization → RCE** — importing a crafted "saved quote" runs arbitrary commands on the server.

**Session 5** — four more toggled demos covering the *environment* the code runs in (new tabs: **Server**, **Database**, **Secrets**, **Documents**):

4. **Server hardening** — a production error page leaks the connection string, stack trace, and server banners.
5. **Database least privilege** — an over-privileged (`db_owner`) app login reads a sensitive `internal_users` table.
6. **Secrets management** — the DB connection string sits in a committed `appsettings.json` instead of Key Vault.
7. **SSRF → cloud metadata** — a "fetch document from URL" feature is tricked into stealing the Managed Identity token and the DB credentials.

---

# Vulnerability 1 — HQL injection

## The scenario

**Certify Insurance** runs a self-service portal. The "list my policies" feature filters by policy type (`Auto`, `Home`, `Life`, `Health`). It mirrors how you ship today:

```
Angular SPA  →  API Gateway (JWT)  →  PolicyService (.NET Core)  →  NHibernate  →  SQL Server
```

- `customerId` is taken from the **validated JWT** — never from the request. That part is correct.
- The `type` filter is **concatenated into an HQL string**. That is the hole.

> The lab uses **SQLite** so the whole thing runs in a single container with no external database. HQL is database-agnostic — the identical injection occurs against **SQL Server** in production.

---

## What you'll prove

1. An **authenticated** customer (the attacker holds a valid JWT) can read **all** customers' policies.
2. The vulnerability is in **data access**, not authentication — the gateway did its job; the query did not.
3. The fix is to **bind the filter as a parameter**. One line.

---

## Run it (Docker)

**Prerequisite:** Docker Desktop (or Docker Engine + Compose).

```bash
cd CertifyLab

# Option A — one command
docker compose up --build

# Option B — plain Docker
docker build -t certify-lab .
docker run --rm -p 8088:8080 certify-lab
```

Then open **http://localhost:8088** — the Certify Insurance portal. Use the **toggle at the top** to switch
every request between the ❌ vulnerable (`/api/v1`) and ✅ secure (`/api/v2`) endpoints, type a filter (or hit
the red **💉 inject** chip), and watch other customers' policies appear in red when the breach happens. The
container logs print the **generated SQL** so you can show the injected `OR '1'='1'` reaching the DB.

The curl walkthrough below does the same thing from the terminal.

---

## Walkthrough

> The `X-Customer-Id` header stands in for the JWT subject — it is **you**, the logged-in customer (#1).
> Examples use `bash`/Git Bash curl. On PowerShell use `curl.exe` (not the `curl` alias).

### Step 1 — Normal use: you see only your own policies

```bash
curl -G http://localhost:8088/api/v1/policies \
     -H "X-Customer-Id: 1" --data-urlencode "type=Auto"
```

Expected — **1** policy, all yours:

```json
{
  "endpoint": "VULNERABLE — concatenated HQL",
  "loggedInCustomerId": 1,
  "filterType": "Auto",
  "returned": 1,
  "leakedOtherCustomers": false,
  "policies": [
    { "customerId": 1, "customerName": "Dana Cohen", "policyNumber": "CERT-2026-1001",
      "type": "Auto", "premium": 2400, "status": "Active" }
  ]
}
```

### Step 2 — The attack: one filter leaks everyone

```bash
curl -G http://localhost:8088/api/v1/policies \
     -H "X-Customer-Id: 1" --data-urlencode "type=x' OR '1'='1"
```

Expected — **7** policies, `leakedOtherCustomers: true`, including the CEO's ₪45,000 life policy:

```json
{
  "endpoint": "VULNERABLE — concatenated HQL",
  "loggedInCustomerId": 1,
  "filterType": "x' OR '1'='1",
  "returned": 7,
  "leakedOtherCustomers": true,
  "policies": [
    { "customerId": 1, "customerName": "Dana Cohen",      "type": "Auto",   "premium": 2400  },
    { "customerId": 2, "customerName": "Yossi Levi",       "type": "Life",   "premium": 980   },
    { "customerId": 3, "customerName": "Maya Friedman",    "type": "Auto",   "premium": 2675  },
    { "customerId": 4, "customerName": "Avi Stern (CEO)",  "type": "Life",   "premium": 45000 }
    // ... and the rest
  ]
}
```

You were customer #1. You are now reading customer #4's data. **That is a reportable PII breach for an insurer.**

### Step 3 — See it in the SQL

In the container logs you'll see NHibernate emit roughly:

```sql
select ... from Policies policy0_
where  policy0_.CustomerId = 1 and policy0_.Type = 'x' OR '1'='1'
```

`AND` binds tighter than `OR`, so this reads as `(CustomerId = 1 AND Type = 'x') OR ('1'='1')` → **always true** → every row.

### Step 4 — The secure build neutralizes the same attack

```bash
curl -G http://localhost:8088/api/v2/policies \
     -H "X-Customer-Id: 1" --data-urlencode "type=x' OR '1'='1"
```

Expected — **0** policies, `leakedOtherCustomers: false`. The payload is now treated as a literal policy
type (which matches nothing), because it was sent as **data**, not query text.

---

## The code — vulnerable vs fixed

Both live in [`Infrastructure/PolicyRepository.cs`](Infrastructure/PolicyRepository.cs):

```csharp
// ❌ VULNERABLE — 'type' concatenated into the HQL string
var hql = "from Policy p where p.CustomerId = " + customerId +
          " and p.Type = '" + type + "'";
return session.CreateQuery(hql).List<Policy>();

// ✅ SECURE — 'type' bound as a named parameter
return session
    .CreateQuery("from Policy p where p.CustomerId = :cid and p.Type = :type")
    .SetParameter("cid", customerId)
    .SetParameter("type", type)
    .List<Policy>();

// ✅ Even safer — QueryOver, no query string at all (compile-checked)
// return session.QueryOver<Policy>()
//     .Where(p => p.CustomerId == customerId && p.Type == type).List();
```

---

# Vulnerability 2 — Race condition: double-paying a claim

An approved claim should be paid out **once** (`Status: Approved → Paid`). The vulnerable payout handler
checks the status and *then* disburses as two separate steps — a **TOCTOU** gap. Fire several payout requests
at the same instant and they all pass the check before any of them flips the status, so the claim is paid
multiple times. No scanner flags this; the code is "correct."

### Demo it (portal)

Open the **Claims** tab with the toggle on **❌ Vulnerable (v1)**, find claim `CLM-2026-0007` (₪250,000
total-loss) and click **⚡ Fire 5× (race)**. The ledger shows the claim **paid 5×** with a red **DOUBLE
PAYOUT** banner — ₪1,250,000 disbursed on a ₪250,000 claim. Flip to **✅ Secure (v2)**, **Reset**, race
again → it pays **once**.

### Demo it (terminal, parallel requests)

```bash
# fire 5 payouts at once at the VULNERABLE endpoint (claim id 3 = CLM-2026-0007)
curl --parallel --parallel-immediate -X POST \
  http://localhost:8088/api/v1/claims/3/payout http://localhost:8088/api/v1/claims/3/payout \
  http://localhost:8088/api/v1/claims/3/payout http://localhost:8088/api/v1/claims/3/payout \
  http://localhost:8088/api/v1/claims/3/payout

curl -s -H "X-Customer-Id: 1" http://localhost:8088/api/claims    # CLM-2026-0007 -> timesPaid 5, totalPaid 1250000
curl -s -X POST http://localhost:8088/api/claims/3/reset          # reset, then race /api/v2 -> timesPaid 1
```

Verified: **v1 → paid 5× (₪1,250,000)** · **v2 → paid once (₪250,000)**.

### The code — vulnerable vs fixed

Both live in [`Infrastructure/ClaimRepository.cs`](Infrastructure/ClaimRepository.cs):

```csharp
// ❌ VULNERABLE — check, gap, then act (TOCTOU). Concurrent calls all pass the check.
var claim = session.Get<Claim>(id);
if (claim.Status != "Approved") return AlreadyPaid;     // time of check
Thread.Sleep(200);                                      // fraud check / bank call = the race window
claim.Status = "Paid"; session.Update(claim);           // time of use
session.Save(new Payout { ... });

// ✅ SECURE — atomic conditional transition; the DB picks exactly one winner.
int affected = session.CreateQuery(
    "update Claim c set c.Status = 'Paid' where c.Id = :id and c.Status = 'Approved'")
    .SetParameter("id", id).ExecuteUpdate();
if (affected != 1) return AlreadyPaid;                  // someone else already flipped it
session.Save(new Payout { ... });
```

Other valid fixes on their stack: **optimistic concurrency** (a `<version>` column → the loser gets
`StaleObjectStateException`), a **pessimistic lock** (`session.Get<Claim>(id, LockMode.Upgrade)` →
`SELECT … FOR UPDATE`), or a **UNIQUE constraint** on `Payouts(ClaimId)` as a backstop.

---

# Vulnerability 3 — Insecure deserialization → remote code execution

Customers can export an in-progress application and **re-import** it later. The importer deserializes the
uploaded JSON with **Json.NET `TypeNameHandling.All`**, which lets the *payload* choose which .NET type to
build. By naming a "gadget" type (`ReportTask`) plus a command, an attacker turns an import into **arbitrary
code execution on the server**.

### Demo it (portal)

Open the **Quote Import** tab with the toggle on **❌ Vulnerable (v1)**. Pick a command (e.g. `id`), click
**💣 Build RCE payload**, then **Import draft** — a red **REMOTE CODE EXECUTION** banner shows the command
output. Flip to **✅ Secure (v2)** and import the same payload: nothing runs.

### Demo it (terminal)

```bash
curl -s -X POST http://localhost:8088/api/v1/quotes/import \
  -H "Content-Type: application/json" \
  -d '{"$type":"CertifyLab.Domain.ReportTask, CertifyLab","Run":"id; hostname; uname -a"}'
```

Verified output — the gadget ran **as root** in the container:

```
uid=0(root) gid=0(root) groups=0(root)
9894f6c4aef5
Linux 9894f6c4aef5 ... x86_64 GNU/Linux
```

The same request to `/api/v2/quotes/import` returns an empty `QuoteDraft` and `commandOutput: null` — the
gadget type is never instantiated.

### The code — vulnerable vs fixed

Gadget in [`Domain/ReportTask.cs`](Domain/ReportTask.cs); endpoints in [`Program.cs`](Program.cs):

```csharp
// ❌ VULNERABLE — the payload picks the CLR type; a gadget runs code on deserialization.
var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
var obj = JsonConvert.DeserializeObject(json, settings);   // builds ReportTask -> RCE

// ✅ SECURE — bind into a concrete DTO with a serializer that ignores embedded types.
var draft = System.Text.Json.JsonSerializer.Deserialize<QuoteDraft>(json, opts);  // data only
```

The rule: **never deserialize untrusted input with type information enabled.** Use a data-only serializer
(`System.Text.Json`) into a known type. If polymorphism is genuinely required, allow-list types with
`[JsonDerivedType]` — never `TypeNameHandling.All`. `BinaryFormatter` (removed in .NET 9) is the same trap.

---

# Session 5 — Infrastructure, Databases & Server Hardening

Four more toggled demos in the **same portal** — this time the *environment* the code runs in. Same
❌v1 / ✅v2 toggle; new tabs: **Server**, **Database**, **Secrets**, **Documents**.

> **Fully offline.** A **mock Azure IMDS** and **mock Key Vault** live inside the app, alongside a seeded
> `internal_users` table and a deliberately-committed `appsettings.json`. No cloud account, no external SQL
> Server. The address `169.254.169.254` is simulated so the SSRF chain runs on your laptop.

## ① Server hardening — the error page that leaks everything

**Portal:** open the **Server** tab and **Run server report** on ❌v1 — the response leaks the **connection
string**, a stack trace, the framework version, and `Server` / `X-Powered-By` banners. Flip to ✅v2 — a
generic error, banners gone, security headers (HSTS, CSP, `nosniff`, …) present.

```bash
curl -i http://localhost:8088/api/v1/server/report   # ❌ leaks the connection string + banners
curl -i http://localhost:8088/api/v2/server/report   # ✅ generic ProblemDetails, hardened headers
```

Code: the `/server/report` endpoints in `Program.cs` + `builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false)`.

## ② Database least privilege — db_owner vs scoped login

The policy service has a foothold and pivots to `internal_users` (admin credential hashes), a table it never
needs. Whether it succeeds depends only on the **DB login's privilege**.

**Portal:** **Database** tab → **⛏️ Dump internal_users**. ❌v1 (db_owner) returns the hashes; ✅v2 (scoped) is denied.

```bash
curl -s http://localhost:8088/api/v1/db/internal-users   # ❌ db_owner -> admin password hashes
curl -s http://localhost:8088/api/v2/db/internal-users   # ✅ least privilege -> permission denied
```

Code: `Infrastructure/AdminRepository.cs`; the sensitive table is seeded in `SessionFactoryBuilder.cs`.

## ③ Secrets — committed appsettings.json vs Key Vault

**Portal:** **Secrets** tab → **Read config**. ❌v1 reads the connection string straight from committed
`appsettings.json`; ✅v2 shows only a `@Microsoft.KeyVault(...)` reference and a masked, runtime-resolved value.

```bash
curl -s http://localhost:8088/api/v1/secrets/config   # ❌ plaintext secret from appsettings.json
curl -s http://localhost:8088/api/v2/secrets/config   # ✅ Key Vault reference; value masked
git log -p -- appsettings.json                        # the secret is in history — rotate, don't just delete
```

Code: `appsettings.json` (the committed secret) + the `/secrets/config` endpoints in `Program.cs`.

## ④ SSRF → cloud metadata → Key Vault → DB

A "fetch document from URL" feature. ❌v1 fetches **anything**; point it at the metadata endpoint and the
server hands back its **Managed Identity token**, which unlocks Key Vault and the DB credentials. ✅v2
allow-lists the host and blocks link-local / private addresses.

**Portal:** **Documents** tab → click the **☠️ SSRF: Azure IMDS token** chip → **Fetch** on ❌v1. The page
renders the full chain: SSRF → token → Key Vault → connection string. Flip to ✅v2 → blocked.

```bash
# ❌ v1 — SSRF reaches the (simulated) Azure metadata endpoint and returns the MI token
curl -s -X POST http://localhost:8088/api/v1/documents/fetch -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/metadata/identity/oauth2/token?resource=https://vault.azure.net"}'

# present the stolen token to Key Vault -> the DB connection string
curl -s -X POST http://localhost:8088/api/attack/keyvault -H "Content-Type: application/json" \
  -d '{"token":"<access_token from the response above>"}'

# ✅ v2 — the same URL is blocked (link-local, not on the allow-list)
curl -s -X POST http://localhost:8088/api/v2/documents/fetch -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/metadata/identity/oauth2/token"}'
```

Code: `Infrastructure/MockAzure.cs` (the IMDS / Key Vault mocks **and** the real v2 allow-list + private-IP
checks); endpoints in `Program.cs`.

### Map to the deck (Session 5)

| Deck | This lab |
|---|---|
| **Slides 7–9** — verbose errors / leaked connection string | **Server** tab |
| **Slides 11–12** — security headers, banners off | the header table in the Server tab |
| **Slides 15–18** — least privilege, `db_owner` blast radius | **Database** tab |
| **Slides 24–27** — secrets in config → Key Vault | **Secrets** tab |
| **Slides 33–35** — SSRF → IMDS → Key Vault chain | **Documents** tab |

---

## How you'd catch these at Certify (DevSecOps)

- **SonarQube taint analysis** — flags untrusted request data (`type`) reaching the `CreateQuery` sink.
- **Roslyn analyzer** `CA3001` (review for SQL injection) promoted to a **build error** in `.editorconfig`.
- **Code review** — the two-person PR gate should reject any `CreateQuery("..." + value)`, and any
  "check then write" on money/state that isn't atomic.
- **Regression test** — assert the injection payload on `/api/v1` returns only the caller's rows.
- **Concurrency test** — fire N parallel payout requests in an integration test and assert the claim is paid
  exactly once. Scanners can't see race conditions; only tests do.
- **Roslyn analyzers** `CA2326` (no `TypeNameHandling` other than `None`) and `CA2300`/`SYSLIB0011`
  (no `BinaryFormatter`) promoted to **build errors**; grep PRs for `TypeNameHandling` and `BinaryFormatter`.

---

## Map to the deck

| Deck | This lab |
|---|---|
| **Slide 5** — design vs attack sequence diagrams | the policy-lookup flow you run here |
| **Slide 12** — NHibernate HQL injection fix | `PolicyRepository` before/after |
| **Business-logic flaws** — race conditions / TOCTOU | `ClaimRepository` payout before/after |
| **Slides 15–18** — insecure deserialization → RCE | `ReportTask` gadget + import endpoints |
| **Slides 27–30** — DevSecOps gates | the detection checklist above |

---

## Reset / teardown

```bash
docker compose down        # or Ctrl-C if you used docker run --rm
```

The SQLite database is recreated and reseeded on every startup, so the lab is always in a known state.

---

## Files

```
CertifyLab/
├─ Program.cs                         # API endpoints (v1 vuln / v2 secure) + serves the portal UI
├─ Domain/
│  ├─ Policy.cs                       # policy entity (HQL injection demo)
│  ├─ Claim.cs  ·  Payout.cs          # claim + payout ledger (race-condition demo)
│  ├─ ReportTask.cs                   # deserialization gadget (RCE)
│  └─ QuoteDraft.cs                   # safe import DTO (System.Text.Json target)
├─ Infrastructure/
│  ├─ PolicyMap.cs  ·  ClaimMaps.cs   # NHibernate mappings
│  ├─ SessionFactoryBuilder.cs        # SQLite config (WAL) + schema + seed
│  ├─ MicrosoftDataSqliteDriver.cs    # NHibernate driver for Microsoft.Data.Sqlite
│  ├─ PolicyRepository.cs             # ❌/✅ HQL injection
│  ├─ ClaimRepository.cs              # ❌/✅ race condition  (TOCTOU)
│  ├─ AdminRepository.cs              # ❌/✅ DB least privilege (internal_users)   [S5 ②]
│  ├─ LabSecrets.cs                   # shared fake connection string / MI token    [S5]
│  └─ MockAzure.cs                    # mock IMDS + Key Vault + SSRF URL validation  [S5 ④]
├─ appsettings.json                   # deliberately-committed secret               [S5 ③]
├─ wwwroot/index.html                 # portal UI — 7 tabs, v1 ↔ v2 toggle
├─ Dockerfile · docker-compose.yml · .dockerignore
└─ README.md
```

---

*ToDo Security Solutions · Secure SDLC · Sessions 4–5 · David Smolovich · david@smolovich.com*
