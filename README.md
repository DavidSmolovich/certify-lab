# Certify Lab — HQL Injection in a Policy-Lookup Microservice

> **Secure SDLC · Session 4 — Backend Logic & Data Integrity**
> A hands-on companion to **Slide 5**. Unlike the Juice Shop demos (Node.js), this lab is **C# .NET Core + NHibernate** — *your* stack. The bug, and the fix, are in your own language.

A logged-in **Certify Insurance** customer opens the policy portal to list *their* policies, filtered by type. With one tampered filter value they walk out with **every customer's** policies — names, policy numbers, premiums. Then you fix it in one line.

---

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

## How you'd catch this at Certify (DevSecOps)

- **SonarQube taint analysis** — flags untrusted request data (`type`) reaching the `CreateQuery` sink.
- **Roslyn analyzer** `CA3001` (review for SQL injection) promoted to a **build error** in `.editorconfig`.
- **Code review** — the two-person PR gate should reject any `CreateQuery("..." + value)`.
- **Regression test** — assert the attack payload on `/api/v1` returns only the caller's rows. Once the
  fix lands, that test fails forever if someone reintroduces concatenation.

---

## Map to the deck

| Deck | This lab |
|---|---|
| **Slide 5** — design vs attack sequence diagrams | the exact flow you run here |
| **Slide 12** — NHibernate HQL injection fix | `PolicyRepository` before/after |
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
├─ Program.cs                         # endpoints: /api/v1 (vuln), /api/v2 (secure); serves the portal UI
├─ Domain/Policy.cs                   # the entity
├─ Infrastructure/
│  ├─ PolicyMap.cs                    # NHibernate mapping-by-code
│  ├─ SessionFactoryBuilder.cs        # SQLite config + schema + seed
│  ├─ MicrosoftDataSqliteDriver.cs    # NHibernate driver for Microsoft.Data.Sqlite
│  └─ PolicyRepository.cs             # ❌ vulnerable + ✅ secure queries  <-- the lab
├─ wwwroot/index.html                 # Certify portal UI — toggle switches v1 ↔ v2
├─ Dockerfile · docker-compose.yml · .dockerignore
└─ README.md
```

---

*ToDo Security Solutions · Secure SDLC · Session 4 — Backend Logic & Data Integrity · David Smolovich · david@smolovich.com*
