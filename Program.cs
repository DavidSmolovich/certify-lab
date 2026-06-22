using CertifyLab.Domain;
using CertifyLab.Infrastructure;
using NHibernate;

var builder = WebApplication.CreateBuilder(args);

// Module ① — never advertise the server banner (real Kestrel hardening).
builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false);

// Self-contained SQLite DB; recreated and seeded on every startup.
var dbPath = Environment.GetEnvironmentVariable("CERTIFY_DB") ?? "/tmp/certify.db";
if (File.Exists(dbPath)) File.Delete(dbPath);

var sessionFactory = SessionFactoryBuilder.Build(dbPath);

builder.Services.AddSingleton<ISessionFactory>(sessionFactory);
builder.Services.AddSingleton<PolicyRepository>();
builder.Services.AddSingleton<ClaimRepository>();
builder.Services.AddSingleton<AdminRepository>();

var app = builder.Build();

// Serve the Certify portal frontend (wwwroot/index.html) at "/"
app.UseDefaultFiles();
app.UseStaticFiles();

// --- Simulated authentication -------------------------------------------------
// In production, customerId = the JWT 'sub' claim (validated at the gateway).
// For the lab, the "logged-in customer" is the X-Customer-Id header (default 1).
// The point: the attacker IS authenticated — auth is not the broken control here.
static int CurrentCustomer(HttpRequest req) =>
    int.TryParse(req.Headers["X-Customer-Id"].ToString(), out var id) ? id : 1;

static object Project(IEnumerable<Policy> policies) =>
    policies.Select(p => new
    {
        p.CustomerId,
        p.CustomerName,
        p.PolicyNumber,
        p.Type,
        p.Premium,
        p.Status
    });

// ❌ VULNERABLE build — concatenated HQL
app.MapGet("/api/v1/policies", (HttpRequest req, PolicyRepository repo) =>
{
    var customerId = CurrentCustomer(req);
    var type = req.Query["type"].ToString();
    if (string.IsNullOrEmpty(type)) type = "Auto";

    var result = repo.FindByTypeVulnerable(customerId, type);

    return Results.Json(new
    {
        endpoint = "VULNERABLE — concatenated HQL",
        loggedInCustomerId = customerId,
        filterType = type,
        returned = result.Count,
        leakedOtherCustomers = result.Any(p => p.CustomerId != customerId),
        policies = Project(result)
    });
});

// ✅ SECURE build — parameterized HQL
app.MapGet("/api/v2/policies", (HttpRequest req, PolicyRepository repo) =>
{
    var customerId = CurrentCustomer(req);
    var type = req.Query["type"].ToString();
    if (string.IsNullOrEmpty(type)) type = "Auto";

    var result = repo.FindByTypeSecure(customerId, type);

    return Results.Json(new
    {
        endpoint = "SECURE — parameterized HQL",
        loggedInCustomerId = customerId,
        filterType = type,
        returned = result.Count,
        leakedOtherCustomers = result.Any(p => p.CustomerId != customerId),
        policies = Project(result)
    });
});

// ── Claims & payouts (business-logic race condition) ──────────────────────
app.MapGet("/api/claims", (HttpRequest req, ClaimRepository claims) =>
{
    var cid = CurrentCustomer(req);
    var list = claims.ListForCustomer(cid).Select(c =>
    {
        var ps = claims.PayoutsFor(c.Id);
        return new
        {
            c.Id,
            c.ClaimNumber,
            c.Description,
            c.Amount,
            c.Status,
            timesPaid = ps.Count,
            totalPaid = ps.Sum(p => p.Amount)
        };
    });
    return Results.Json(list);
});

// ❌ VULNERABLE payout — TOCTOU race; concurrent calls pay the same claim repeatedly
app.MapPost("/api/v1/claims/{id:int}/payout", (int id, ClaimRepository claims) =>
    Results.Json(new { endpoint = "VULNERABLE — check-then-act", outcome = claims.PayoutVulnerable(id).ToString() }));

// ✅ SECURE payout — atomic conditional update; pays at most once
app.MapPost("/api/v2/claims/{id:int}/payout", (int id, ClaimRepository claims) =>
    Results.Json(new { endpoint = "SECURE — atomic state transition", outcome = claims.PayoutSecure(id).ToString() }));

// Reset a claim back to Approved (clears its payouts) so the lab is repeatable
app.MapPost("/api/claims/{id:int}/reset", (int id, ClaimRepository claims) =>
{
    claims.Reset(id);
    return Results.Json(new { reset = id });
});

// ── Quote draft import (insecure deserialization -> RCE) ──────────────────
// ❌ VULNERABLE — Json.NET with TypeNameHandling.All lets the payload pick the CLR
//    type to instantiate. A gadget (ReportTask) runs a command on deserialization.
app.MapPost("/api/v1/quotes/import", async (HttpRequest req) =>
{
    var json = await new StreamReader(req.Body).ReadToEndAsync();
    try
    {
        var settings = new Newtonsoft.Json.JsonSerializerSettings
        {
            TypeNameHandling = Newtonsoft.Json.TypeNameHandling.All
        };
        var obj = Newtonsoft.Json.JsonConvert.DeserializeObject(json, settings);
        return Results.Json(new
        {
            endpoint = "VULNERABLE — Json.NET TypeNameHandling.All",
            deserializedType = obj?.GetType().FullName,
            commandOutput = (obj as CertifyLab.Domain.ReportTask)?.Output,
            draft = obj?.ToString()
        });
    }
    catch (Exception ex)
    {
        return Results.Json(new { endpoint = "VULNERABLE — Json.NET TypeNameHandling.All", error = ex.Message });
    }
});

// ✅ SECURE — System.Text.Json binds into a concrete DTO. No embedded type names are
//    honoured, so the gadget is never instantiated and nothing executes.
app.MapPost("/api/v2/quotes/import", async (HttpRequest req) =>
{
    var json = await new StreamReader(req.Body).ReadToEndAsync();
    try
    {
        var draft = System.Text.Json.JsonSerializer.Deserialize<CertifyLab.Domain.QuoteDraft>(
            json, new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        return Results.Json(new
        {
            endpoint = "SECURE — System.Text.Json, no type binding",
            deserializedType = typeof(CertifyLab.Domain.QuoteDraft).FullName,
            commandOutput = (string)null,
            draft
        });
    }
    catch (Exception ex)
    {
        return Results.Json(new { endpoint = "SECURE — System.Text.Json, no type binding", error = ex.Message });
    }
});

// ════════════════════════════════════════════════════════════════════════════
//  SESSION 5 — Infrastructure, Databases & Server Hardening (4 toggled demos)
// ════════════════════════════════════════════════════════════════════════════

// ── ① Server hardening — verbose error + banners  vs  generic error + headers ──
app.MapGet("/api/v1/server/report", (HttpResponse res) =>
{
    res.Headers["Server"] = "Kestrel";
    res.Headers["X-Powered-By"] = "ASP.NET";
    return Results.Json(new
    {
        endpoint = "VULNERABLE — DeveloperExceptionPage in production",
        framework = ".NET 8.0",
        exception = "System.Data.SqlClient.SqlException (0x80131904): A network-related or instance-specific error occurred while establishing a connection to SQL Server.",
        stackTrace = "   at Certify.Data.PolicyContext.OpenAsync()\n   at Certify.Policies.PolicyService.GetForCustomer(Int32 id)\n   at Certify.Api.PoliciesController.Get()",
        leakedConnectionString = LabSecrets.ProdConnectionString,
        leakedHeaders = new[] { "Server: Kestrel", "X-Powered-By: ASP.NET" },
        securityHeaders = "none"
    }, statusCode: StatusCodes.Status500InternalServerError);
});

app.MapGet("/api/v2/server/report", (HttpResponse res) =>
{
    res.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
    res.Headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; frame-ancestors 'none'";
    res.Headers["X-Content-Type-Options"] = "nosniff";
    res.Headers["X-Frame-Options"] = "DENY";
    res.Headers["Referrer-Policy"] = "no-referrer";
    return Results.Json(new
    {
        endpoint = "SECURE — generic ProblemDetails, hardened headers",
        title = "An unexpected error occurred.",
        status = 500,
        traceId = Guid.NewGuid().ToString(),
        leakedConnectionString = (string)null,
        leakedHeaders = Array.Empty<string>(),
        securityHeaders = "HSTS · CSP · X-Content-Type-Options · X-Frame-Options · Referrer-Policy",
        note = "No stack trace, no connection string, no server/framework banner."
    }, statusCode: StatusCodes.Status500InternalServerError);
});

// ── ② Database least privilege — claims lookup, UNION-injected to internal_users ──
app.MapGet("/api/v1/db/claims-search", (HttpRequest req, AdminRepository admin) =>
{
    var r = admin.SearchClaimsVulnerable(req.Query["q"].ToString());
    return Results.Json(new
    {
        endpoint = "VULNERABLE — app login is a member of db_owner",
        effectiveGrant = "db_owner (entire database)",
        executedSql = r.Sql,
        columns = AdminRepository.Columns,
        rowCount = r.Rows?.Count ?? 0,
        reachedInternalUsers = r.ReachedInternalUsers,
        error = r.Error,
        rows = r.Rows
    });
});

app.MapGet("/api/v2/db/claims-search", (HttpRequest req, AdminRepository admin) =>
{
    var r = admin.SearchClaimsScoped(req.Query["q"].ToString());
    return Results.Json(new
    {
        endpoint = "SECURE — least-privilege login (Policies schema only)",
        effectiveGrant = "GRANT SELECT ON SCHEMA::Policies",
        executedSql = r.Sql,
        columns = AdminRepository.Columns,
        rowCount = r.Rows?.Count ?? 0,
        denied = r.Denied,
        error = r.Error,
        rows = r.Rows
    });
});

// ── ③ Secrets — committed appsettings.json  vs  Key Vault reference ───────────
app.MapGet("/api/v1/secrets/config", (IConfiguration config) =>
    Results.Json(new
    {
        endpoint = "VULNERABLE — secret hardcoded in committed appsettings.json",
        source = "appsettings.json (committed to git)",
        connectionString = config.GetConnectionString("Certify") ?? LabSecrets.ProdConnectionString,
        inGitHistory = true,
        note = "Deleting the line later won't help — git history keeps it. Rotate the credential."
    }));

app.MapGet("/api/v2/secrets/config", (IConfiguration config) =>
    Results.Json(new
    {
        endpoint = "SECURE — Azure Key Vault + Managed Identity",
        source = "Key Vault (resolved in-memory at startup)",
        appsettingsShows = LabSecrets.KeyVaultReference,
        connectionString = LabSecrets.Mask(LabSecrets.ProdConnectionString),
        inGitHistory = false,
        note = "No secret on disk, in the repo, or in the image."
    }));

// ── ④ SSRF — fetch any URL (reaches IMDS)  vs  allow-list + internal-IP block ──
app.MapPost("/api/v1/documents/fetch", async (HttpRequest req) =>
{
    var url = await ReadJsonField(req, "url") ?? "";
    if (!Uri.TryCreate(url, UriKind.Absolute, out var u))
        return Results.Json(new { endpoint = "VULNERABLE — no URL validation", error = "not a valid absolute URL" });

    var (status, body) = MockAzure.SimulateGet(u);    // fetches ANYTHING, incl. link-local
    return Results.Json(new
    {
        endpoint = "VULNERABLE — server fetches any URL (SSRF)",
        requestedUrl = url,
        reachedInternal = MockAzure.TargetsInternal(u),
        httpStatus = status,
        body
    });
});

app.MapPost("/api/v2/documents/fetch", async (HttpRequest req) =>
{
    var url = await ReadJsonField(req, "url") ?? "";
    if (!Uri.TryCreate(url, UriKind.Absolute, out var u))
        return Results.Json(new { endpoint = "SECURE — validated fetch", error = "not a valid absolute URL" });

    if (!MockAzure.IsAllowedDestination(u, out var reason))
        return Results.Json(new { endpoint = "SECURE — allow-list + internal-IP block", requestedUrl = url, blocked = true, reason });

    var (status, body) = MockAzure.SimulateGet(u);
    return Results.Json(new { endpoint = "SECURE — validated fetch", requestedUrl = url, blocked = false, httpStatus = status, body });
});

// The attacker presents the SSRF-stolen Managed Identity token to Key Vault.
app.MapPost("/api/attack/keyvault", async (HttpRequest req) =>
{
    var token = await ReadJsonField(req, "token") ?? "";
    var (ok, value) = MockAzure.KeyVaultGetSecret(token);
    return Results.Json(new { ok, secretUri = LabSecrets.KeyVaultSecretUri, connectionString = value });
});

static async Task<string> ReadJsonField(HttpRequest req, string field)
{
    try
    {
        using var doc = await System.Text.Json.JsonDocument.ParseAsync(req.Body);
        return doc.RootElement.TryGetProperty(field, out var v) ? v.GetString() : null;
    }
    catch { return null; }
}

app.Run();
