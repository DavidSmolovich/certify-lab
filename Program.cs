using CertifyLab.Domain;
using CertifyLab.Infrastructure;
using NHibernate;

var builder = WebApplication.CreateBuilder(args);

// Self-contained SQLite DB; recreated and seeded on every startup.
var dbPath = Environment.GetEnvironmentVariable("CERTIFY_DB") ?? "/tmp/certify.db";
if (File.Exists(dbPath)) File.Delete(dbPath);

var sessionFactory = SessionFactoryBuilder.Build(dbPath);

builder.Services.AddSingleton<ISessionFactory>(sessionFactory);
builder.Services.AddSingleton<PolicyRepository>();
builder.Services.AddSingleton<ClaimRepository>();

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

app.Run();
