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

app.Run();
