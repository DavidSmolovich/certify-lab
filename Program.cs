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

app.Run();
