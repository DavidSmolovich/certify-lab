using NHibernate;

namespace CertifyLab.Infrastructure;

/// <summary>
/// Module ② — Database least privilege, shown through a *legitimate* feature.
///
/// "Claims lookup" is a normal internal staff tool: search claims by claimant name.
/// The search term is concatenated into the SQL (an injection bug — the real fix is
/// parameterization, Session 4). This module's point is different: when an attacker
/// UNION-injects to read `internal_users` (admin password hashes), whether it SUCCEEDS
/// is decided only by the privilege of the application's DB login:
///   ❌ db_owner        → the cross-table read succeeds (full compromise),
///   ✅ least privilege  → the same injection is denied on `internal_users`.
///
/// SQLite has no role engine, so the scoped login's DENY is modelled here in the
/// repository (see the Module ② slides). Same bug, different blast radius.
/// </summary>
public class AdminRepository
{
    private readonly ISessionFactory _factory;
    public AdminRepository(ISessionFactory factory) => _factory = factory;

    // Display headers for the claims-lookup result grid.
    public static readonly string[] Columns = { "Claim #", "Claimant", "Description", "Amount" };

    public record SearchResult(string Sql, IList<string[]> Rows, bool ReachedInternalUsers, bool Denied, string Error);

    // The legitimate query — IDENTICAL in both builds; only the DB login's privilege differs.
    private static string BuildSql(string nameFilter) =>
        "SELECT ClaimNumber, CustomerName, Description, Amount " +
        "FROM Claims WHERE CustomerName LIKE '%" + nameFilter + "%'";

    // Tables the application's own login is granted. Anything else => no SELECT grant.
    private static bool TouchesForbiddenTable(string sql) =>
        sql.ToLowerInvariant().Contains("internal_users");

    // ❌ db_owner — runs whatever the query became, across the whole database.
    public SearchResult SearchClaimsVulnerable(string nameFilter)
    {
        var sql = BuildSql(nameFilter);
        try
        {
            return new SearchResult(sql, Exec(sql), TouchesForbiddenTable(sql), false, null);
        }
        catch (Exception ex) { return new SearchResult(sql, null, false, false, ex.Message); }
    }

    // ✅ Least privilege — the scoped login is denied any table outside its grant.
    public SearchResult SearchClaimsScoped(string nameFilter)
    {
        var sql = BuildSql(nameFilter);
        if (TouchesForbiddenTable(sql))
            return new SearchResult(sql, null, false, true,
                "SELECT permission denied on object 'internal_users' — login 'svc_certify_app' is granted only the Policies schema (no db_owner).");
        try
        {
            return new SearchResult(sql, Exec(sql), false, false, null);
        }
        catch (Exception ex) { return new SearchResult(sql, null, false, false, ex.Message); }
    }

    private IList<string[]> Exec(string sql)
    {
        using var session = _factory.OpenSession();
        return session.CreateSQLQuery(sql).List<object[]>()
            .Select(r => r.Select(c => c?.ToString() ?? "").ToArray())
            .ToList();
    }
}
