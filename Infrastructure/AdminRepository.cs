using NHibernate;

namespace CertifyLab.Infrastructure;

/// <summary>
/// Module ② — Database least privilege.
///
/// `internal_users` is a sensitive table OUTSIDE the application's domain model
/// (admin credential hashes). The application never needs it. Two reads of the
/// same table model the same query running under two different SQL Server logins:
///   ❌ a login that is a member of db_owner  → reaches the whole database,
///   ✅ a login scoped to the app's own tables → permission denied.
///
/// SQLite has no role engine, so the scope check is enforced in the repository to
/// model the GRANT/DENY you would configure on SQL Server (see the Module ② slides).
/// </summary>
public class AdminRepository
{
    private readonly ISessionFactory _factory;
    public AdminRepository(ISessionFactory factory) => _factory = factory;

    public record LeakedUser(string Username, string PasswordHash, string Role, string Mfa);

    // The only tables the application's own login is granted.
    private static readonly HashSet<string> AppSchemaTables =
        new(StringComparer.OrdinalIgnoreCase) { "Policy", "Claim", "Payout" };

    // ❌ db_owner — one foothold reads admin password hashes, the audit log, everything.
    public IList<LeakedUser> DumpInternalUsersVulnerable()
    {
        using var session = _factory.OpenSession();
        return session
            .CreateSQLQuery("SELECT username, password_hash, role, mfa FROM internal_users")
            .List<object[]>()
            .Select(r => new LeakedUser((string)r[0], (string)r[1], (string)r[2], (string)r[3]))
            .ToList();
    }

    // ✅ Least privilege — the scoped login may only touch the app's own tables.
    public (bool allowed, string error, IList<LeakedUser> rows) ReadTableScoped(string table)
    {
        if (!AppSchemaTables.Contains(table))
            return (false,
                $"SELECT permission denied on object '{table}' — login 'svc_certify_app' is granted only the Policies schema (no db_owner).",
                null);

        // (App tables would be returned here; not needed for the demo.)
        return (true, null, new List<LeakedUser>());
    }
}
