using CertifyLab.Domain;
using NHibernate;
using NHibernate.Cfg;
using NHibernate.Dialect;
using NHibernate.Driver;
using NHibernate.Mapping.ByCode;
using NHibernate.Tool.hbm2ddl;

namespace CertifyLab.Infrastructure;

/// <summary>
/// Builds the NHibernate <see cref="ISessionFactory"/> over a self-contained SQLite
/// database, (re)creates the schema and seeds demo data so the lab is deterministic.
/// </summary>
public static class SessionFactoryBuilder
{
    public static ISessionFactory Build(string dbPath)
    {
        var cfg = new Configuration();

        cfg.DataBaseIntegration(db =>
        {
            db.Dialect<SQLiteDialect>();
            db.Driver<MicrosoftDataSqliteDriver>();
            db.ConnectionString = $"Data Source={dbPath};Default Timeout=30";
            db.LogSqlInConsole = true;     // print the generated SQL to the container logs
            db.LogFormattedSql = true;
        });

        // Microsoft.Data.Sqlite doesn't implement the GetSchema metadata collections
        // ("DataTypes"/"ReservedWords") that NHibernate's keyword auto-import queries
        // at startup, so BuildSessionFactory() would throw. Turn it off.
        cfg.SetProperty("hbm2ddl.keywords", "none");

        var mapper = new ModelMapper();
        mapper.AddMapping<PolicyMap>();
        mapper.AddMapping<ClaimMap>();
        mapper.AddMapping<PayoutMap>();
        cfg.AddMapping(mapper.CompileMappingForAllExplicitlyAddedEntities());

        // Fresh schema on every startup -> the demo always looks the same.
        new SchemaExport(cfg).Create(useStdOut: false, execute: true);

        var factory = cfg.BuildSessionFactory();

        // WAL + busy-retry (Default Timeout above) let a second concurrent payout
        // wait for the first instead of erroring — which is what makes the race
        // condition observable rather than just throwing SQLITE_BUSY.
        using (var s = factory.OpenSession())
            s.CreateSQLQuery("PRAGMA journal_mode=WAL").UniqueResult();

        Seed(factory);
        SeedInternalUsers(factory);
        return factory;
    }

    /// <summary>
    /// Module ② — a sensitive table OUTSIDE the app's domain model (admin credential
    /// hashes). Created with raw SQL because the application's entities never map it;
    /// only an over-privileged (db_owner) login should be able to reach it.
    /// </summary>
    private static void SeedInternalUsers(ISessionFactory factory)
    {
        using var session = factory.OpenSession();
        var conn = session.Connection;   // raw ADO — robust for DDL on SQLite

        void Exec(string sql)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            cmd.ExecuteNonQuery();
        }

        Exec(@"CREATE TABLE internal_users (
                 id INTEGER PRIMARY KEY,
                 username TEXT, password_hash TEXT, role TEXT, mfa TEXT)");

        Exec(@"INSERT INTO internal_users (username, password_hash, role, mfa) VALUES
                 ('dba_admin',  '$2a$12$Kx9hq1Qe7r3uVbN2sLf0Oe8wZc5pYt1aR4mB6nD8gH0jK2lM4oPq', 'db_owner',  'disabled'),
                 ('svc_backup', '$2a$12$Qp7rT2yU4iO6pA8sD0fG1He3jK5lZ7xC9vB1nM3qW5eR7tY9uI1o', 'sysadmin',  'disabled'),
                 ('helpdesk',   '$2a$12$Zr2sE4tY6uI8oP0aS2dF3gH5jK7lX9cV1bN3mQ5wE7rT9yU1iO3p', 'operator',  'enabled')");
    }

    private static void Seed(ISessionFactory factory)
    {
        using var session = factory.OpenSession();
        using var tx = session.BeginTransaction();

        void Add(int customerId, string name, string number, string type, decimal premium, string status)
            => session.Save(new Policy
            {
                CustomerId = customerId,
                CustomerName = name,
                PolicyNumber = number,
                Type = type,
                Premium = premium,
                Status = status
            });

        // Customer 1 — "you", the logged-in lab user. You should ONLY ever see these two.
        Add(1, "Dana Cohen",       "CERT-2026-1001", "Auto",   2400m,  "Active");
        Add(1, "Dana Cohen",       "CERT-2026-1002", "Home",   1850m,  "Active");

        // Other customers — must remain invisible to customer 1.
        Add(2, "Yossi Levi",       "CERT-2026-2001", "Life",     980m, "Active");
        Add(2, "Yossi Levi",       "CERT-2026-2002", "Health",  3120m, "Active");
        Add(3, "Maya Friedman",    "CERT-2026-3001", "Auto",    2675m, "Lapsed");
        Add(3, "Maya Friedman",    "CERT-2026-3002", "Home",    2200m, "Active");
        Add(4, "Avi Stern (CEO)",  "CERT-2026-4001", "Life",   45000m, "Active"); // the juicy target

        // Approved claims — each must be paid out exactly once.
        void Claim(int cid, string name, string num, string desc, decimal amt)
            => session.Save(new Claim
            {
                CustomerId = cid, CustomerName = name, ClaimNumber = num,
                Description = desc, Amount = amt, Status = "Approved"
            });

        Claim(1, "Dana Cohen", "CLM-2026-0001", "Windshield replacement",                1200m);
        Claim(1, "Dana Cohen", "CLM-2026-0002", "Water damage - kitchen",               18500m);
        Claim(1, "Dana Cohen", "CLM-2026-0007", "Total loss - vehicle (comprehensive)", 250000m);
        Claim(2, "Yossi Levi", "CLM-2026-0103", "Storm damage - roof",                   32000m);

        tx.Commit();
    }
}
