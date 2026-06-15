using NHibernate.Driver;

namespace CertifyLab.Infrastructure;

/// <summary>
/// NHibernate driver for the Microsoft.Data.Sqlite ADO.NET provider.
/// NHibernate 5.x ships SQLite20Driver (System.Data.SQLite, which needs native
/// SQLite.Interop libs) but not one for Microsoft.Data.Sqlite — which is pure
/// managed (SQLitePCLRaw) and works on Linux/Windows/macOS without native setup.
/// This small reflection-based driver wires it up.
/// </summary>
public class MicrosoftDataSqliteDriver : ReflectionBasedDriver
{
    public MicrosoftDataSqliteDriver()
        : base(
            "Microsoft.Data.Sqlite",
            "Microsoft.Data.Sqlite.SqliteConnection",
            "Microsoft.Data.Sqlite.SqliteCommand")
    {
    }

    public override bool UseNamedPrefixInSql => true;
    public override bool UseNamedPrefixInParameter => true;
    public override string NamedPrefix => "@";
    public override bool SupportsMultipleOpenReaders => false;
}
