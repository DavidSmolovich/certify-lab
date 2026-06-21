namespace CertifyLab.Infrastructure;

/// <summary>
/// One deliberately-FAKE production secret, reused across every Session 5 demo so
/// they tell a single story:
///   • Module ① — it leaks in the verbose server error,
///   • Module ② — the db_owner login can reach the table it protects,
///   • Module ③ — it sits in committed appsettings.json (vulnerable) vs Key Vault (secure),
///   • Module ④ — it is exfiltrated by the SSRF → IMDS → Key Vault chain.
/// The lab never connects to a real SQL Server, Key Vault, or Azure.
/// </summary>
public static class LabSecrets
{
    // Note the insecure params too (Encrypt=False, TrustServerCertificate=True) — see Module ② slides.
    public const string ProdConnectionString =
        "Server=sql-prod.certify.local,1433;Database=Certify;User Id=svc_certify;" +
        "Password=S3cr3t-P@ss-2026!;Encrypt=False;TrustServerCertificate=True";

    public const string KeyVaultSecretUri =
        "https://kv-certify.vault.azure.net/secrets/Certify-Conn";

    public const string KeyVaultReference =
        "@Microsoft.KeyVault(SecretUri=https://kv-certify.vault.azure.net/secrets/Certify-Conn)";

    // The access token a real Azure IMDS would mint for the VM's Managed Identity.
    public const string ManagedIdentityToken =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9." +
        "FAKE.managed-identity-access-token.for-the-lab-only.sig";

    /// <summary>Mask a connection string's password for the SECURE responses.</summary>
    public static string Mask(string connectionString) =>
        System.Text.RegularExpressions.Regex.Replace(
            connectionString, @"(?i)(Password=)[^;]*", "$1********");
}
