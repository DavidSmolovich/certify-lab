using System.Net;
using System.Net.Sockets;

namespace CertifyLab.Infrastructure;

/// <summary>
/// A tiny, offline "virtual cloud" for the SSRF demo (Module ④).
///
/// The actual content retrieval is SIMULATED so the lab needs no internet and no
/// Azure — but the security-relevant code (the v2 destination validation) is REAL:
/// the same allow-list + private/link-local IP checks you would ship in production.
/// </summary>
public static class MockAzure
{
    // The real Azure Instance Metadata Service address. On a real Azure VM this
    // link-local IP responds; here we simulate its response. v2 blocks it by IP class.
    public const string ImdsHost = "169.254.169.254";
    public const string DocsHost = "docs.certify-insurer.com"; // the ONE allowed external host

    // ── SIMULATED fetch: what a real GET to this URL would return, offline ──────
    public static (int status, string body) SimulateGet(Uri u)
    {
        // 1) The cloud metadata service — the SSRF jackpot.
        if (u.Host == ImdsHost && u.AbsolutePath.Contains("/oauth2/token"))
        {
            var resource = QueryParam(u, "resource") ?? "https://vault.azure.net";
            var json =
                "{\n" +
                $"  \"access_token\": \"{LabSecrets.ManagedIdentityToken}\",\n" +
                "  \"token_type\": \"Bearer\",\n" +
                $"  \"resource\": \"{resource}\",\n" +
                "  \"expires_in\": \"86400\",\n" +
                "  \"_note\": \"SIMULATED Azure IMDS (169.254.169.254) — no real cloud in this lab\"\n" +
                "}";
            return (200, json);
        }

        // 2) A legitimate, allow-listed document host (also simulated).
        if (u.Host.Equals(DocsHost, StringComparison.OrdinalIgnoreCase))
            return (200, $"%PDF-1.4 (simulated policy document at {u.AbsolutePath})");

        // 3) Anything else in this offline lab is "unreachable".
        return (502, $"simulated fetch: '{u.Host}' is not reachable in the offline lab");
    }

    // ── Mock Key Vault: hands over the secret ONLY for a valid bearer token ─────
    public static (bool ok, string value) KeyVaultGetSecret(string bearerToken) =>
        bearerToken == LabSecrets.ManagedIdentityToken
            ? (true, LabSecrets.ProdConnectionString)
            : (false, null);

    // ── REAL SSRF-safe destination validation (used by the v2 fetch endpoint) ──
    private static readonly HashSet<string> AllowedHosts =
        new(StringComparer.OrdinalIgnoreCase) { DocsHost };

    public static bool IsAllowedDestination(Uri u, out string reason)
    {
        if (u.Scheme != Uri.UriSchemeHttps && u.Scheme != Uri.UriSchemeHttp)
        { reason = $"scheme '{u.Scheme}' is not allowed"; return false; }

        if (!AllowedHosts.Contains(u.Host))
        { reason = $"host '{u.Host}' is not on the allow-list"; return false; }

        foreach (var ip in Resolve(u.Host))
            if (IsPrivateOrLinkLocal(ip))
            { reason = $"'{u.Host}' resolves to internal address {ip}"; return false; }

        reason = null;
        return true;
    }

    private static IEnumerable<IPAddress> Resolve(string host)
    {
        if (IPAddress.TryParse(host, out var literal)) return new[] { literal };
        try { return Dns.GetHostAddresses(host); } catch { return Array.Empty<IPAddress>(); }
    }

    /// <summary>True if the URL's host points at a loopback / private / link-local address.</summary>
    public static bool TargetsInternal(Uri u)
    {
        foreach (var ip in Resolve(u.Host))
            if (IsPrivateOrLinkLocal(ip)) return true;
        return false;
    }

    /// <summary>Blocks loopback, RFC-1918 private ranges, and 169.254.0.0/16 link-local (Azure IMDS).</summary>
    public static bool IsPrivateOrLinkLocal(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)   // link-local — includes Azure IMDS
                || b[0] == 127;
        }
        return ip.IsIPv6LinkLocal || IPAddress.IPv6Loopback.Equals(ip);
    }

    private static string QueryParam(Uri u, string key)
    {
        foreach (var part in u.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = part.Split('=', 2);
            if (kv.Length == 2 && Uri.UnescapeDataString(kv[0]).Equals(key, StringComparison.OrdinalIgnoreCase))
                return Uri.UnescapeDataString(kv[1]);
        }
        return null;
    }
}
