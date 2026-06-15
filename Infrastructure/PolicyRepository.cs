using CertifyLab.Domain;
using NHibernate;

namespace CertifyLab.Infrastructure;

/// <summary>
/// Data access for policies. This is the heart of the lab: two implementations of
/// the SAME query — one vulnerable to HQL injection, one safe.
/// </summary>
public class PolicyRepository
{
    private readonly ISessionFactory _factory;

    public PolicyRepository(ISessionFactory factory) => _factory = factory;

    // ------------------------------------------------------------------
    // ❌ VULNERABLE
    // The 'type' filter is concatenated straight into the HQL string.
    // 'customerId' is trusted (it comes from the JWT, not the request),
    // but 'type' is attacker-controlled => classic HQL injection.
    //
    //   type = "x' OR '1'='1"
    //   => "from Policy p where p.CustomerId = 1 and p.Type = 'x' OR '1'='1'"
    //   AND binds tighter than OR, so the whole predicate is always true
    //   and EVERY customer's policies come back.
    // ------------------------------------------------------------------
    public IList<Policy> FindByTypeVulnerable(int customerId, string type)
    {
        using var session = _factory.OpenSession();

        var hql = "from Policy p where p.CustomerId = " + customerId +
                  " and p.Type = '" + type + "'";

        return session.CreateQuery(hql).List<Policy>();
    }

    // ------------------------------------------------------------------
    // ✅ SECURE
    // 'type' is bound as a named parameter; NHibernate sends it as data,
    // never as query text. The same payload is now treated literally
    // (it simply matches no policy), so the per-customer scope holds.
    // ------------------------------------------------------------------
    public IList<Policy> FindByTypeSecure(int customerId, string type)
    {
        using var session = _factory.OpenSession();

        return session
            .CreateQuery("from Policy p where p.CustomerId = :cid and p.Type = :type")
            .SetParameter("cid", customerId)
            .SetParameter("type", type)
            .List<Policy>();

        // Even safer — no query string at all (compile-checked):
        // return session.QueryOver<Policy>()
        //     .Where(p => p.CustomerId == customerId && p.Type == type)
        //     .List();
    }
}
