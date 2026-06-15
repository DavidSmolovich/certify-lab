using CertifyLab.Domain;
using NHibernate;

namespace CertifyLab.Infrastructure;

public enum PayoutOutcome { Paid, AlreadyPaid, NotFound }

/// <summary>
/// Claim payouts — the business-logic race condition lives here.
/// A claim must be paid exactly once. The vulnerable method checks the status and
/// then acts on it as two separate steps (TOCTOU); the secure method makes the
/// state transition a single atomic operation.
/// </summary>
public class ClaimRepository
{
    private readonly ISessionFactory _factory;
    public ClaimRepository(ISessionFactory factory) => _factory = factory;

    public IList<Claim> ListForCustomer(int customerId)
    {
        using var session = _factory.OpenSession();
        return session.QueryOver<Claim>()
            .Where(c => c.CustomerId == customerId)
            .OrderBy(c => c.Id).Asc
            .List();
    }

    public IList<Payout> PayoutsFor(int claimId)
    {
        using var session = _factory.OpenSession();
        return session.QueryOver<Payout>()
            .Where(p => p.ClaimId == claimId)
            .List();
    }

    // ------------------------------------------------------------------
    // ❌ VULNERABLE — check-then-act (TOCTOU).
    // The status is checked, then (after a gap) acted upon. Two requests that
    // arrive together both read Status = "Approved", both pass the check, and
    // both write a payout => the claim is disbursed multiple times.
    // ------------------------------------------------------------------
    public PayoutOutcome PayoutVulnerable(int claimId)
    {
        using var session = _factory.OpenSession();

        var claim = session.Get<Claim>(claimId);
        if (claim == null) return PayoutOutcome.NotFound;
        if (claim.Status != "Approved") return PayoutOutcome.AlreadyPaid;   // TIME OF CHECK

        // Real handlers spend time here: document checks, fraud scoring, an
        // external bank call. That gap is the race window.
        System.Threading.Thread.Sleep(200);

        using var tx = session.BeginTransaction();                          // TIME OF USE
        claim.Status = "Paid";
        session.Update(claim);
        session.Save(new Payout
        {
            ClaimId = claim.Id,
            ClaimNumber = claim.ClaimNumber,
            Amount = claim.Amount,
            PaidAtUtc = DateTime.UtcNow
        });
        tx.Commit();
        return PayoutOutcome.Paid;
    }

    // ------------------------------------------------------------------
    // ✅ SECURE — atomic conditional state transition.
    // The UPDATE only matches rows that are still "Approved", so the database
    // itself guarantees exactly one winner under concurrency. Everyone else
    // updates 0 rows and is rejected. No double payout is possible.
    // ------------------------------------------------------------------
    public PayoutOutcome PayoutSecure(int claimId)
    {
        using var session = _factory.OpenSession();
        using var tx = session.BeginTransaction();

        var claim = session.Get<Claim>(claimId);
        if (claim == null) { tx.Rollback(); return PayoutOutcome.NotFound; }

        int affected = session.CreateQuery(
                "update Claim c set c.Status = 'Paid' " +
                "where c.Id = :id and c.Status = 'Approved'")
            .SetParameter("id", claimId)
            .ExecuteUpdate();

        if (affected != 1)
        {
            tx.Commit();
            return PayoutOutcome.AlreadyPaid;   // someone else already won the transition
        }

        session.Save(new Payout
        {
            ClaimId = claim.Id,
            ClaimNumber = claim.ClaimNumber,
            Amount = claim.Amount,
            PaidAtUtc = DateTime.UtcNow
        });
        tx.Commit();
        return PayoutOutcome.Paid;

        // Other valid fixes on their stack:
        //   • Optimistic concurrency: map a <version> column; the loser gets a
        //     StaleObjectStateException.
        //   • Pessimistic lock: session.Get<Claim>(id, LockMode.Upgrade) issues
        //     SELECT ... FOR UPDATE so the second caller blocks then sees "Paid".
        //   • A UNIQUE constraint on Payouts(ClaimId) as a last-line guarantee.
    }

    // Reset a claim to Approved and clear its payouts so the demo is repeatable.
    public void Reset(int claimId)
    {
        using var session = _factory.OpenSession();
        using var tx = session.BeginTransaction();
        session.CreateQuery("delete from Payout p where p.ClaimId = :id")
            .SetParameter("id", claimId).ExecuteUpdate();
        session.CreateQuery("update Claim c set c.Status = 'Approved' where c.Id = :id")
            .SetParameter("id", claimId).ExecuteUpdate();
        tx.Commit();
    }
}
