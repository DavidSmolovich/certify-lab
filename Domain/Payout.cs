namespace CertifyLab.Domain;

/// <summary>
/// A money-out ledger entry. One row = one disbursement. If a single claim ends up
/// with more than one Payout row, the company paid the same claim twice (the bug).
/// </summary>
public class Payout
{
    public virtual int Id { get; set; }
    public virtual int ClaimId { get; set; }
    public virtual string ClaimNumber { get; set; }
    public virtual decimal Amount { get; set; }
    public virtual DateTime PaidAtUtc { get; set; }
}
