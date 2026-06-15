namespace CertifyLab.Domain;

/// <summary>
/// An approved insurance claim. It should be paid out exactly once:
/// Status goes Approved -> Paid, and that transition must happen atomically.
/// </summary>
public class Claim
{
    public virtual int Id { get; set; }
    public virtual string ClaimNumber { get; set; }
    public virtual int CustomerId { get; set; }
    public virtual string CustomerName { get; set; }
    public virtual string Description { get; set; }
    public virtual decimal Amount { get; set; }
    public virtual string Status { get; set; }   // Approved | Paid
}
