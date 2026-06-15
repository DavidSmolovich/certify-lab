namespace CertifyLab.Domain;

/// <summary>
/// An insurance policy belonging to a customer.
/// NHibernate requires members to be <c>virtual</c> (for lazy-loading proxies)
/// and the class to have a parameterless constructor (the implicit one is fine).
/// </summary>
public class Policy
{
    public virtual int Id { get; set; }

    /// <summary>Owner of the policy. In the API this is taken from the JWT, never from input.</summary>
    public virtual int CustomerId { get; set; }

    public virtual string CustomerName { get; set; }
    public virtual string PolicyNumber { get; set; }

    /// <summary>Auto | Home | Life | Health — the field the customer filters on.</summary>
    public virtual string Type { get; set; }

    public virtual decimal Premium { get; set; }

    /// <summary>Active | Lapsed</summary>
    public virtual string Status { get; set; }
}
