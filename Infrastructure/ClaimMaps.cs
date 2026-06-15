using CertifyLab.Domain;
using NHibernate.Mapping.ByCode;
using NHibernate.Mapping.ByCode.Conformist;

namespace CertifyLab.Infrastructure;

public class ClaimMap : ClassMapping<Claim>
{
    public ClaimMap()
    {
        Table("Claims");
        Id(x => x.Id, m => m.Generator(Generators.Identity));
        Property(x => x.ClaimNumber);
        Property(x => x.CustomerId);
        Property(x => x.CustomerName);
        Property(x => x.Description);
        Property(x => x.Amount);
        Property(x => x.Status);
    }
}

public class PayoutMap : ClassMapping<Payout>
{
    public PayoutMap()
    {
        Table("Payouts");
        Id(x => x.Id, m => m.Generator(Generators.Identity));
        Property(x => x.ClaimId);
        Property(x => x.ClaimNumber);
        Property(x => x.Amount);
        Property(x => x.PaidAtUtc);
    }
}
