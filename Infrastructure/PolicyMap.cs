using CertifyLab.Domain;
using NHibernate.Mapping.ByCode;
using NHibernate.Mapping.ByCode.Conformist;

namespace CertifyLab.Infrastructure;

/// <summary>NHibernate mapping-by-code for <see cref="Policy"/> -> table "Policies".</summary>
public class PolicyMap : ClassMapping<Policy>
{
    public PolicyMap()
    {
        Table("Policies");
        Id(x => x.Id, m => m.Generator(Generators.Identity));
        Property(x => x.CustomerId);
        Property(x => x.CustomerName);
        Property(x => x.PolicyNumber);
        Property(x => x.Type);
        Property(x => x.Premium);
        Property(x => x.Status);
    }
}
