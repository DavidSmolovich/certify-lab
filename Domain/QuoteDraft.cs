namespace CertifyLab.Domain;

/// <summary>
/// A saved insurance-quote draft that a customer can export and re-import later.
/// This is the *intended* shape of an imported document — plain data, no behaviour.
/// The secure endpoint binds incoming JSON straight into this concrete type.
/// </summary>
public class QuoteDraft
{
    public string ApplicantName { get; set; }
    public string Product { get; set; }        // Auto | Home | Life | Health
    public decimal CoverageAmount { get; set; }
    public string Notes { get; set; }
}
