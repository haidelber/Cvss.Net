namespace Cvss.Net.Enums
{
    public enum AttackVector
    {
        Network,
        Adjacent,
        Local,
        Physical
    }

    public enum AttackComplexity
    {
        Low,
        High
    }

    public enum PrivilegesRequired
    {
        None,
        Low,
        High
    }

    public enum UserInteraction
    {
        None,
        Required
    }

    public enum Scope
    {
        Unchanged,
        Changed
    }
    /// <summary>
    /// ConfidentialityImpact
    /// IntegrityImpact
    /// AvailabilityImpact
    /// </summary>
    public enum Impact
    {
        High,
        Low,
        None
    }

    public enum ExploitCodeMaturity
    {
        High,
        Functional,
        ProofOfConcept,
        Unproven
    }

    public enum RemediationLevel
    {
        Unavailable,
        Workaround,
        TemporaryFix,
        OfficialFix
    }

    public enum ReportConfidence
    {
        Confirmed,
        Reasonable,
        Unknown
    }

    public enum QualitativeSeverityRating
    {
        None,
        Low,
        Medium,
        High,
        Critical
    }

    public enum SecurityRequirement
    {
        High,
        Medium,
        Low
    }

    public enum CvssVersion
    {
        V3
    }
}
