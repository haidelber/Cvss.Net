using System;
using Cvss.Net.Enums;

namespace Cvss.Net
{
    public interface ICvss
    {
        string VectorPrefix { get; }
        decimal BaseScore { get; }
        QualitativeSeverityRating QualitativeBaseScore { get; }
        decimal TemporalScore { get; }
        QualitativeSeverityRating QualitativeTemporalScore { get; }
        decimal EnvironmentalScore { get; }
        QualitativeSeverityRating QualitativeEnvironmentalScore { get; }
        string Vector { get; }
    }
}
