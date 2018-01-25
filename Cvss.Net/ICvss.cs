using System;
using Cvss.Net.Enums;

namespace Cvss.Net
{
    public interface ICvss
    {
        string VectorPrefix { get; }
        double BaseScore { get; }
        QualitativeSeverityRating QualitativeBaseScore { get; }
        double TemporalScore { get; }
        QualitativeSeverityRating QualitativeTemporalScore { get; }
        double EnvironmentalScore { get; }
        QualitativeSeverityRating QualitativeEnvironmentalScore { get; }
        string Vector { get; }
    }
}
