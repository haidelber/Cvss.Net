using System;
using System.Collections.Generic;
using Cvss.Net.Builder;
using Cvss.Net;
using Cvss.Net.Enums;
using Xunit.Abstractions;

namespace Cvss.Net.Test
{
    public class CvssV3TestData
    {
        protected readonly ITestOutputHelper Output;

        public CvssV3TestData(ITestOutputHelper output)
        {
            this.Output = output;
        }


        public static IEnumerable<object[]> ValidTestData => new[]
        {
            new object[]{Valid44Base, 4.4, QualitativeSeverityRating.Medium, 4.4, QualitativeSeverityRating.Medium, 4.4,QualitativeSeverityRating.Medium },
            new object[]{Valid41Temp, 4.4, QualitativeSeverityRating.Medium, 4.1, QualitativeSeverityRating.Medium, 4.1, QualitativeSeverityRating.Medium},
            new object[]{Valid34Env, 4.4, QualitativeSeverityRating.Medium, 4.1, QualitativeSeverityRating.Medium, 3.4, QualitativeSeverityRating.Low},
            new object[]{ValidNotPreferedOrder, 4.4, QualitativeSeverityRating.Medium, 4.4, QualitativeSeverityRating.Medium, 4.4, QualitativeSeverityRating.Medium},
            new object[]{ ValidLong, 10, QualitativeSeverityRating.Critical, 8.1, QualitativeSeverityRating.High, 6.2, QualitativeSeverityRating.Medium},
            new object[]{WorkingBuilder, 4.8, QualitativeSeverityRating.Medium, 4.8, QualitativeSeverityRating.Medium, 4.8, QualitativeSeverityRating.Medium }
        };

        public static CvssV3 Valid44Base =>
            new CvssV3("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L");
        public static CvssV3 Valid41Temp =>
            new CvssV3("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:P/RL:W/RC:C");
        public static CvssV3 Valid34Env =>
            new CvssV3("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:P/RL:W/RC:C/MS:U");
        public static CvssV3 ValidNotPreferedOrder =>
            new CvssV3("CVSS:3.0/C:L/I:L/A:L/AV:P/AC:H/PR:L/UI:R/S:C");
        public static CvssV3 ValidLong =>
            new CvssV3("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:L/MAV:L");


        public static CvssV3 InvalidWrongMs =>
            new CvssV3("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:P/RL:W/RC:C/MS:Z");
        public static CvssV3 InvalidMissingRequired =>
            new CvssV3("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L");

        public static CvssV3 WorkingBuilder => CvssBuilder.NewV3().AttackComplexity(AttackComplexity.High).AttackVector(AttackVector.Physical)
            .PrivilegesRequired(PrivilegesRequired.None).UserInteraction(UserInteraction.None)
            .Scope(Scope.Unchanged).ConfidentialityImpact(Impact.High).IntegrityImpact(Impact.Low)
            .AvailabilityImpact(Impact.None).Build();
        public static CvssV3 MissingBuilder => CvssBuilder.NewV3().AttackComplexity(AttackComplexity.High).AttackVector(AttackVector.Physical)
            .PrivilegesRequired(PrivilegesRequired.None).UserInteraction(UserInteraction.None)
            .Scope(Scope.Unchanged).ConfidentialityImpact(Impact.High).Build();
    }
}