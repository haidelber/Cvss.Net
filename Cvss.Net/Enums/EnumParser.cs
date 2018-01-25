using System;

namespace Cvss.Net.Enums
{
    internal static class EnumParser
    {
        public static AttackVector AttackVector(string value, string param = "AV")
        {
            var normVal = value.ToUpperInvariant();
            switch (normVal)
            {
                case "N": return Enums.AttackVector.Network;
                case "A": return Enums.AttackVector.Adjacent;
                case "L": return Enums.AttackVector.Local;
                case "P": return Enums.AttackVector.Physical;
                default: throw new ArgumentOutOfRangeException(param);
            }
        }

        public static AttackComplexity AttackComplexity(string value, string param = "AC")
        {
            var normVal = value.ToUpperInvariant();
            switch (normVal)
            {
                case "L": return Enums.AttackComplexity.Low;
                case "H": return Enums.AttackComplexity.High;
                default: throw new ArgumentOutOfRangeException(param);
            }
        }

        public static PrivilegesRequired PrivilegesRequired(string value, string param = "PR")
        {
            var normVal = value.ToUpperInvariant();
            switch (normVal)
            {
                case "N": return Enums.PrivilegesRequired.None;
                case "L": return Enums.PrivilegesRequired.Low;
                case "H": return Enums.PrivilegesRequired.High;
                default: throw new ArgumentOutOfRangeException(param);
            }
        }

        public static UserInteraction UserInteraction(string value, string param = "UI")
        {
            var normVal = value.ToUpperInvariant();
            switch (normVal)
            {
                case "N": return Enums.UserInteraction.None;
                case "R": return Enums.UserInteraction.Required;
                default: throw new ArgumentOutOfRangeException(param);
            }
        }

        public static Scope Scope(string value, string param = "S")
        {
            var normVal = value.ToUpperInvariant();
            switch (normVal)
            {
                case "U": return Enums.Scope.Unchanged;
                case "C": return Enums.Scope.Changed;
                default: throw new ArgumentOutOfRangeException(param);
            }
        }

        public static Impact Impact(string value, string param)
        {
            var normVal = value.ToUpperInvariant();
            switch (normVal)
            {
                case "H": return Enums.Impact.High;
                case "L": return Enums.Impact.Low;
                case "N": return Enums.Impact.None;
                default: throw new ArgumentOutOfRangeException(param);
            }
        }

        public static ExploitCodeMaturity? ExploitCodeMaturity(string value, string param = "E")
        {
            var normVal = value.ToUpperInvariant();
            switch (normVal)
            {
                case "X": return null;
                case "H": return Enums.ExploitCodeMaturity.High;
                case "F": return Enums.ExploitCodeMaturity.Functional;
                case "P": return Enums.ExploitCodeMaturity.ProofOfConcept;
                case "U": return Enums.ExploitCodeMaturity.Unproven;
                default: throw new ArgumentOutOfRangeException(param);
            }
        }

        public static RemediationLevel? RemediationLevel(string value, string param = "RL")
        {
            var normVal = value.ToUpperInvariant();
            switch (normVal)
            {
                case "X": return null;
                case "U": return Enums.RemediationLevel.Unavailable;
                case "W": return Enums.RemediationLevel.Workaround;
                case "T": return Enums.RemediationLevel.TemporaryFix;
                case "O": return Enums.RemediationLevel.OfficialFix;
                default: throw new ArgumentOutOfRangeException(param);
            }
        }

        public static ReportConfidence? ReportConfidence(string value, string param = "RC")
        {
            var normVal = value.ToUpperInvariant();
            switch (normVal)
            {
                case "X": return null;
                case "C": return Enums.ReportConfidence.Confirmed;
                case "R": return Enums.ReportConfidence.Reasonable;
                case "U": return Enums.ReportConfidence.Unknown;
                default: throw new ArgumentOutOfRangeException(param);
            }
        }

        public static SecurityRequirement? SecurityRequirement(string value, string param)
        {
            var normVal = value.ToUpperInvariant();
            switch (normVal)
            {
                case "X": return null;
                case "H": return Enums.SecurityRequirement.High;
                case "M": return Enums.SecurityRequirement.Medium;
                case "L": return Enums.SecurityRequirement.Low;
                default: throw new ArgumentOutOfRangeException(param);
            }
        }

        public static T? Modified<T>(string value, string param, Func<string, string, T> func) where T : struct
        {
            var normVal = value.ToUpperInvariant();
            if (normVal == "X")
            {
                return null;
            }
            return func(normVal, param);
        }
    }
}
