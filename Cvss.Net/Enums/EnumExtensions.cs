using System;

namespace Cvss.Net.Enums
{
    internal static class EnumExtensions
    {
        public static double NumericValue(this AttackVector attackVector)
        {
            switch (attackVector)
            {
                case AttackVector.Network: return 0.85;
                case AttackVector.Adjacent: return 0.62;
                case AttackVector.Local: return 0.55;
                case AttackVector.Physical: return 0.2;
                default:
                    throw new ArgumentOutOfRangeException(nameof(attackVector), attackVector, null);
            }
        }

        public static string StringValue(this AttackVector attackVector)
        {
            switch (attackVector)
            {
                case AttackVector.Network: return "N";
                case AttackVector.Adjacent: return "A";
                case AttackVector.Local: return "L";
                case AttackVector.Physical: return "P";
                default:
                    throw new ArgumentOutOfRangeException(nameof(attackVector), attackVector, null);
            }
        }

        public static double NumericValue(this AttackComplexity attackComplexity)
        {
            switch (attackComplexity)
            {
                case AttackComplexity.Low: return 0.77;
                case AttackComplexity.High: return 0.44;
                default:
                    throw new ArgumentOutOfRangeException(nameof(attackComplexity), attackComplexity, null);
            }
        }

        public static string StringValue(this AttackComplexity attackComplexity)
        {
            switch (attackComplexity)
            {
                case AttackComplexity.Low: return "L";
                case AttackComplexity.High: return "H";
                default:
                    throw new ArgumentOutOfRangeException(nameof(attackComplexity), attackComplexity, null);
            }
        }

        public static double NumericValue(this PrivilegesRequired privilegesRequired, Scope scope)
        {
            switch (privilegesRequired)
            {
                case PrivilegesRequired.None: return 0.85;
                case PrivilegesRequired.Low:
                    return (scope == Scope.Changed)
                        ? 0.68
                        : 0.62;
                case PrivilegesRequired.High:
                    return (scope == Scope.Changed)
                        ? 0.50
                        : 0.27;
                default:
                    throw new ArgumentOutOfRangeException(nameof(privilegesRequired), privilegesRequired, null);
            }
        }

        public static string StringValue(this PrivilegesRequired privilegesRequired)
        {
            switch (privilegesRequired)
            {
                case PrivilegesRequired.None: return "N";
                case PrivilegesRequired.Low: return "L";
                case PrivilegesRequired.High: return "H";
                default:
                    throw new ArgumentOutOfRangeException(nameof(privilegesRequired), privilegesRequired, null);
            }
        }

        public static double NumericValue(this UserInteraction userInteraction)
        {
            switch (userInteraction)
            {
                case UserInteraction.None: return 0.85;
                case UserInteraction.Required: return 0.62;
                default:
                    throw new ArgumentOutOfRangeException(nameof(userInteraction), userInteraction, null);
            }
        }

        public static string StringValue(this UserInteraction userInteraction)
        {
            switch (userInteraction)
            {
                case UserInteraction.None: return "N";
                case UserInteraction.Required: return "R";
                default:
                    throw new ArgumentOutOfRangeException(nameof(userInteraction), userInteraction, null);
            }
        }

        public static string StringValue(this Scope scope)
        {
            switch (scope)
            {
                case Scope.Unchanged: return "U";
                case Scope.Changed: return "C";
                default:
                    throw new ArgumentOutOfRangeException(nameof(scope), scope, null);
            }
        }

        public static double NumericValue(this Impact impact)
        {
            switch (impact)
            {
                case Impact.High: return 0.56;
                case Impact.Low: return 0.22;
                case Impact.None: return 0;
                default:
                    throw new ArgumentOutOfRangeException(nameof(impact), impact, null);
            }
        }

        public static string StringValue(this Impact impact)
        {
            switch (impact)
            {
                case Impact.High: return "H";
                case Impact.Low: return "L";
                case Impact.None: return "N";
                default:
                    throw new ArgumentOutOfRangeException(nameof(impact), impact, null);
            }
        }

        public static double NumericValue(this ExploitCodeMaturity? exploitCodeMaturity)
        {
            if (!exploitCodeMaturity.HasValue)
                return 1;
            switch (exploitCodeMaturity.Value)
            {
                case ExploitCodeMaturity.High: return 1;
                case ExploitCodeMaturity.Functional: return 0.97;
                case ExploitCodeMaturity.ProofOfConcept: return 0.94;
                case ExploitCodeMaturity.Unproven: return 0.91;
                default:
                    throw new ArgumentOutOfRangeException(nameof(exploitCodeMaturity), exploitCodeMaturity, null);
            }
        }

        public static string StringValue(this ExploitCodeMaturity exploitCodeMaturity)
        {
            switch (exploitCodeMaturity)
            {
                case ExploitCodeMaturity.High: return "H";
                case ExploitCodeMaturity.Functional: return "F";
                case ExploitCodeMaturity.ProofOfConcept: return "P";
                case ExploitCodeMaturity.Unproven: return "U";
                default:
                    throw new ArgumentOutOfRangeException(nameof(exploitCodeMaturity), exploitCodeMaturity, null);
            }
        }

        public static double NumericValue(this RemediationLevel? remediationLevel)
        {
            if (!remediationLevel.HasValue)
                return 1;
            switch (remediationLevel.Value)
            {
                case RemediationLevel.Unavailable: return 1;
                case RemediationLevel.Workaround: return 0.97;
                case RemediationLevel.TemporaryFix: return 0.96;
                case RemediationLevel.OfficialFix: return 0.95;
                default:
                    throw new ArgumentOutOfRangeException(nameof(remediationLevel), remediationLevel, null);
            }
        }

        public static string StringValue(this RemediationLevel remediationLevel)
        {
            switch (remediationLevel)
            {
                case RemediationLevel.Unavailable: return "U";
                case RemediationLevel.Workaround: return "W";
                case RemediationLevel.TemporaryFix: return "T";
                case RemediationLevel.OfficialFix: return "O";
                default:
                    throw new ArgumentOutOfRangeException(nameof(remediationLevel), remediationLevel, null);
            }
        }

        public static double NumericValue(this ReportConfidence? reportConfidence)
        {
            if (!reportConfidence.HasValue)
                return 1;
            switch (reportConfidence.Value)
            {
                case ReportConfidence.Confirmed: return 1;
                case ReportConfidence.Reasonable: return 0.96;
                case ReportConfidence.Unknown: return 0.92;
                default:
                    throw new ArgumentOutOfRangeException(nameof(reportConfidence), reportConfidence, null);
            }
        }

        public static string StringValue(this ReportConfidence reportConfidence)
        {
            switch (reportConfidence)
            {
                case ReportConfidence.Confirmed: return "C";
                case ReportConfidence.Reasonable: return "R";
                case ReportConfidence.Unknown: return "U";
                default:
                    throw new ArgumentOutOfRangeException(nameof(reportConfidence), reportConfidence, null);
            }
        }

        public static double NumericValue(this SecurityRequirement? securityRequirement)
        {
            if (!securityRequirement.HasValue)
                return 1;
            switch (securityRequirement.Value)
            {
                case SecurityRequirement.High: return 1.5;
                case SecurityRequirement.Medium: return 1;
                case SecurityRequirement.Low: return 0.5;
                default:
                    throw new ArgumentOutOfRangeException(nameof(securityRequirement), securityRequirement, null);
            }
        }

        public static string StringValue(this SecurityRequirement securityRequirement)
        {
            switch (securityRequirement)
            {
                case SecurityRequirement.High: return "H";
                case SecurityRequirement.Medium: return "M";
                case SecurityRequirement.Low: return "L";
                default:
                    throw new ArgumentOutOfRangeException(nameof(securityRequirement), securityRequirement, null);
            }
        }

        public static double Modified<T>(this T? value, T defaultValue, Func<T, double> func) where T : struct
        {
            if (value == null)
            {
                return func(defaultValue);
            }
            return func(value.Value);
        }
    }
}
