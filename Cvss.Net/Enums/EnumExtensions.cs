using System;

namespace Cvss.Net.Enums
{
    internal static class EnumExtensions
    {
        public static decimal Value(this AttackVector attackVector)
        {
            switch (attackVector)
            {
                case AttackVector.Network: return 0.85M;
                case AttackVector.Adjacent: return 0.62M;
                case AttackVector.Local: return 0.55M;
                case AttackVector.Physical: return 0.2M;
                default:
                    throw new ArgumentOutOfRangeException(nameof(attackVector), attackVector, null);
            }
        }

        public static decimal Value(this AttackComplexity attackComplexity)
        {
            switch (attackComplexity)
            {
                case AttackComplexity.Low: return 0.77M;
                case AttackComplexity.High: return 0.44M;
                default:
                    throw new ArgumentOutOfRangeException(nameof(attackComplexity), attackComplexity, null);
            }
        }

        public static decimal Value(this PrivilegesRequired privilegesRequired, Scope scope, Scope? modifiedScope = null)
        {
            switch (privilegesRequired)
            {
                case PrivilegesRequired.None: return 0.85M;
                case PrivilegesRequired.Low:
                    return (scope == Scope.Changed || modifiedScope.HasValue && modifiedScope.Value == Scope.Changed)
                        ? 0.68M
                        : 0.62M;
                case PrivilegesRequired.High:
                    return (scope == Scope.Changed || modifiedScope.HasValue && modifiedScope.Value == Scope.Changed)
                        ? 0.50M
                        : 0.27M;
                default:
                    throw new ArgumentOutOfRangeException(nameof(privilegesRequired), privilegesRequired, null);
            }
        }

        public static decimal Value(this UserInteraction userInteraction)
        {
            switch (userInteraction)
            {
                case UserInteraction.None: return 0.85M;
                case UserInteraction.Required: return 0.62M;
                default:
                    throw new ArgumentOutOfRangeException(nameof(userInteraction), userInteraction, null);
            }
        }

        public static decimal Value(this Impact impact)
        {
            switch (impact)
            {
                case Impact.High: return 0.56M;
                case Impact.Low: return 0.22M;
                case Impact.None: return 0M;
                default:
                    throw new ArgumentOutOfRangeException(nameof(impact), impact, null);
            }
        }

        public static decimal Value(this ExploitCodeMaturity exploitCodeMaturity)
        {
            switch (exploitCodeMaturity)
            {
                case ExploitCodeMaturity.NotDefined: return 1;
                case ExploitCodeMaturity.High: return 1;
                case ExploitCodeMaturity.Functional: return 0.97M;
                case ExploitCodeMaturity.ProofOfConcept: return 0.94M;
                case ExploitCodeMaturity.Unproven: return 0.91M;
                default:
                    throw new ArgumentOutOfRangeException(nameof(exploitCodeMaturity), exploitCodeMaturity, null);
            }
        }

        public static decimal Value(this RemediationLevel remediationLevel)
        {
            switch (remediationLevel)
            {
                case RemediationLevel.NotDefined: return 1;
                case RemediationLevel.Unavailable: return 1;
                case RemediationLevel.Workaround: return 0.97M;
                case RemediationLevel.TemporaryFix: return 0.96M;
                case RemediationLevel.OfficialFix: return 0.95M;
                default:
                    throw new ArgumentOutOfRangeException(nameof(remediationLevel), remediationLevel, null);
            }
        }

        public static decimal Value(this ReportConfidence reportConfidence)
        {
            switch (reportConfidence)
            {
                case ReportConfidence.NotDefined: return 1;
                case ReportConfidence.Confirmed: return 1;
                case ReportConfidence.Reasonable: return 0.96M;
                case ReportConfidence.Unknown: return 0.92M;
                default:
                    throw new ArgumentOutOfRangeException(nameof(reportConfidence), reportConfidence, null);
            }
        }

        public static decimal Value(this SecurityRequirement securityRequirement)
        {
            switch (securityRequirement)
            {
                case SecurityRequirement.NotDefined: return 1;
                case SecurityRequirement.High: return 1.5M;
                case SecurityRequirement.Medium: return 1;
                case SecurityRequirement.Low: return 0.5M;
                default:
                    throw new ArgumentOutOfRangeException(nameof(securityRequirement), securityRequirement, null);
            }
        }
    }
}
