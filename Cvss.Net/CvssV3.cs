using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Cvss.Net.Enums;
using Cvss.Net.Extensions;

namespace Cvss.Net
{
    public class CvssV3 : ICvss
    {
        #region Base score properties
        public AttackVector AttackVector { get; internal set; }
        public AttackComplexity AttackComplexity { get; internal set; }
        public PrivilegesRequired PrivilegesRequired { get; internal set; }
        public UserInteraction UserInteraction { get; internal set; }
        public Scope Scope { get; internal set; }
        public Impact ConfidentialityImpact { get; internal set; }
        public Impact IntegrityImpact { get; internal set; }
        public Impact AvailabilityImpact { get; internal set; }
        #endregion

        #region Temporal score properties
        public ExploitCodeMaturity? ExploitCodeMaturity { get; internal set; }
        public RemediationLevel? RemediationLevel { get; internal set; }
        public ReportConfidence? ReportConfidence { get; internal set; }
        #endregion

        #region Environmental score properties
        public SecurityRequirement? ConfidentialityRequirement { get; internal set; }
        public SecurityRequirement? IntegrityRequirement { get; internal set; }
        public SecurityRequirement? AvailabilityRequirement { get; internal set; }

        public AttackVector? ModifiedAttackVector { get; internal set; }
        public AttackComplexity? ModifiedAttackComplexity { get; internal set; }
        public PrivilegesRequired? ModifiedPrivilegesRequired { get; internal set; }
        public UserInteraction? ModifiedUserInteraction { get; internal set; }
        public Scope? ModifiedScope { get; internal set; }
        public Impact? ModifiedConfidentialityImpact { get; internal set; }
        public Impact? ModifiedIntegrityImpact { get; internal set; }
        public Impact? ModifiedAvailabilityImpact { get; internal set; }
        #endregion

        #region Constructors

        internal CvssV3() { }

        internal CvssV3(CvssV3 other) : this(other.AttackVector, other.AttackComplexity, other.PrivilegesRequired,
            other.UserInteraction, other.Scope, other.ConfidentialityImpact, other.IntegrityImpact,
            other.AvailabilityImpact, other.ExploitCodeMaturity, other.RemediationLevel, other.ReportConfidence,
            other.ConfidentialityRequirement, other.IntegrityRequirement, other.AvailabilityRequirement, other.ModifiedAttackVector,
            other.ModifiedAttackComplexity, other.ModifiedPrivilegesRequired, other.ModifiedUserInteraction, other.ModifiedScope,
            other.ModifiedConfidentialityImpact, other.ModifiedIntegrityImpact, other.ModifiedAvailabilityImpact)
        { }

        public CvssV3(AttackVector attackVector, AttackComplexity attackComplexity, PrivilegesRequired privilegesRequired,
            UserInteraction userInteraction, Scope scope, Impact confidentialityImpact, Impact integrityImpact,
            Impact availabilityImpact, ExploitCodeMaturity? exploitCodeMaturity = default(ExploitCodeMaturity?),
            RemediationLevel? remediationLevel = default(RemediationLevel?), ReportConfidence? reportConfidence = default(ReportConfidence?),
            SecurityRequirement? confidentialityRequirement = default(SecurityRequirement?),
            SecurityRequirement? integrityRequirement = default(SecurityRequirement?),
            SecurityRequirement? availabilityRequirement = default(SecurityRequirement?),
            AttackVector? modifiedAttackVector = default(AttackVector?), AttackComplexity? modifiedAttackComplexity = default(AttackComplexity?),
            PrivilegesRequired? modifiedPrivilegesRequired = default(PrivilegesRequired?),
            UserInteraction? modifiedUserInteraction = default(UserInteraction?), Scope? modifiedScope = default(Scope?),
            Impact? modifiedConfidentialityImpact = default(Impact?), Impact? modifiedIntegrityImpact = default(Impact?),
            Impact? modifiedAvailabilityImpact = default(Impact?))
        {
            AttackVector = attackVector;
            AttackComplexity = attackComplexity;
            PrivilegesRequired = privilegesRequired;
            UserInteraction = userInteraction;
            Scope = scope;
            ConfidentialityImpact = confidentialityImpact;
            IntegrityImpact = integrityImpact;
            AvailabilityImpact = availabilityImpact;
            ExploitCodeMaturity = exploitCodeMaturity;
            RemediationLevel = remediationLevel;
            ReportConfidence = reportConfidence;
            ConfidentialityRequirement = confidentialityRequirement;
            IntegrityRequirement = integrityRequirement;
            AvailabilityRequirement = availabilityRequirement;
            ModifiedAttackVector = modifiedAttackVector;
            ModifiedAttackComplexity = modifiedAttackComplexity;
            ModifiedPrivilegesRequired = modifiedPrivilegesRequired;
            ModifiedUserInteraction = modifiedUserInteraction;
            ModifiedScope = modifiedScope;
            ModifiedConfidentialityImpact = modifiedConfidentialityImpact;
            ModifiedIntegrityImpact = modifiedIntegrityImpact;
            ModifiedAvailabilityImpact = modifiedAvailabilityImpact;

            CalculateScores();
        }

        public CvssV3(string vector)
        {
            vector = vector.Trim('/', ' ');
            if (!vector.StartsWith(VectorPrefix))
            {
                throw new ArgumentException($"Vector must begin with prefix \"{VectorPrefix}\"", nameof(vector));
            }

            var metricParts = vector.Split('/').Skip(1);
            var metricRegex = new Regex("[A-Za-z]+:[A-Za-z]{1}");
            var parsedMetrics = new List<string>();
            foreach (var metricVector in metricParts)
            {
                if (!metricRegex.IsMatch(metricVector))
                {
                    throw new ArgumentException($"Invalid vector-part \"{metricVector}\"", nameof(vector));
                }

                var kv = metricVector.Split(':');
                var value = kv[1];
                var key = kv[0].ToUpperInvariant();
                parsedMetrics.Add(key);
                switch (key)
                {
                    case "AV": AttackVector = EnumParser.AttackVector(value); break;
                    case "AC": AttackComplexity = EnumParser.AttackComplexity(value); break;
                    case "PR": PrivilegesRequired = EnumParser.PrivilegesRequired(value); break;
                    case "UI": UserInteraction = EnumParser.UserInteraction(value); break;
                    case "S": Scope = EnumParser.Scope(value); break;
                    case "C": ConfidentialityImpact = EnumParser.Impact(value, "C"); break;
                    case "I": IntegrityImpact = EnumParser.Impact(value, "I"); break;
                    case "A": AvailabilityImpact = EnumParser.Impact(value, "A"); break;
                    case "E": ExploitCodeMaturity = EnumParser.ExploitCodeMaturity(value); break;
                    case "RL": RemediationLevel = EnumParser.RemediationLevel(value); break;
                    case "RC": ReportConfidence = EnumParser.ReportConfidence(value); break;
                    case "CR": ConfidentialityRequirement = EnumParser.SecurityRequirement(value, "CR"); break;
                    case "IR": IntegrityRequirement = EnumParser.SecurityRequirement(value, "IR"); break;
                    case "AR": AvailabilityRequirement = EnumParser.SecurityRequirement(value, "AR"); break;
                    case "MAV": ModifiedAttackVector = EnumParser.Modified(value, "MAV", EnumParser.AttackVector); break;
                    case "MAC": ModifiedAttackComplexity = EnumParser.Modified(value, "MAC", EnumParser.AttackComplexity); break;
                    case "MPR": ModifiedPrivilegesRequired = EnumParser.Modified(value, "MPR", EnumParser.PrivilegesRequired); break;
                    case "MUI": ModifiedUserInteraction = EnumParser.Modified(value, "MUI", EnumParser.UserInteraction); break;
                    case "MS": ModifiedScope = EnumParser.Modified(value, "MS", EnumParser.Scope); break;
                    case "MC": ModifiedConfidentialityImpact = EnumParser.Modified(value, "MC", EnumParser.Impact); break;
                    case "MI": ModifiedIntegrityImpact = EnumParser.Modified(value, "MI", EnumParser.Impact); break;
                    case "MA": ModifiedAvailabilityImpact = EnumParser.Modified(value, "MA", EnumParser.Impact); break;
                }
            }

            CheckRequiredMetrics(parsedMetrics);

            CalculateScores();
        }
        #endregion

        #region Interface members
        public string VectorPrefix => "CVSS:3.0";
        public double BaseScore { get; private set; }
        public QualitativeSeverityRating QualitativeBaseScore => QualitativeScore(BaseScore);
        public double TemporalScore { get; private set; }
        public QualitativeSeverityRating QualitativeTemporalScore => QualitativeScore(TemporalScore);
        public double EnvironmentalScore { get; private set; }
        public QualitativeSeverityRating QualitativeEnvironmentalScore => QualitativeScore(EnvironmentalScore);
        public string Vector => BuildNormalizedVector(false);
        public string FullVector => BuildNormalizedVector(true);
        #endregion

        #region Helper

        internal void CheckRequiredMetrics(IEnumerable<string> metricsSet)
        {
            var metricsSetList = metricsSet.ToList();
            void CheckParsed(string param)
            {
                if (!metricsSetList.Contains(param))
                {
                    throw new ArgumentException($"Required metric missing \"{param}\"");
                }
            }

            CheckParsed("AV");
            CheckParsed("AC");
            CheckParsed("PR");
            CheckParsed("UI");
            CheckParsed("S");
            CheckParsed("C");
            CheckParsed("I");
            CheckParsed("A");
        }

        internal void CalculateScores()
        {
            double ImpactSubScore(Scope scope, double subScore)
            {
                switch (scope)
                {
                    case Scope.Unchanged:
                        return 6.42 * subScore;
                    case Scope.Changed:
                        return 7.52 * (subScore - 0.029) - 3.25 * Math.Pow(subScore - 0.02, 15);
                    default:
                        throw new ArgumentOutOfRangeException(nameof(Scope), Scope, "Invalid scope");
                }
            }

            double Score(Scope scope, double impactSub, double exploitSub)
            {
                if (impactSub <= 0)
                {
                    return 0;
                }
                switch (scope)
                {
                    case Scope.Unchanged:
                        return Math.Min(impactSub + exploitSub, 10).RoundUp(1);
                    case Scope.Changed:
                        return Math.Min(1.08 * (impactSub + exploitSub), 10).RoundUp(1);
                    default:
                        throw new ArgumentOutOfRangeException(nameof(Scope), Scope, "Invalid scope");
                }
            }

            double TempScore(double baseScore)
            {
                return (baseScore * ExploitCodeMaturity.NumericValue() * RemediationLevel.NumericValue() *
                       ReportConfidence.NumericValue()).RoundUp(1);
            }

            var impactSubScoreBase = 1 - (1 - ConfidentialityImpact.NumericValue()) * (1 - IntegrityImpact.NumericValue()) *
                          (1 - AvailabilityImpact.NumericValue());
            var impactSubScore = ImpactSubScore(Scope, impactSubScoreBase);
            var exploitabilitySubScore = 8.22 * AttackVector.NumericValue() * AttackComplexity.NumericValue() *
                                         PrivilegesRequired.NumericValue(Scope) * UserInteraction.NumericValue();
            BaseScore = Score(Scope, impactSubScore, exploitabilitySubScore);

            //Temporal
            TemporalScore = TempScore(BaseScore);

            //Environmental
            var impactSubScoreModified = Math.Min(0.915,
                1 - (1 - ModifiedConfidentialityImpact.Modified(ConfidentialityImpact, EnumExtensions.NumericValue) *
                     ConfidentialityRequirement.NumericValue()) * (1 - ModifiedIntegrityImpact.Modified(IntegrityImpact,
                                                                       EnumExtensions
                                                                           .NumericValue) *
                                                                   IntegrityRequirement.NumericValue()) *
                (1 - ModifiedAvailabilityImpact.Modified(AvailabilityImpact, EnumExtensions.NumericValue) *
                 AvailabilityRequirement.NumericValue()));
            var modifiedImpactSubScore = ImpactSubScore(ModifiedScope ?? Scope, impactSubScoreModified);
            var modifiedExploitabilitySubScore =
                8.22 * ModifiedAttackVector.Modified(AttackVector, EnumExtensions.NumericValue) *
                ModifiedAttackComplexity.Modified(AttackComplexity, EnumExtensions.NumericValue) *
                ModifiedPrivilegesRequired.Modified(PrivilegesRequired, required => required.NumericValue(ModifiedScope ?? Scope)) *
                ModifiedUserInteraction.Modified(UserInteraction, EnumExtensions.NumericValue);
            EnvironmentalScore = TempScore(
                Score(ModifiedScope ?? Scope, modifiedImpactSubScore, modifiedExploitabilitySubScore));
        }

        private string BuildNormalizedVector(bool addEmptyValues)
        {
            var param = new List<string>
            {
                $"AV:{AttackVector.StringValue()}",
                $"AC:{AttackComplexity.StringValue()}",
                $"PR:{PrivilegesRequired.StringValue()}",
                $"UI:{UserInteraction.StringValue()}",
                $"S:{Scope.StringValue()}",
                $"C:{ConfidentialityImpact.StringValue()}",
                $"I:{IntegrityImpact.StringValue()}",
                $"A:{AvailabilityImpact.StringValue()}"
            };

            void AddConditional(string key, string value)
            {
                if (!string.IsNullOrEmpty(value))
                    param.Add($"{key}:{value}");
                else if (addEmptyValues)
                    param.Add($"{key}:X");
            }

            AddConditional("E", ExploitCodeMaturity?.StringValue());
            AddConditional("RL", RemediationLevel?.StringValue());
            AddConditional("RC", ReportConfidence?.StringValue());

            AddConditional("CR", ConfidentialityRequirement?.StringValue());
            AddConditional("IR", IntegrityRequirement?.StringValue());
            AddConditional("AR", AvailabilityRequirement?.StringValue());
            AddConditional("MAV", ModifiedAttackVector?.StringValue());
            AddConditional("MAC", ModifiedAttackComplexity?.StringValue());
            AddConditional("MPR", ModifiedPrivilegesRequired?.StringValue());
            AddConditional("MUI", ModifiedUserInteraction?.StringValue());
            AddConditional("MS", ModifiedScope?.StringValue());
            AddConditional("MC", ModifiedConfidentialityImpact?.StringValue());
            AddConditional("MI", ModifiedIntegrityImpact?.StringValue());
            AddConditional("MA", ModifiedAvailabilityImpact?.StringValue());

            StringBuilder sb = new StringBuilder();
            sb.Append(VectorPrefix);
            foreach (var current in param)
            {
                sb.Append('/');
                sb.Append(current);
            }
            return sb.ToString();
        }

        private QualitativeSeverityRating QualitativeScore(double rawScore)
        {
            if (rawScore < 0 && rawScore > 10)
            {
                throw new ArgumentException("Score below 0 or above 10 is invalid", nameof(rawScore));
            }
            if (rawScore == 0)
            {
                return QualitativeSeverityRating.None;
            }
            if (rawScore < 4)
            {
                return QualitativeSeverityRating.Low;
            }
            if (rawScore < 7)
            {
                return QualitativeSeverityRating.Medium;
            }
            if (rawScore < 9)
            {
                return QualitativeSeverityRating.High;
            }
            return QualitativeSeverityRating.Critical;
        }
        #endregion
    }
}