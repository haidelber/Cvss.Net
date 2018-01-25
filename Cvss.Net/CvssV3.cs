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
        public AttackVector AttackVector { get; }
        public AttackComplexity AttackComplexity { get; }
        public PrivilegesRequired PrivilegesRequired { get; }
        public UserInteraction UserInteraction { get; }
        public Scope Scope { get; }
        public Impact ConfidentialityImpact { get; }
        public Impact IntegrityImpact { get; }
        public Impact AvailabilityImpact { get; }
        #endregion

        #region Temporal score properties
        public ExploitCodeMaturity? ExploitCodeMaturity { get; }
        public RemediationLevel? RemediationLevel { get; }
        public ReportConfidence? ReportConfidence { get; }
        #endregion

        #region Environmental score properties
        public SecurityRequirement? ConfidentialityRequirement { get; }
        public SecurityRequirement? IntegrityRequirement { get; }
        public SecurityRequirement? AvailabilityRequirement { get; }

        public AttackVector? ModifiedAttackVector { get; }
        public AttackComplexity? ModifiedAttackComplexity { get; }
        public PrivilegesRequired? ModifiedPrivilegesRequired { get; }
        public UserInteraction? ModifiedUserInteraction { get; }
        public Scope? ModifiedScope { get; }
        public Impact? ModifiedConfidentialityImpact { get; }
        public Impact? ModifiedIntegrityImpact { get; }
        public Impact? ModifiedAvailabilityImpact { get; }
        #endregion

        #region Constructors
        internal CvssV3(AttackVector attackVector, AttackComplexity attackComplexity, PrivilegesRequired privilegesRequired,
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
        }

        public CvssV3(string vector)
        {
            if (!vector.StartsWith(VectorPrefix))
            {
                throw new ArgumentException($"Vector must begin with prefix \"{VectorPrefix}\"", nameof(vector));
            }

            var paramParts = vector.Split('/').Skip(1);
            var paramRegex = new Regex("[A-Za-z]+:[A-Za-z]{1}");
            var parsedParams = new List<string>();
            foreach (var paramVector in paramParts)
            {
                if (!paramRegex.IsMatch(paramVector))
                {
                    throw new ArgumentException($"Invalid vector-part \"{paramVector}\"", nameof(vector));
                }

                var kv = paramVector.Split(':');
                var value = kv[1];
                var key = kv[0].ToUpperInvariant();
                parsedParams.Add(key);
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

            void CheckParsed(string param)
            {
                if (!parsedParams.Contains(param))
                {
                    throw new ArgumentException($"Required metric missing \"{param}\"", nameof(vector));
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

            CalculateScores();
        }
        #endregion

        #region Interface members
        public string VectorPrefix => "CVSS:3.0";
        public double BaseScore { get; private set; }
        public QualitativeSeverityRating QualitativeBaseScore => QualitativeScore(BaseScore);
        public double TemporalScore { get; }
        public QualitativeSeverityRating QualitativeTemporalScore => QualitativeScore(TemporalScore);
        public double EnvironmentalScore { get; }
        public QualitativeSeverityRating QualitativeEnvironmentalScore => QualitativeScore(EnvironmentalScore);
        public string Vector => BuildNormalizedVector(false);
        public string FullVector => BuildNormalizedVector(true);
        #endregion

        #region Helper

        private void CalculateScores()
        {
            var impactSubScoreBase = 1 - (1 - ConfidentialityImpact.NumericValue()) * (1 - IntegrityImpact.NumericValue()) *
                          (1 - AvailabilityImpact.NumericValue());
            double impactSubScore = 0;
            switch (Scope)
            {
                case Scope.Unchanged:
                    impactSubScore = 6.42 * impactSubScoreBase;
                    break;
                case Scope.Changed:
                    impactSubScore = 7.52 * (impactSubScoreBase - 0.029) - 3.25 * Math.Pow(impactSubScoreBase - 0.02, 15);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(Scope), Scope, "Invalid scope");
            }
            var exploitabilitySubScore = 8.22 * AttackVector.NumericValue() * AttackComplexity.NumericValue() *
                                         PrivilegesRequired.NumericValue(Scope) * UserInteraction.NumericValue();
            if (impactSubScore <= 0)
            {
                BaseScore = 0;
            }
            else switch (Scope)
                {
                    case Scope.Unchanged:
                        BaseScore = Math.Min(impactSubScore + exploitabilitySubScore, 10).RoundUp(1);
                        break;
                    case Scope.Changed:
                        BaseScore = Math.Min(1.08 * (impactSubScore + exploitabilitySubScore), 10).RoundUp(1);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(Scope), Scope, "Invalid scope");
                }
            //Temporal
            TemporalScore = BaseScore * ExploitCodeMaturity.NumericValue() * RemediationLevel.NumericValue() *
                            ReportConfidence.NumericValue().RoundUp(1);

            //TODO Environmental
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