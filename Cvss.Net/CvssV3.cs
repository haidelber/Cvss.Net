using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Cvss.Net.Enums;

namespace Cvss.Net
{
    public class CvssV3 : ICvss
    {
        public string VectorPrefix => "CVSS:3.0";

        #region Base score properties
        public AttackVector AttackVector { get; private set; }
        public AttackComplexity AttackComplexity { get; private set; }
        public PrivilegesRequired PrivilegesRequired { get; private set; }
        public UserInteraction UserInteraction { get; private set; }
        public Scope Scope { get; private set; }
        public Impact ConfidentialityImpact { get; private set; }
        public Impact IntegrityImpact { get; private set; }
        public Impact AvailabilityImpact { get; private set; }
        #endregion

        #region Temporal score properties
        public ExploitCodeMaturity? ExploitCodeMaturity { get; private set; }
        public RemediationLevel? RemediationLevel { get; private set; }
        public ReportConfidence? ReportConfidence { get; private set; }
        #endregion

        #region Environmental score properties
        public SecurityRequirement? ConfidentialityRequirement { get; private set; }
        public SecurityRequirement? IntegrityRequirement { get; private set; }
        public SecurityRequirement? AvailabilityRequirement { get; private set; }

        public AttackVector? ModifiedAttackVector { get; private set; }
        public AttackComplexity? ModifiedAttackComplexity { get; private set; }
        public PrivilegesRequired? ModifiedPrivilegesRequired { get; private set; }
        public UserInteraction? ModifiedUserInteraction { get; private set; }
        public Scope? ModifiedScope { get; private set; }
        public Impact? ModifiedConfidentialityImpact { get; private set; }
        public Impact? ModifiedIntegrityImpact { get; private set; }
        public Impact? ModifiedAvailabilityImpact { get; private set; }
        #endregion

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

            if (!(parsedParams.Contains("AV") && parsedParams.Contains("AC") && parsedParams.Contains("PR")
                  && parsedParams.Contains("UI") && parsedParams.Contains("S") && parsedParams.Contains("C")
                  && parsedParams.Contains("I") && parsedParams.Contains("A")))
            {
                throw new ArgumentException($"Invalid vector-part \"{paramVector}\"", nameof(vector));
            }
        }
    }
}