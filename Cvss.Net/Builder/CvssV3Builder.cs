using System.Collections.Generic;
using Cvss.Net.Enums;

namespace Cvss.Net.Builder
{
    public class CvssV3Builder
    {
        private CvssV3 Cvss { get; }
        private List<string> UsedMetrics { get; }

        internal CvssV3Builder()
        {
            Cvss = new CvssV3();
            UsedMetrics = new List<string>();
        }

        internal CvssV3Builder(CvssV3 cvss)
        {
            Cvss = new CvssV3(cvss);
            UsedMetrics = new List<string>();
        }

        public CvssV3 Build()
        {
            Cvss.CheckRequiredMetrics(UsedMetrics);
            Cvss.CalculateScores();
            return Cvss;
        }

        public CvssV3Builder AttackVector(AttackVector param) { UsedMetrics.Add("AV"); Cvss.AttackVector = param; return this; }
        public CvssV3Builder AttackComplexity(AttackComplexity param) { UsedMetrics.Add("AC"); Cvss.AttackComplexity = param; return this; }
        public CvssV3Builder PrivilegesRequired(PrivilegesRequired param) { UsedMetrics.Add("PR"); Cvss.PrivilegesRequired = param; return this; }
        public CvssV3Builder UserInteraction(UserInteraction param) { UsedMetrics.Add("UI"); Cvss.UserInteraction = param; return this; }
        public CvssV3Builder Scope(Scope param) { UsedMetrics.Add("S"); Cvss.Scope = param; return this; }
        public CvssV3Builder ConfidentialityImpact(Impact param) { UsedMetrics.Add("C"); Cvss.ConfidentialityImpact = param; return this; }
        public CvssV3Builder IntegrityImpact(Impact param) { UsedMetrics.Add("I"); Cvss.IntegrityImpact = param; return this; }
        public CvssV3Builder AvailabilityImpact(Impact param) { UsedMetrics.Add("A"); Cvss.AvailabilityImpact = param; return this; }
        public CvssV3Builder ExploitCodeMaturity(ExploitCodeMaturity? param) { UsedMetrics.Add("E"); Cvss.ExploitCodeMaturity = param; return this; }
        public CvssV3Builder RemediationLevel(RemediationLevel? param) { UsedMetrics.Add("RL"); Cvss.RemediationLevel = param; return this; }
        public CvssV3Builder ReportConfidence(ReportConfidence? param) { UsedMetrics.Add("RC"); Cvss.ReportConfidence = param; return this; }
        public CvssV3Builder ConfidentialityRequirement(SecurityRequirement? param) { UsedMetrics.Add("CR"); Cvss.ConfidentialityRequirement = param; return this; }
        public CvssV3Builder IntegrityRequirement(SecurityRequirement? param) { UsedMetrics.Add("IR"); Cvss.IntegrityRequirement = param; return this; }
        public CvssV3Builder AvailabilityRequirement(SecurityRequirement? param) { UsedMetrics.Add("AR"); Cvss.AvailabilityRequirement = param; return this; }
        public CvssV3Builder ModifiedAttackVector(AttackVector? param) { UsedMetrics.Add("MAV"); Cvss.ModifiedAttackVector = param; return this; }
        public CvssV3Builder ModifiedAttackComplexity(AttackComplexity? param) { UsedMetrics.Add("MAC"); Cvss.ModifiedAttackComplexity = param; return this; }
        public CvssV3Builder ModifiedPrivilegesRequired(PrivilegesRequired? param) { UsedMetrics.Add("MPR"); Cvss.ModifiedPrivilegesRequired = param; return this; }
        public CvssV3Builder ModifiedUserInteraction(UserInteraction? param) { UsedMetrics.Add("MUI"); Cvss.ModifiedUserInteraction = param; return this; }
        public CvssV3Builder ModifiedScope(Scope? param) { UsedMetrics.Add("MS"); Cvss.ModifiedScope = param; return this; }
        public CvssV3Builder ModifiedConfidentialityImpact(Impact? param) { UsedMetrics.Add("MC"); Cvss.ModifiedConfidentialityImpact = param; return this; }
        public CvssV3Builder ModifiedIntegrityImpact(Impact? param) { UsedMetrics.Add("MI"); Cvss.ModifiedIntegrityImpact = param; return this; }
        public CvssV3Builder ModifiedAvailabilityImpact(Impact? param) { UsedMetrics.Add("MA"); Cvss.ModifiedAvailabilityImpact = param; return this; }
    }
}