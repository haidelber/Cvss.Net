using System;
using Cvss.Net;
using Cvss.Net.Enums;
using Xunit;
using Xunit.Abstractions;

namespace Cvss.Net.Test
{
    public class CvssV3Test : CvssV3TestData
    {
        public CvssV3Test(ITestOutputHelper output) : base(output)
        {
        }

        [Theory]
        [MemberData(nameof(ValidTestData))]
        public void TestParse(CvssV3 toTest,
            double baseScore, QualitativeSeverityRating baseQ,
            double tempScore, QualitativeSeverityRating tempQ,
            double envScore, QualitativeSeverityRating envQ)
        {
            Output.WriteLine(toTest.Vector);
        }

        [Theory]
        [MemberData(nameof(ValidTestData))]
        public void TestScore(CvssV3 toTest,
            double baseScore, QualitativeSeverityRating baseQ,
            double tempScore, QualitativeSeverityRating tempQ,
            double envScore, QualitativeSeverityRating envQ)
        {
            Output.WriteLine(toTest.Vector);
            Assert.Equal(baseScore, toTest.BaseScore);
            Assert.Equal(tempScore, toTest.TemporalScore);
            Assert.Equal(envScore, toTest.EnvironmentalScore);
        }

        [Theory]
        [MemberData(nameof(ValidTestData))]
        public void TestQualitativeRating(CvssV3 toTest,
            double baseScore, QualitativeSeverityRating baseQ,
            double tempScore, QualitativeSeverityRating tempQ,
            double envScore, QualitativeSeverityRating envQ)
        {
            Output.WriteLine(toTest.Vector);
            Assert.Equal(baseQ, toTest.QualitativeBaseScore);
            Assert.Equal(tempQ, toTest.QualitativeTemporalScore);
            Assert.Equal(envQ, toTest.QualitativeEnvironmentalScore);
        }

        [Fact]
        public void FailInvalidWrongMs()
        {
            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => InvalidWrongMs);
            Assert.Equal("MS", ex.ParamName);
        }

        [Fact]
        public void FailInvalidMissingRequired()
        {
            var ex = Assert.Throws<ArgumentException>(() => InvalidMissingRequired);
            Assert.Contains("\"I\"", ex.Message);
        }
    }
}