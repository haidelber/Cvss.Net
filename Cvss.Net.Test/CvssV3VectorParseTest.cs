using Xunit;

namespace Cvss.Net.Test
{
    public static class CvssV3TestData
    {
        public static CvssV3 Valid51Base => new CvssV3("CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L");
    }
    public class CvssV3VectorParseTest
    {
        /// <summary>
        /// No Exceptions means success
        /// </summary>
        [Fact]
        public void TestValidVectors()
        {
            var cvss = CvssV3TestData.Valid51Base;
        }
    }

    public class CvssV3ScoreTest
    {
        /// <summary>
        /// No Exceptions means success
        /// </summary>
        [Fact]
        public void TestValidVectors()
        {
            Assert.Equal(5.1,CvssV3TestData.Valid51Base.BaseScore);
        }
    }
}
