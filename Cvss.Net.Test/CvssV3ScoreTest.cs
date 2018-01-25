using Xunit;

namespace Cvss.Net.Test
{
    public class CvssV3ScoreTest
    {
        /// <summary>
        /// No Exceptions means success
        /// </summary>
        [Fact]
        public void TestScore()
        {
            Assert.Equal(4.4, CvssV3TestData.Valid44Base.BaseScore);
            Assert.Equal(4.4, CvssV3TestData.Valid44Base.TemporalScore);
            Assert.Equal(4.4, CvssV3TestData.Valid44Base.EnvironmentalScore);

            Assert.Equal(4.4, CvssV3TestData.Valid41Temp.BaseScore);
            Assert.Equal(4.1, CvssV3TestData.Valid41Temp.TemporalScore);
            Assert.Equal(4.1, CvssV3TestData.Valid41Temp.EnvironmentalScore);

            Assert.Equal(4.4, CvssV3TestData.Valid34Env.BaseScore);
            Assert.Equal(4.1, CvssV3TestData.Valid34Env.TemporalScore);
            Assert.Equal(3.4, CvssV3TestData.Valid34Env.EnvironmentalScore);
        }
    }
}