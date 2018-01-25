using System;
using Xunit;

namespace Cvss.Net.Test
{
    public class CvssV3VectorParseTest
    {
        /// <summary>
        /// No Exceptions means success
        /// </summary>
        [Fact]
        public void TestValidVectors()
        {
            var cvss = CvssV3TestData.Valid44Base;
            Console.WriteLine(cvss.Vector);
            cvss = CvssV3TestData.Valid41Temp;
            Console.WriteLine(cvss.Vector);
            cvss = CvssV3TestData.Valid34Env;
            Console.WriteLine(cvss.Vector);
        }
    }
}
