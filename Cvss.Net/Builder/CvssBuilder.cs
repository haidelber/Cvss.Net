using Cvss.Net.Enums;

namespace Cvss.Net.Builder
{
    public class CvssBuilder
    {
        public static CvssV3Builder NewV3()
        {
            return new CvssV3Builder();
        }
        public static CvssV3Builder FromExistingV3(CvssV3 cvss)
        {
            return new CvssV3Builder(cvss);
        }
    }
}
