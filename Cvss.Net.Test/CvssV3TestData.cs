namespace Cvss.Net.Test
{
    public static class CvssV3TestData
    {
        public static CvssV3 Valid44Base =>
            new CvssV3("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L");
        public static CvssV3 Valid41Temp =>
            new CvssV3("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:P/RL:W/RC:C");
        public static CvssV3 Valid34Env =>
            new CvssV3("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:P/RL:W/RC:C/MS:U");
    }
}