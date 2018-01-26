using System;

namespace Cvss.Net.Extensions
{
    public static class MathExtensions
    {
        public static double RoundUp(this double value, uint decimals)
        {
            double multiplier = Math.Pow(10, Convert.ToDouble(decimals));
            return Math.Ceiling(value * multiplier) / multiplier;
        }
    }
}
