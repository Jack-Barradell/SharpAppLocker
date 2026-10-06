using System;
using System.Collections.Generic;
using SharpAppLocker.Analysis;
using SharpAppLocker.Model;

namespace SharpAppLocker.Output
{
    internal static class FindingsPrinter
    {
        public static void Print(List<Finding> findings)
        {
            Console.WriteLine("AppLocker configuration review");
            if (findings.Count == 0)
            {
                Console.WriteLine("  No weak-rule / bypass findings.");
                return;
            }

            int crit = 0, high = 0, med = 0, low = 0, info = 0;
            foreach (Finding f in findings)
            {
                switch (f.Severity)
                {
                    case Severity.Critical: crit++; break;
                    case Severity.High: high++; break;
                    case Severity.Medium: med++; break;
                    case Severity.Low: low++; break;
                    default: info++; break;
                }
            }
            Console.WriteLine("  " + findings.Count + " finding(s): " +
                crit + " critical, " + high + " high, " + med + " medium, " + low + " low, " + info + " info");

            foreach (Finding f in findings)
            {
                Console.WriteLine();
                Console.WriteLine("  [" + f.Severity.ToString().ToUpperInvariant() + "] " + f.Category + "  (" + f.Collection + ")");
                Console.WriteLine("     Rule: " + f.RuleName + "  " + f.RuleId);
                Console.WriteLine("     " + f.Detail);
                PrintRule(f.OffendingRule);
            }
        }

        private static void PrintRule(Rule r)
        {
            if (r == null)
                return;

            Console.WriteLine("     ---- rule ----");
            Console.WriteLine("     Action:  " + r.Action);
            Console.WriteLine("     Type:    " + r.Kind);
            Console.WriteLine("     Applies: " + Sid.Describe(r.Sid));
            if (!string.IsNullOrEmpty(r.Description))
                Console.WriteLine("     Desc:    " + r.Description);

            foreach (Condition inc in r.Inclusions)
                Console.WriteLine("     Include: " + inc.Summary);

            if (r.Exclusions.Count == 0)
                Console.WriteLine("     Exclude: (none)");
            else
                foreach (Condition exc in r.Exclusions)
                    Console.WriteLine("     Exclude: " + exc.Summary);
        }
    }
}