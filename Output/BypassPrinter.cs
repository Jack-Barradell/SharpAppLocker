using System;
using System.Collections.Generic;
using SharpAppLockerAudit.Analysis;

namespace SharpAppLockerAudit.Output
{
    internal static class BypassPrinter
    {
        public static void Print(List<BypassResult> results)
        {
            Console.WriteLine("AppLocker bypass test (writability of allowed locations)");
            if (results.Count == 0)
            {
                Console.WriteLine("  No writable allowed locations found for the target principal.");
                return;
            }

            Console.WriteLine("  " + results.Count + " exploitable allow rule location(s):");

            foreach (BypassResult r in results)
            {
                Console.WriteLine();
                Console.WriteLine("  [" + r.Severity.ToString().ToUpperInvariant() + "] " + r.Kind + "  (" + r.Collection + ")");
                Console.WriteLine("     Rule:  " + r.RuleName + "  " + r.RuleId);
                Console.WriteLine("     Allows: " + r.RulePath);
                Console.WriteLine("     Drop:   " + r.DropPath);
                Console.WriteLine("     " + r.Detail);
            }
        }
    }
}