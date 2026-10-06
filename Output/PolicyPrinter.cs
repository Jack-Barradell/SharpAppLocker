using System;
using System.Collections.Generic;
using System.Linq;
using SharpAppLockerAudit.Model;

namespace SharpAppLockerAudit.Output
{
    internal static class PolicyPrinter
    {
        public static void Print(PolicyDocument policy, string collectionFilter, ISet<string> matchSids, string action)
        {
            Console.WriteLine("AppLocker policy (schema v" + policy.Version + ")");
            if (matchSids != null)
                Console.WriteLine("  (filtered to " + matchSids.Count + " SID(s))");
            if (policy.Collections.Count == 0)
                Console.WriteLine("  No rule collections defined.");

            foreach (RuleCollection c in policy.Collections)
            {
                if (collectionFilter != null &&
                    !c.Type.Equals(collectionFilter, StringComparison.OrdinalIgnoreCase))
                    continue;

                List<Rule> rules = c.Rules
                    .Where(r => (matchSids == null || matchSids.Contains(r.Sid))
                             && (action == null || r.Action.Equals(action, StringComparison.OrdinalIgnoreCase)))
                    .ToList();

                Console.WriteLine();
                Console.WriteLine("== " + c.Type + " rules  [EnforcementMode: " + c.EnforcementMode +
                                  "]  (" + rules.Count + " rule(s))");

                foreach (Rule r in rules.OrderBy(r => r.Action == "Deny" ? 0 : 1).ThenBy(r => r.Name))
                {
                    Console.WriteLine();
                    Console.WriteLine("  [" + r.Action.ToUpperInvariant() + "] " + r.Name);
                    Console.WriteLine("     Type:    " + r.Kind);
                    Console.WriteLine("     Id:      " + r.Id);
                    Console.WriteLine("     Applies: " + Sid.Describe(r.Sid));
                    if (!string.IsNullOrEmpty(r.Description))
                        Console.WriteLine("     Desc:    " + r.Description);

                    foreach (Condition inc in r.Inclusions)
                        Console.WriteLine("     Include: " + inc.Summary);
                    foreach (Condition exc in r.Exclusions)
                        Console.WriteLine("     Exclude: " + exc.Summary);
                }
            }
        }
    }
}