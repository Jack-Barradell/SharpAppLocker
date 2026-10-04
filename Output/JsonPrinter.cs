using System;
using System.Collections.Generic;
using System.Linq;
using SharpAppLocker.Analysis;
using SharpAppLocker.Model;

namespace SharpAppLocker.Output
{
    internal static class JsonPrinter
    {
        public static void PrintPolicy(PolicyDocument policy, string collectionFilter, ISet<string> matchSids, string action)
        {
            List<object> collections = new List<object>();
            foreach (RuleCollection c in policy.Collections)
            {
                if (collectionFilter != null &&
                    !c.Type.Equals(collectionFilter, StringComparison.OrdinalIgnoreCase))
                    continue;

                List<object> rules = new List<object>();
                foreach (Rule r in c.Rules)
                {
                    if (matchSids != null && !matchSids.Contains(r.Sid)) continue;
                    if (action != null && !r.Action.Equals(action, StringComparison.OrdinalIgnoreCase)) continue;

                    rules.Add(new Dictionary<string, object>
                    {
                        { "action", r.Action },
                        { "kind", r.Kind },
                        { "id", r.Id },
                        { "name", r.Name },
                        { "sid", r.Sid },
                        { "sidName", Sid.Describe(r.Sid) },
                        { "description", r.Description },
                        { "inclusions", r.Inclusions.Select(x => (object)x.Summary).ToList() },
                        { "exclusions", r.Exclusions.Select(x => (object)x.Summary).ToList() },
                    });
                }

                collections.Add(new Dictionary<string, object>
                {
                    { "type", c.Type },
                    { "enforcementMode", c.EnforcementMode },
                    { "rules", rules },
                });
            }

            object doc = new Dictionary<string, object>
            {
                { "version", policy.Version },
                { "collections", collections },
            };
            Console.WriteLine(Json.Serialize(doc));
        }

        public static void PrintFindings(List<Finding> findings)
        {
            List<object> items = findings.Select(f => (object)new Dictionary<string, object>
            {
                { "severity", f.Severity.ToString() },
                { "category", f.Category },
                { "collection", f.Collection },
                { "ruleId", f.RuleId },
                { "ruleName", f.RuleName },
                { "detail", f.Detail },
            }).ToList();
            Console.WriteLine(Json.Serialize(items));
        }

        public static void PrintBypass(List<BypassResult> results)
        {
            List<object> items = results.Select(r => (object)new Dictionary<string, object>
            {
                { "severity", r.Severity.ToString() },
                { "kind", r.Kind },
                { "collection", r.Collection },
                { "ruleId", r.RuleId },
                { "ruleName", r.RuleName },
                { "rulePath", r.RulePath },
                { "dropPath", r.DropPath },
                { "detail", r.Detail },
            }).ToList();
            Console.WriteLine(Json.Serialize(items));
        }
    }
}