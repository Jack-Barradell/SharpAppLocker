using System;
using System.Collections.Generic;
using System.Linq;
using SharpAppLockerAudit.Model;

namespace SharpAppLockerAudit.Analysis
{
    internal enum Severity { Critical = 0, High = 1, Medium = 2, Low = 3, Info = 4 }

    internal sealed class Finding
    {
        public Severity Severity;
        public string Category;
        public string Collection;
        public Guid RuleId;
        public string RuleName;
        public string Detail;
        public Rule OffendingRule;
    }

    internal static class PolicyAnalyser
    {
        private static readonly string[] WritableMarkers =
        {
            @"\APPDATA\", @"\LOCAL\TEMP\", @"\DOWNLOADS\", @"\DESKTOP\", @"\PUBLIC\",
            @"\PROGRAMDATA\", @"%OSDRIVE%\USERS\", @"\TEMP\", "%REMOVABLE%", "%HOT%",
        };

        private static readonly char[] Wild = { '*', '?' };

        private static readonly string[] KnownWritableDirs =
        {
            @"%WINDIR%\TASKS\*",
            @"%WINDIR%\TEMP\*",
            @"%WINDIR%\TRACING\*",
            @"%WINDIR%\REGISTRATION\CRMLOG\*",
            @"%SYSTEM32%\TASKS\*",
            @"%SYSTEM32%\SPOOL\DRIVERS\COLOR\*",
            @"%SYSTEM32%\SPOOL\PRINTERS\*",
            @"%SYSTEM32%\FXSTMP\*",
            @"%SYSTEM32%\COM\DMP\*",
            @"%SYSTEM32%\MICROSOFT\CRYPTO\RSA\MACHINEKEYS\*",
        };

        private static readonly HashSet<string> BroadAudience = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "S-1-1-0",
            "S-1-5-11",
            "S-1-5-32-545",
            "S-1-5-4",
            "S-1-5-32-546",
        };

        private static readonly HashSet<string> AdminAudience = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "S-1-5-32-544",
            "S-1-5-18",
        };

        private static readonly HashSet<int> BroadDomainRids = new HashSet<int> { 513, 514 };
        private static readonly HashSet<int> AdminDomainRids = new HashSet<int> { 512, 518, 519 };

        public static List<Finding> Analyse(PolicyDocument doc, string collectionFilter)
        {
            List<Finding> findings = new List<Finding>();

            foreach (RuleCollection c in doc.Collections)
            {
                if (collectionFilter != null &&
                    !c.Type.Equals(collectionFilter, StringComparison.OrdinalIgnoreCase))
                    continue;

                AnalyseEnforcement(c, findings);

                foreach (Rule r in c.Rules)
                {
                    if (!string.Equals(r.Action, "Allow", StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (r.Kind == "FilePathRule")
                        AnalysePathRule(c, r, findings);
                    else if (r.Kind == "FilePublisherRule")
                        AnalysePublisherRule(c, r, findings);
                }
            }

            return findings.OrderBy(f => (int)f.Severity).ThenBy(f => f.Collection).ToList();
        }

        private static void AnalysePathRule(RuleCollection c, Rule r, List<Finding> findings)
        {
            bool broad = IsBroadAudience(r.Sid);
            bool admin = IsAdminAudience(r.Sid);

            List<string> excPaths = r.Exclusions
                .Select(e => NormalisePath(PathValue(e)))
                .Where(s => !string.IsNullOrEmpty(s))
                .ToList();

            foreach (Condition inc in r.Inclusions)
            {
                string path = NormalisePath(PathValue(inc));
                if (string.IsNullOrEmpty(path))
                    continue;

                if (excPaths.Any(ep => GlobIsSuperset(ep, path)))
                {
                    Add(findings, Severity.Info, "RULE-EXCEPTED", c, r,
                        "Allow for " + path + Audience(r.Sid) +
                        " is fully covered by an exception, so this condition grants no execution.");
                    continue;
                }

                if (path == "*" || path == "*.*" || path == @"*\*")
                {
                    Add(findings, admin ? Severity.Info : Severity.Critical, "ALLOW-ALL", c, r,
                        "Allows execution of ANY file" + Audience(r.Sid) +
                        (admin ? " (administrators are unconstrained by design)." :
                                 " - this negates the whole policy."));
                    continue;
                }

                string marker = WritableMarkers.FirstOrDefault(path.Contains);
                if (marker != null)
                {
                    Add(findings, broad ? Severity.High : Severity.Medium, "WRITABLE-PATH-ALLOW", c, r,
                        "Allows execution from a user-writable location (" + marker.Trim('\\') + "): " +
                        path + Audience(r.Sid) + PartialExceptionNote(excPaths.Count));
                    continue;
                }

                if (IsBroadRoot(path))
                {
                    bool encompassesWindows = path.StartsWith("%WINDIR%") || path.StartsWith("%SYSTEM32%")
                                              || path.StartsWith("%OSDRIVE%") || path.StartsWith(@"C:\");
                    Severity sev = broad ? Severity.High : Severity.Low;
                    if (path.StartsWith("%PROGRAMFILES%")) sev = Severity.Info;

                    if (encompassesWindows)
                    {
                        List<string> inside    = KnownWritableDirs.Where(w => GlobIsSuperset(path, w)).ToList();
                        List<string> excepted  = inside.Where(w => excPaths.Any(ep => GlobIsSuperset(ep, w))).ToList();
                        List<string> remaining = inside.Where(w => !excepted.Contains(w)).ToList();

                        if (inside.Count > 0 && remaining.Count == 0)
                        {
                            Add(findings, Severity.Info, "BROAD-WILDCARD-MITIGATED", c, r,
                                "Broad wildcard allow: " + path + Audience(r.Sid) +
                                " - exceptions exclude the known user-writable subdirectories (" +
                                string.Join(", ", excepted.ToArray()) + "), so those paths are blocked.");
                        }
                        else
                        {
                            string reach = remaining.Count > 0
                                ? " - still reaches user-writable subdirectories: " + string.Join(", ", remaining.ToArray())
                                : " - includes user-writable subdirectories (e.g. Tasks, Temp, spool\\drivers\\color) unless excepted";
                            string note = excepted.Count > 0
                                ? "  [already excepted: " + string.Join(", ", excepted.ToArray()) + "]"
                                : "";
                            Add(findings, sev, "BROAD-WILDCARD", c, r,
                                "Broad wildcard allow: " + path + Audience(r.Sid) + reach + note);
                        }
                    }
                    else
                    {
                        Add(findings, sev, "BROAD-WILDCARD", c, r,
                            "Broad wildcard allow: " + path + Audience(r.Sid) +
                            PartialExceptionNote(excPaths.Count));
                    }
                }
            }
        }

        private static string PartialExceptionNote(int exceptionCount)
        {
            return exceptionCount > 0
                ? "  [rule has " + exceptionCount + " exception(s), none covering this location]"
                : "";
        }

        private static string ExpandForCompare(string p)
        {
            string s = (p ?? "").ToUpperInvariant();
            s = s.Replace("%SYSTEM32%", @"C:\WINDOWS\SYSTEM32");
            s = s.Replace("%WINDIR%", @"C:\WINDOWS");
            s = s.Replace("%OSDRIVE%", "C:");
            s = s.Replace("%PROGRAMFILES%", @"C:\PROGRAM FILES");
            return s;
        }

        private static bool GlobIsSuperset(string outer, string inner)
        {
            string oe = ExpandForCompare(outer);
            string ie = ExpandForCompare(inner);
            if (oe.Length == 0) return false;

            if (oe == "*" || oe == @"*\*" || oe == "*.*")
                return true;

            if (oe.EndsWith(@"\*", StringComparison.Ordinal))
            {
                string prefix = oe.Substring(0, oe.Length - 1);
                if (prefix.IndexOfAny(Wild) >= 0) return false;
                return ie.StartsWith(prefix, StringComparison.Ordinal);
            }

            if (oe.IndexOfAny(Wild) >= 0) return false;
            return string.Equals(oe, ie, StringComparison.Ordinal);
        }

        private static void AnalysePublisherRule(RuleCollection c, Rule r, List<Finding> findings)
        {
            if (!IsAnyPublisher(r))
                return;

            bool admin = IsAdminAudience(r.Sid);
            if (c.Type.Equals("Appx", StringComparison.OrdinalIgnoreCase))
            {
                Add(findings, Severity.Info, "PUBLISHER-ANY-SIGNED", c, r,
                    "Allows any signed packaged app (standard Appx baseline)" + Audience(r.Sid) + ".");
            }
            else
            {
                Add(findings, admin ? Severity.Low : Severity.High, "PUBLISHER-ANY-SIGNED", c, r,
                    "Allows ANY signed file" + Audience(r.Sid) +
                    " - any Authenticode-signed binary runs, including signed living-off-the-land tools.");
            }
        }

        private static bool IsBroadAudience(string sid)
        {
            if (sid == null) return false;
            if (BroadAudience.Contains(sid)) return true;
            return DomainRidMatches(sid, BroadDomainRids);
        }

        private static bool IsAdminAudience(string sid)
        {
            if (sid == null) return false;
            if (AdminAudience.Contains(sid)) return true;
            return DomainRidMatches(sid, AdminDomainRids);
        }

        private static bool DomainRidMatches(string sid, HashSet<int> rids)
        {
            if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) return false;
            int dash = sid.LastIndexOf('-');
            int rid;
            return dash > 0 && int.TryParse(sid.Substring(dash + 1), out rid) && rids.Contains(rid);
        }

        private static bool IsBroadRoot(string path)
        {
            int wc = path.IndexOfAny(new[] { '*', '?' });
            if (wc < 0)
                return false;

            string prefix = path.Substring(0, wc);
            int slash = prefix.LastIndexOf('\\');
            string head = slash >= 0 ? prefix.Substring(0, slash) : "";
            int segments = head.Split('\\').Count(s => s.Length > 0);
            return segments <= 2;
        }

        private static string PathValue(Condition c)
        {
            string s = c.Summary ?? "";

            int q1 = s.IndexOf('"');
            if (q1 >= 0)
            {
                int q2 = s.IndexOf('"', q1 + 1);
                if (q2 > q1) return s.Substring(q1 + 1, q2 - q1 - 1);
            }

            const string p = "Path: ";
            int idx = s.IndexOf(p, StringComparison.Ordinal);
            if (idx >= 0) return s.Substring(idx + p.Length).Trim();

            return "";
        }

        private static string NormalisePath(string path)
        {
            return (path ?? "").ToUpperInvariant().Replace("%WINDIR%\\SYSTEM32", "%SYSTEM32%");
        }

        private static bool IsAnyPublisher(Rule r)
        {
            foreach (Condition c in r.Inclusions)
            {
                string s = (c.Summary ?? "").ToUpperInvariant();
                if (s.Contains("PUBLISHER: *")) return true;
                if (s.Contains("{\"*\\*\\*\"")) return true;
            }
            return false;
        }

        private static string Audience(string sid)
        {
            if (string.IsNullOrEmpty(sid)) return "";
            return " for " + Sid.Describe(sid);
        }

        private static void AnalyseEnforcement(RuleCollection c, List<Finding> findings)
        {
            if (c.Rules.Count == 0)
                return;

            string m = (c.EnforcementMode ?? "").Trim();
            if (m.StartsWith("Enabled", StringComparison.OrdinalIgnoreCase))
                return;

            if (m.StartsWith("NotConfigured", StringComparison.OrdinalIgnoreCase))
            {
                AddCollection(findings, Severity.Info, "ENFORCED-IMPLICIT", c,
                    c.Rules.Count + " rule(s) present with EnforcementMode NotConfigured - these ARE enforced by default (a higher-precedence GPO could override).");
                return;
            }

            if (m.StartsWith("AuditOnly", StringComparison.OrdinalIgnoreCase))
            {
                AddCollection(findings, Severity.Medium, "NOT-ENFORCED", c,
                    c.Rules.Count + " rule(s) present but EnforcementMode is AuditOnly - nothing is blocked, only logged.");
                return;
            }

            AddCollection(findings, Severity.Info, "ENFORCEMENT-UNKNOWN", c,
                c.Rules.Count + " rule(s) present; EnforcementMode is '" + m + "' - cannot confirm enforcement (e.g. file mode without --enforcement-from-registry).");
        }

        private static void AddCollection(List<Finding> list, Severity sev, string cat, RuleCollection c, string detail)
        {
            list.Add(new Finding
            {
                Severity = sev,
                Category = cat,
                Collection = c.Type,
                RuleId = Guid.Empty,
                RuleName = "(collection)",
                Detail = detail
            });
        }

        private static void Add(List<Finding> list, Severity sev, string cat, RuleCollection c, Rule r, string detail)
        {
            list.Add(new Finding
            {
                Severity = sev,
                Category = cat,
                Collection = c.Type,
                RuleId = r.Id,
                RuleName = string.IsNullOrEmpty(r.Name) ? "(unnamed)" : r.Name,
                Detail = detail,
                OffendingRule = r
            });
        }
    }
}