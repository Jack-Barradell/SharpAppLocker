using System;
using System.Collections.Generic;
using System.Linq;
using SharpAppLocker.Model;

namespace SharpAppLocker.Analysis
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
    }

    /// <summary>
    /// Static review of a parsed policy for configuration weaknesses that create bypass surface.
    /// Only Allow rules grant execution, so those are what we scrutinise; Deny rules only reduce
    /// risk. Works on the shared model, so it is identical for COM and file sources.
    /// </summary>
    internal static class PolicyAnalyser
    {
        // User-writable locations: an Allow path rule pointing into one of these is a standing bypass,
        // because a low-privileged user can drop an executable there.
        private static readonly string[] WritableMarkers =
        {
            @"\APPDATA\", @"\LOCAL\TEMP\", @"\DOWNLOADS\", @"\DESKTOP\", @"\PUBLIC\",
            @"\PROGRAMDATA\", @"%OSDRIVE%\USERS\", @"\TEMP\", "%REMOVABLE%", "%HOT%",
        };

        // SIDs that mean "essentially every interactive user".
        private static readonly HashSet<string> BroadAudience = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "S-1-1-0",       // Everyone
            "S-1-5-11",      // Authenticated Users
            "S-1-5-32-545",  // BUILTIN\Users
            "S-1-5-4",       // Interactive
            "S-1-5-32-546",  // Guests
        };

        // SIDs that are unconstrained by design (flagging an allow-all for these is just noise).
        private static readonly HashSet<string> AdminAudience = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "S-1-5-32-544",  // BUILTIN\Administrators
            "S-1-5-18",      // SYSTEM
        };

        public static List<Finding> Analyse(PolicyDocument doc, string collectionFilter)
        {
            List<Finding> findings = new List<Finding>();

            foreach (RuleCollection c in doc.Collections)
            {
                if (collectionFilter != null &&
                    !c.Type.Equals(collectionFilter, StringComparison.OrdinalIgnoreCase))
                    continue;

                foreach (Rule r in c.Rules)
                {
                    if (!string.Equals(r.Action, "Allow", StringComparison.OrdinalIgnoreCase))
                        continue;   // deny rules don't grant execution

                    if (r.Kind == "FilePathRule")
                        AnalysePathRule(c, r, findings);
                    else if (r.Kind == "FilePublisherRule")
                        AnalysePublisherRule(c, r, findings);
                    // FileHashRule: pinned to one binary -> no bypass surface.
                }
            }

            // Most severe first.
            return findings.OrderBy(f => (int)f.Severity).ThenBy(f => f.Collection).ToList();
        }

        private static void AnalysePathRule(RuleCollection c, Rule r, List<Finding> findings)
        {
            bool broad = IsBroadAudience(r.Sid);
            bool admin = AdminAudience.Contains(r.Sid ?? "");

            foreach (Condition inc in r.Inclusions)
            {
                string path = NormalisePath(PathValue(inc));
                if (string.IsNullOrEmpty(path))
                    continue;

                // 1. Allow-all: "*" (optionally "*.*" / "*\*").
                if (path == "*" || path == "*.*" || path == @"*\*")
                {
                    Add(findings, admin ? Severity.Info : Severity.Critical, "ALLOW-ALL", c, r,
                        "Allows execution of ANY file" + Audience(r.Sid) +
                        (admin ? " (administrators are unconstrained by design)." :
                                 " - this negates the whole policy."));
                    continue;
                }

                // 2. Directly into a user-writable location.
                string marker = WritableMarkers.FirstOrDefault(path.Contains);
                if (marker != null)
                {
                    Add(findings, broad ? Severity.High : Severity.Medium, "WRITABLE-PATH-ALLOW", c, r,
                        "Allows execution from a user-writable location (" + marker.Trim('\\') + "): " +
                        path + Audience(r.Sid) + ExceptionNote(r));
                    continue;
                }

                // 3. Broad root wildcard that implicitly includes writable subdirectories.
                if (IsBroadRoot(path))
                {
                    bool encompassesWindows = path.StartsWith("%WINDIR%") || path.StartsWith("%SYSTEM32%")
                                              || path.StartsWith("%OSDRIVE%") || path.StartsWith(@"C:\");
                    Severity sev = broad ? Severity.High : Severity.Low;
                    // %PROGRAMFILES%\* is a normal baseline (users can't write there) -> informational.
                    if (path.StartsWith("%PROGRAMFILES%")) sev = Severity.Info;

                    Add(findings, sev, "BROAD-WILDCARD", c, r,
                        "Broad wildcard allow: " + path + Audience(r.Sid) +
                        (encompassesWindows
                            ? " - includes known user-writable subdirectories (e.g. Tasks, Temp, spool\\drivers\\color) unless excepted."
                            : "") +
                        ExceptionNote(r));
                }
            }
        }

        private static void AnalysePublisherRule(RuleCollection c, Rule r, List<Finding> findings)
        {
            if (!IsAnyPublisher(r))
                return;

            bool admin = AdminAudience.Contains(r.Sid ?? "");
            // "Any signed file" trusts every code-signing certificate, including signed LOLBins.
            // For the Appx collection this is the normal "all signed packaged apps" baseline.
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

        // ---- helpers ----------------------------------------------------------------------

        private static bool IsBroadAudience(string sid)
        {
            return sid != null && BroadAudience.Contains(sid);
        }

        private static bool IsBroadRoot(string path)
        {
            // ends in "\*" with few segments, i.e. a whole top-level tree.
            if (!path.EndsWith(@"\*"))
                return false;
            string head = path.Substring(0, path.Length - 2);
            int segments = head.Split('\\').Count(s => s.Length > 0);
            return segments <= 2;   // %WINDIR%\* , %OSDRIVE%\* , C:\Foo\* etc.
        }

        /// <summary>Pull the path value from a condition summary, in either COM or file form.</summary>
        private static string PathValue(Condition c)
        {
            string s = c.Summary ?? "";

            // file-mode SDDL: APPID://PATH Contains "X"
            int q1 = s.IndexOf('"');
            if (q1 >= 0)
            {
                int q2 = s.IndexOf('"', q1 + 1);
                if (q2 > q1) return s.Substring(q1 + 1, q2 - q1 - 1);
            }

            // com-mode: "Path: X"
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
                if (s.Contains("PUBLISHER: *")) return true;          // com form
                if (s.Contains("{\"*\\*\\*\"")) return true;          // file FQBN form: {"*\*\*",0}
            }
            return false;
        }

        private static string Audience(string sid)
        {
            if (string.IsNullOrEmpty(sid)) return "";
            return " for " + Sid.Describe(sid);
        }

        private static string ExceptionNote(Rule r)
        {
            return r.Exclusions.Count > 0 ? "  [has " + r.Exclusions.Count + " exception(s)]" : "";
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
                Detail = detail
            });
        }
    }
}