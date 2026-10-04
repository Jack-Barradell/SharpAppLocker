using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using SharpAppLocker.Model;

namespace SharpAppLocker.Analysis
{
    internal sealed class BypassResult
    {
        public Severity Severity;
        public string Collection;
        public Guid RuleId;
        public string RuleName;
        public string RulePath;    // the allow rule's path condition
        public string DropPath;    // the concrete location the user could write to
        public string Kind;        // REPLACE-EXISTING / NEW-FILE-IN-DIR / CREATE-MISSING / REMOVABLE-MEDIA
        public string Detail;
    }

    /// <summary>
    /// Tests whether Allow path rules are *actually* exploitable, by checking the filesystem ACLs
    /// along each allowed location for the target principal's SIDs. A rule is only a real bypass if
    /// the user can place (or replace) an executable somewhere the rule covers and no Deny path rule
    /// covers that same location.
    ///
    /// Runs against the LOCAL filesystem, so it is meaningful only for the live local policy - not
    /// for .AppLocker files copied from another machine (their ACLs are not these ACLs).
    ///
    /// Effective access is approximated as (allowed rights) &amp; ~(denied rights) over the SID set,
    /// which errs towards under-reporting rather than false positives. Confirm critical cases with
    /// accesschk / Effective Access.
    /// </summary>
    internal static class BypassTester
    {
        // Classic user-writable subdirectories beneath the Windows folder, relative to %WINDIR%.
        // A recursive allow such as "%WINDIR%\*" implicitly covers these.
        private static readonly string[] WritableUnderWindows =
        {
            @"Tasks", @"Temp", @"tracing", @"Registration\CRMLog",
            @"System32\Tasks", @"SysWOW64\Tasks",
            @"System32\spool\drivers\color", @"System32\spool\PRINTERS", @"System32\spool\servers",
            @"System32\com\dmp", @"SysWOW64\com\dmp",
            @"System32\FxsTmp", @"SysWOW64\FxsTmp", @"Debug\WIA",
        };

        public static List<BypassResult> Test(PolicyDocument doc, string collectionFilter, ISet<string> targetSids)
        {
            List<BypassResult> results = new List<BypassResult>();

            foreach (RuleCollection c in doc.Collections)
            {
                if (collectionFilter != null &&
                    !c.Type.Equals(collectionFilter, StringComparison.OrdinalIgnoreCase))
                    continue;

                // Deny path rules that apply to this principal - a drop path covered by one is blocked.
                List<string> denyPaths = c.Rules
                    .Where(r => r.Action == "Deny" && r.Kind == "FilePathRule" && Applies(r, targetSids))
                    .SelectMany(r => r.Inclusions.Select(PathValue))
                    .Where(p => !string.IsNullOrEmpty(p))
                    .Select(ExpandMacros)
                    .Where(p => p != null)
                    .ToList();

                foreach (Rule r in c.Rules)
                {
                    if (r.Action != "Allow" || r.Kind != "FilePathRule" || !Applies(r, targetSids))
                        continue;

                    foreach (Condition inc in r.Inclusions)
                    {
                        string rulePath = PathValue(inc);
                        if (string.IsNullOrEmpty(rulePath))
                            continue;

                        foreach (BypassResult res in TestRulePath(c, r, rulePath, targetSids, denyPaths))
                            results.Add(res);
                    }
                }
            }

            return results.OrderBy(r => (int)r.Severity).ThenBy(r => r.Collection).ToList();
        }

        // --- per-rule testing ---------------------------------------------------------------
        private static IEnumerable<BypassResult> TestRulePath(
            RuleCollection c, Rule r, string rulePath, ISet<string> targetSids, List<string> denyPaths)
        {
            List<BypassResult> found = new List<BypassResult>();

            string upper = rulePath.ToUpperInvariant();
            if (upper.Contains("%REMOVABLE%") || upper.Contains("%HOT%"))
            {
                // Removable / hot-plug media: user-writable by nature, no fixed ACL to read.
                Add(found, Severity.Medium, c, r, rulePath, rulePath, "REMOVABLE-MEDIA",
                    "Allows execution from removable/hot-plug media, which the user fully controls.");
                return found;
            }

            string expanded = ExpandMacros(rulePath);
            if (expanded == null)
                return found;   // unknown macro; skip

            bool wildcard = expanded.IndexOf('*') >= 0;
            bool recursive = expanded.TrimEnd('\\').EndsWith(@"\*") || expanded.EndsWith(@"\*");

            string fixedDir = FixedDirectoryOf(expanded, wildcard);

            if (!wildcard)
            {
                // Specific file: replaceable if the file exists and is writable, or its parent allows create.
                if (File.Exists(expanded))
                {
                    if (CanReplaceFile(expanded, targetSids) && !BlockedByDeny(expanded, denyPaths))
                        Add(found, Severity.High, c, r, rulePath, expanded, "REPLACE-EXISTING",
                            "The allowed file exists and the user can overwrite/replace it.");
                }
                else
                {
                    TestMissing(found, c, r, rulePath, expanded, targetSids, denyPaths);
                }
                return found;
            }

            // Wildcard rule -> a directory (subtree) is covered.
            if (Directory.Exists(fixedDir))
            {
                if (CanCreateFile(fixedDir, targetSids) && !BlockedByDeny(fixedDir, denyPaths))
                    Add(found, Severity.High, c, r, rulePath, fixedDir, "NEW-FILE-IN-DIR",
                        "The allowed directory exists and the user can create a new executable in it.");

                if (recursive)
                    TestKnownWritableSubdirs(found, c, r, rulePath, fixedDir, targetSids, denyPaths);
            }
            else
            {
                TestMissing(found, c, r, rulePath, fixedDir, targetSids, denyPaths);
            }

            return found;
        }

        private static void TestKnownWritableSubdirs(
            List<BypassResult> found, RuleCollection c, Rule r, string rulePath,
            string baseDir, ISet<string> targetSids, List<string> denyPaths)
        {
            // Only meaningful when baseDir is the Windows folder (or an ancestor of these subdirs).
            string windir = Environment.GetEnvironmentVariable("windir") ?? @"C:\Windows";
            if (!baseDir.TrimEnd('\\').Equals(windir.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                return;

            foreach (string sub in WritableUnderWindows)
            {
                string dir = Path.Combine(windir, sub);
                if (!Directory.Exists(dir))
                    continue;
                if (CanCreateFile(dir, targetSids) && !BlockedByDeny(dir, denyPaths))
                    Add(found, Severity.High, c, r, rulePath, dir, "NEW-FILE-IN-DIR",
                        "Recursive allow covers a known user-writable system subdirectory.");
            }
        }

        private static void TestMissing(
            List<BypassResult> found, RuleCollection c, Rule r, string rulePath,
            string target, ISet<string> targetSids, List<string> denyPaths)
        {
            // Walk up to the nearest existing ancestor; if the user can create there, they can
            // materialise the missing path and drop an executable that matches the rule.
            string ancestor = NearestExistingAncestor(target);
            if (ancestor == null)
                return;

            if (CanCreateDirectory(ancestor, targetSids) && !BlockedByDeny(target, denyPaths))
                Add(found, Severity.High, c, r, rulePath, target, "CREATE-MISSING",
                    "The allowed path does not exist yet, but the user can create it under " + ancestor + ".");
        }

        // --- ACL checks ---------------------------------------------------------------------
        private static bool CanCreateFile(string dir, ISet<string> sids)
        {
            FileSystemRights eff = EffectiveRights(dir, true, sids);
            return Has(eff, FileSystemRights.CreateFiles) || Has(eff, FileSystemRights.Write)
                   || Has(eff, FileSystemRights.Modify) || Has(eff, FileSystemRights.FullControl);
        }

        private static bool CanCreateDirectory(string dir, ISet<string> sids)
        {
            FileSystemRights eff = EffectiveRights(dir, true, sids);
            return Has(eff, FileSystemRights.CreateDirectories) || Has(eff, FileSystemRights.Write)
                   || Has(eff, FileSystemRights.Modify) || Has(eff, FileSystemRights.FullControl);
        }

        private static bool CanReplaceFile(string file, ISet<string> sids)
        {
            FileSystemRights eff = EffectiveRights(file, false, sids);
            if (Has(eff, FileSystemRights.WriteData) || Has(eff, FileSystemRights.Modify)
                || Has(eff, FileSystemRights.FullControl) || Has(eff, FileSystemRights.Delete))
                return true;

            // Or delete-and-recreate via the parent directory.
            string parent = Path.GetDirectoryName(file);
            if (parent != null && Directory.Exists(parent))
            {
                FileSystemRights p = EffectiveRights(parent, true, sids);
                if (Has(p, FileSystemRights.DeleteSubdirectoriesAndFiles) && CanCreateFile(parent, sids))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Approximate effective rights for the SID set: union of Allow rights minus union of Deny
        /// rights found in the DACL. Conservative (any matching deny removes the right).
        /// </summary>
        private static FileSystemRights EffectiveRights(string path, bool isDirectory, ISet<string> sids)
        {
            try
            {
                FileSystemSecurity sec = isDirectory
                    ? (FileSystemSecurity)new DirectoryInfo(path).GetAccessControl()
                    : new FileInfo(path).GetAccessControl();

                AuthorizationRuleCollection rules =
                    sec.GetAccessRules(true, true, typeof(SecurityIdentifier));

                FileSystemRights allow = 0;
                FileSystemRights deny = 0;

                foreach (AuthorizationRule ar in rules)
                {
                    FileSystemAccessRule fsr = ar as FileSystemAccessRule;
                    if (fsr == null)
                        continue;
                    if (!sids.Contains(fsr.IdentityReference.Value))
                        continue;

                    if (fsr.AccessControlType == AccessControlType.Allow)
                        allow |= fsr.FileSystemRights;
                    else
                        deny |= fsr.FileSystemRights;
                }

                return allow & ~deny;
            }
            catch
            {
                return 0;   // can't read the ACL -> treat as no access (conservative)
            }
        }

        private static bool Has(FileSystemRights value, FileSystemRights flag)
        {
            return (value & flag) == flag;
        }

        // --- path helpers -------------------------------------------------------------------
        private static bool BlockedByDeny(string dropPath, List<string> denyPaths)
        {
            string p = dropPath.ToUpperInvariant();
            foreach (string d in denyPaths)
            {
                string dd = d.ToUpperInvariant().TrimEnd('*').TrimEnd('\\');
                if (dd.Length > 0 && p.StartsWith(dd, StringComparison.Ordinal))
                    return true;
            }
            return false;
        }

        private static string FixedDirectoryOf(string expanded, bool wildcard)
        {
            if (!wildcard)
                return Path.GetDirectoryName(expanded) ?? expanded;

            int star = expanded.IndexOf('*');
            string head = expanded.Substring(0, star);
            int slash = head.LastIndexOf('\\');
            return slash >= 0 ? head.Substring(0, slash) : head;
        }

        private static string NearestExistingAncestor(string path)
        {
            string cur = path;
            // if it's a file-ish leaf, start from its directory
            if (!cur.EndsWith("\\") && Path.GetExtension(cur).Length > 0)
                cur = Path.GetDirectoryName(cur);

            while (!string.IsNullOrEmpty(cur))
            {
                if (Directory.Exists(cur))
                    return cur;
                string parent = Path.GetDirectoryName(cur.TrimEnd('\\'));
                if (parent == cur) break;
                cur = parent;
            }
            return null;
        }

        /// <summary>Expand AppLocker path macros to a concrete local path, or null if unknown.</summary>
        private static string ExpandMacros(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;

            string windir = Environment.GetEnvironmentVariable("windir") ?? @"C:\Windows";
            string sysDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
            string pf = Environment.GetEnvironmentVariable("ProgramFiles") ?? @"C:\Program Files";
            string programData = Environment.GetEnvironmentVariable("ProgramData") ?? @"C:\ProgramData";

            string p = path;
            p = ReplaceCi(p, "%WINDIR%", windir);
            p = ReplaceCi(p, "%SYSTEM32%", windir + @"\System32");
            p = ReplaceCi(p, "%OSDRIVE%", sysDrive);
            p = ReplaceCi(p, "%PROGRAMFILES%", pf);
            p = ReplaceCi(p, "%PROGRAMDATA%", programData);

            if (p.IndexOf('%') >= 0)
                return null;   // some macro we don't expand (e.g. %REMOVABLE% handled earlier)

            return p;
        }

        private static string ReplaceCi(string input, string token, string replacement)
        {
            int idx = input.IndexOf(token, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return input;
            return input.Substring(0, idx) + replacement + input.Substring(idx + token.Length);
        }

        private static bool Applies(Rule r, ISet<string> targetSids)
        {
            return r.Sid != null && targetSids.Contains(r.Sid);
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

        private static void Add(List<BypassResult> list, Severity sev, RuleCollection c, Rule r,
            string rulePath, string dropPath, string kind, string detail)
        {
            list.Add(new BypassResult
            {
                Severity = sev,
                Collection = c.Type,
                RuleId = r.Id,
                RuleName = string.IsNullOrEmpty(r.Name) ? "(unnamed)" : r.Name,
                RulePath = rulePath,
                DropPath = dropPath,
                Kind = kind,
                Detail = detail
            });
        }
    }
}