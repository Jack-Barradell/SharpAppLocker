using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using SharpAppLockerAudit.Model;

namespace SharpAppLockerAudit.Analysis
{
    internal sealed class BypassResult
    {
        public Severity Severity;
        public string Collection;
        public Guid RuleId;
        public string RuleName;
        public string RulePath;
        public string DropPath;
        public string Kind;
        public string Detail;
    }
    
    internal static class BypassTester
    {
        private static readonly char[] WildcardChars = { '*', '?' };
        
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
                
                List<string> denyPaths = c.Rules
                    .Where(r => r.Action == "Deny" && r.Kind == "FilePathRule" && Applies(r, targetSids))
                    .SelectMany(r => r.Inclusions.Select(PathValue))
                    .Where(p => !string.IsNullOrEmpty(p))
                    .SelectMany(ExpandMacros)
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
        
        private static IEnumerable<BypassResult> TestRulePath(
            RuleCollection c, Rule r, string rulePath, ISet<string> targetSids, List<string> denyPaths)
        {
            List<BypassResult> found = new List<BypassResult>();

            string upper = rulePath.ToUpperInvariant();
            if (upper.Contains("%REMOVABLE%") || upper.Contains("%HOT%"))
            {
                Add(found, Severity.Medium, c, r, rulePath, rulePath, "REMOVABLE-MEDIA",
                    "Allows execution from removable/hot-plug media, which the user fully controls.");
                return found;
            }
            
            foreach (string expanded in ExpandMacros(rulePath))
                TestExpandedPath(found, c, r, rulePath, expanded, targetSids, denyPaths);

            return found;
        }

        private static void TestExpandedPath(
            List<BypassResult> found, RuleCollection c, Rule r, string rulePath,
            string expanded, ISet<string> targetSids, List<string> denyPaths)
        {
            bool wildcard = HasWildcard(expanded);

            if (!wildcard)
            {
                if (File.Exists(expanded))
                {
                    if (CanReplaceFile(expanded, targetSids) && !BlockedByDeny(expanded, denyPaths))
                        Add(found, Severity.High, c, r, rulePath, expanded, "REPLACE-EXISTING",
                            "The allowed file exists and the user can overwrite/replace it.");
                }
                else
                {
                    TestMissing(found, c, r, rulePath, expanded, true, targetSids, denyPaths);
                }
                return;
            }
            
            string fixedDir = FixedDirectoryOf(expanded);
            bool recursive = expanded.TrimEnd('\\').EndsWith(@"\*", StringComparison.Ordinal);

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
                TestMissing(found, c, r, rulePath, fixedDir, false, targetSids, denyPaths);
            }
        }

        private static void TestKnownWritableSubdirs(
            List<BypassResult> found, RuleCollection c, Rule r, string rulePath,
            string baseDir, ISet<string> targetSids, List<string> denyPaths)
        {
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
            string target, bool targetIsFile, ISet<string> targetSids, List<string> denyPaths)
        {
            string ancestor = NearestExistingAncestor(target);
            if (ancestor == null)
                return;

            if (BlockedByDeny(target, denyPaths))
                return;

            string parent = Path.GetDirectoryName(target.TrimEnd('\\'));
            bool directParent = parent != null &&
                                ancestor.TrimEnd('\\').Equals(parent.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);

            if (targetIsFile && directParent)
            {
                if (CanCreateFile(ancestor, targetSids))
                    Add(found, Severity.High, c, r, rulePath, target, "CREATE-MISSING-FILE",
                        "The allowed file does not exist, but the user can create it directly in " + ancestor + ".");
            }
            else
            {
                if (CanCreateDirectory(ancestor, targetSids))
                    Add(found, Severity.High, c, r, rulePath, target, "CREATE-MISSING",
                        "The allowed path does not exist yet, but the user can create it under " + ancestor + ".");
            }
        }
        
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
            
            string parent = Path.GetDirectoryName(file);
            if (parent != null && Directory.Exists(parent))
            {
                FileSystemRights p = EffectiveRights(parent, true, sids);
                if (Has(p, FileSystemRights.DeleteSubdirectoriesAndFiles) && CanCreateFile(parent, sids))
                    return true;
            }
            return false;
        }
        
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
                return 0;
            }
        }

        private static bool Has(FileSystemRights value, FileSystemRights flag)
        {
            return (value & flag) == flag;
        }
        
        private static bool HasWildcard(string s)
        {
            return s.IndexOfAny(WildcardChars) >= 0;
        }

        private static bool BlockedByDeny(string dropPath, List<string> denyPaths)
        {
            string p = dropPath.ToUpperInvariant();
            foreach (string d in denyPaths)
            {
                string dd = d.ToUpperInvariant().TrimEnd('*', '?').TrimEnd('\\');
                if (dd.Length > 0 && p.StartsWith(dd, StringComparison.Ordinal))
                    return true;
            }
            return false;
        }

        private static string FixedDirectoryOf(string expanded)
        {
            int star = expanded.IndexOfAny(WildcardChars);
            if (star < 0)
                return Path.GetDirectoryName(expanded) ?? expanded;

            string head = expanded.Substring(0, star);
            int slash = head.LastIndexOf('\\');
            return slash >= 0 ? head.Substring(0, slash) : head;
        }

        private static string NearestExistingAncestor(string path)
        {
            string cur = path;
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
        
        private static List<string> ExpandMacros(string path)
        {
            List<string> results = new List<string>();
            if (string.IsNullOrEmpty(path))
                return results;

            string windir = Environment.GetEnvironmentVariable("windir") ?? @"C:\Windows";
            string sysDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
            string pf64 = Environment.GetEnvironmentVariable("ProgramW6432")
                          ?? Environment.GetEnvironmentVariable("ProgramFiles") ?? @"C:\Program Files";
            string pf86 = Environment.GetEnvironmentVariable("ProgramFiles(x86)");
            
            string p = path;
            p = ReplaceCi(p, "%SYSTEM32%", windir + @"\System32");
            p = ReplaceCi(p, "%WINDIR%", windir);
            p = ReplaceCi(p, "%OSDRIVE%", sysDrive);
            
            if (ContainsCi(p, "%PROGRAMFILES%"))
            {
                List<string> pfs = new List<string> { pf64 };
                if (!string.IsNullOrEmpty(pf86) && !pf86.Equals(pf64, StringComparison.OrdinalIgnoreCase))
                    pfs.Add(pf86);

                foreach (string pf in pfs)
                {
                    string q = ReplaceCi(p, "%PROGRAMFILES%", pf);
                    if (q.IndexOf('%') < 0)
                        results.Add(q);
                }
            }
            else if (p.IndexOf('%') < 0)
            {
                results.Add(p);
            }

            return results;
        }

        private static bool ContainsCi(string input, string token)
        {
            return input.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0;
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