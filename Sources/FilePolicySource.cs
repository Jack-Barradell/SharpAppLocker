using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using SharpAppLocker.Interop;
using SharpAppLocker.Model;

namespace SharpAppLocker.Sources
{
    internal sealed class FilePolicySource : IPolicySource
    {
        private const string SrpV2Key = @"SOFTWARE\Policies\Microsoft\Windows\SrpV2";

        private static readonly Regex GuidRx = new Regex(
            @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            RegexOptions.Compiled);

        private readonly string _dir;
        private readonly bool _useRegistry;

        public FilePolicySource(string dir, bool useRegistry)
        {
            _dir = dir;
            _useRegistry = useRegistry;
        }
        
        public string LoadXml()
        {
            StringBuilder sb = new StringBuilder();
            foreach (string file in EnumerateFiles())
            {
                sb.AppendLine("==== " + Path.GetFileName(file) + " ====");
                string text = ReadUtf16(file);
                foreach (Record rec in ReadRecords(text))
                {
                    sb.AppendLine(rec.Id + "  " + rec.Name);
                    sb.AppendLine("    " + rec.Sddl);
                }
                sb.AppendLine();
            }
            return sb.ToString();
        }
        
        public PolicyDocument Load()
        {
            PolicyDocument doc = new PolicyDocument { Version = "1 (from file)" };

            foreach (string file in EnumerateFiles())
            {
                string type = Path.GetFileNameWithoutExtension(file);
                RuleCollection collection = new RuleCollection
                {
                    Type = type,
                    EnforcementMode = ReadEnforcementMode(type)
                };

                try
                {
                    string text = ReadUtf16(file);
                    foreach (Record rec in ReadRecords(text))
                        collection.Rules.Add(BuildRule(rec));
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("[!] " + Path.GetFileName(file) + ": " + e.Message);
                }

                doc.Collections.Add(collection);
            }
            return doc;
        }
        
        private IEnumerable<string> EnumerateFiles()
        {
            if (!Directory.Exists(_dir))
                throw new DirectoryNotFoundException("AppLocker folder not found: " + _dir);

            string[] files = Directory.GetFiles(_dir, "*.AppLocker");
            if (files.Length == 0)
                Console.Error.WriteLine("[!] no *.AppLocker files in " + _dir);
            return files;
        }

        private static string ReadUtf16(string file)
        {
            return Encoding.Unicode.GetString(File.ReadAllBytes(file));
        }
        
        private sealed class Record
        {
            public string Id;
            public string Sddl;
            public string Name;
        }

        private static IEnumerable<Record> ReadRecords(string text)
        {
            List<Record> records = new List<Record>();
            MatchCollection guids = GuidRx.Matches(text);

            for (int i = 0; i < guids.Count; i++)
            {
                int start = guids[i].Index;
                string id = text.Substring(start, 36);
                int end = (i + 1 < guids.Count) ? guids[i + 1].Index : text.Length;
                string chunk = text.Substring(start + 36, end - (start + 36));

                string sddl, name;
                SplitSddlAndName(chunk, out sddl, out name);
                if (sddl == null)
                    continue;   // not a rule record

                records.Add(new Record { Id = id, Sddl = sddl, Name = name });
            }
            return records;
        }
        
        private static void SplitSddlAndName(string chunk, out string sddl, out string name)
        {
            sddl = null;
            name = chunk.Trim();

            int i = chunk.IndexOf("D:(", StringComparison.Ordinal);
            if (i < 0)
                return;

            int depth = 0;
            bool inQuote = false;
            int k = i + 2;   // at the '('
            for (; k < chunk.Length; k++)
            {
                char c = chunk[k];
                if (c == '"') inQuote = !inQuote;
                else if (c == '(' && !inQuote) depth++;
                else if (c == ')' && !inQuote)
                {
                    depth--;
                    if (depth == 0) { k++; break; }
                }
            }

            sddl = chunk.Substring(i, k - i);
            string rest = chunk.Substring(k);

            int cut = rest.IndexOf("Applocker Private", StringComparison.OrdinalIgnoreCase);
            if (cut >= 0)
                rest = rest.Substring(0, cut);

            name = rest.Trim();
        }
        
        private static Rule BuildRule(Record rec)
        {
            string inner = rec.Sddl;
            int lp = inner.IndexOf('(');
            if (lp >= 0 && inner.EndsWith(")"))
                inner = inner.Substring(lp + 1, inner.Length - lp - 2);

            List<string> f = SplitFields(inner);
            string action = AceTypeToAction(f.Count > 0 ? f[0] : "");
            string sidToken = f.Count >= 6 ? f[5] : "";
            string condition = f.Count >= 7 ? StripOneOuterParen(f[6]) : "";

            Guid id;
            Guid.TryParse(rec.Id, out id);

            Rule rule = new Rule
            {
                Kind = KindFromCondition(condition),
                Id = id,
                Name = rec.Name,
                Description = "",
                Sid = NativeMethods.NormaliseSid(sidToken),
                Action = action ?? "?"
            };

            List<string> inc, exc;
            SplitCondition(condition, out inc, out exc);
            foreach (string c in inc)
                rule.Inclusions.Add(new Condition { Kind = "SddlCondition", Summary = c });
            foreach (string c in exc)
                rule.Exclusions.Add(new Condition { Kind = "SddlCondition", Summary = c });

            return rule;
        }
        
        private static List<string> SplitFields(string ace)
        {
            List<string> fields = new List<string>();
            StringBuilder sb = new StringBuilder();
            int depth = 0;
            bool inQuote = false;

            foreach (char c in ace)
            {
                if (c == '"') inQuote = !inQuote;

                if (c == '(' && !inQuote) depth++;
                else if (c == ')' && !inQuote) depth--;

                if (c == ';' && depth == 0 && !inQuote)
                {
                    fields.Add(sb.ToString());
                    sb.Length = 0;
                }
                else
                {
                    sb.Append(c);
                }
            }
            fields.Add(sb.ToString());
            return fields;
        }
        
        private static void SplitCondition(string cond, out List<string> inclusions, out List<string> exclusions)
        {
            inclusions = new List<string>();
            exclusions = new List<string>();
            if (string.IsNullOrEmpty(cond))
                return;

            foreach (string raw in SplitTopLevelAnd(cond))
            {
                string p = raw.Trim();
                p = StripMatchedOuterParens(p);

                if (p.StartsWith("!"))
                {
                    string inner = StripMatchedOuterParens(p.Substring(1).Trim());
                    exclusions.Add(inner.Trim());
                }
                else if (p.Length > 0)
                {
                    inclusions.Add(p.Trim());
                }
            }
        }

        private static IEnumerable<string> SplitTopLevelAnd(string s)
        {
            List<string> parts = new List<string>();
            StringBuilder sb = new StringBuilder();
            int depth = 0;
            bool inQuote = false;

            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '"') inQuote = !inQuote;
                else if (c == '(' && !inQuote) depth++;
                else if (c == ')' && !inQuote) depth--;

                if (!inQuote && depth == 0 && c == '&' && i + 1 < s.Length && s[i + 1] == '&')
                {
                    parts.Add(sb.ToString());
                    sb.Length = 0;
                    i++;
                    continue;
                }
                sb.Append(c);
            }
            parts.Add(sb.ToString());
            return parts;
        }
        
        private static string StripMatchedOuterParens(string s)
        {
            s = s.Trim();
            if (s.Length < 2 || s[0] != '(' || s[s.Length - 1] != ')')
                return s;

            int depth = 0;
            bool inQuote = false;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '"') inQuote = !inQuote;
                else if (c == '(' && !inQuote) depth++;
                else if (c == ')' && !inQuote)
                {
                    depth--;
                    if (depth == 0 && i != s.Length - 1)
                        return s;
                }
            }
            return s.Substring(1, s.Length - 2).Trim();
        }

        private static string StripOneOuterParen(string s)
        {
            return StripMatchedOuterParens(s.Trim());
        }

        private static string AceTypeToAction(string aceType)
        {
            switch (aceType)
            {
                case "XA": case "A": return "Allow";
                case "XD": case "D": return "Deny";
                default: return null;
            }
        }

        private static string KindFromCondition(string condition)
        {
            string c = condition.ToUpperInvariant();
            if (c.Contains("APPID://PATH")) return "FilePathRule";
            if (c.Contains("APPID://FQBN")) return "FilePublisherRule";
            if (c.Contains("HASH")) return "FileHashRule";
            return "UnknownRule";
        }
        
        private string ReadEnforcementMode(string collectionType)
        {
            if (!_useRegistry)
                return "Unknown (not stored in .AppLocker; Use --enforcement-from-registry to read it)";

            try
            {
                RegistryView view = Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default;
                using (RegistryKey hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
                using (RegistryKey key = hklm.OpenSubKey(SrpV2Key + "\\" + collectionType))
                {
                    if (key == null)
                        return "Unknown (registry key not found)";

                    object raw = key.GetValue("EnforcementMode");
                    if (raw == null) return "NotConfigured (registry)";
                    if (raw is int && (int)raw == 0) return "AuditOnly (registry)";
                    if (raw is int && (int)raw == 1) return "Enabled (registry)";
                    return "Unknown(" + raw + ") (registry)";
                }
            }
            catch
            {
                return "Unknown (registry unreadable)";
            }
        }
    }
}