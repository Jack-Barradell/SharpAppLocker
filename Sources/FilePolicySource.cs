using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using SharpAppLocker.Interop;
using SharpAppLocker.Model;

namespace SharpAppLocker.Sources
{
    internal sealed class FilePolicySource : IPolicySource
    {
        private const int SdOffsetLocation = 16;   // DWORD at this offset = file offset of the SD

        private readonly string _dir;

        public FilePolicySource(string dir)
        {
            _dir = dir;
        }
        
        public string LoadXml()
        {
            StringBuilder sb = new StringBuilder();
            foreach (string file in EnumerateFiles())
            {
                sb.AppendLine("==== " + Path.GetFileName(file) + " ====");
                byte[] bytes = File.ReadAllBytes(file);
                sb.AppendLine("header: " + HexDump(bytes, 0, Math.Min(32, bytes.Length)));
                try
                {
                    sb.AppendLine(ExtractSddl(bytes));
                }
                catch (Exception e)
                {
                    sb.AppendLine("  [!] could not extract SDDL: " + e.Message);
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
                RuleCollection collection = new RuleCollection
                {
                    Type = CollectionTypeFromFileName(file),
                    EnforcementMode = "Unknown (not decoded from file header yet)"
                };

                try
                {
                    byte[] bytes = File.ReadAllBytes(file);
                    string sddl = ExtractSddl(bytes);
                    foreach (Rule r in ParseAces(sddl))
                        collection.Rules.Add(r);
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

            // The live OS names them <Collection>.AppLocker; copied-off files keep that name.
            string[] files = Directory.GetFiles(_dir, "*.AppLocker");
            if (files.Length == 0)
                Console.Error.WriteLine("[!] no *.AppLocker files in " + _dir);
            return files;
        }

        private static string CollectionTypeFromFileName(string path)
        {
            // Exe.AppLocker -> Exe
            return Path.GetFileNameWithoutExtension(path);
        }
        
        private static string ExtractSddl(byte[] bytes)
        {
            if (bytes.Length < SdOffsetLocation + 4)
                throw new InvalidDataException("file too small to contain an SD offset");

            int sdOffset = BitConverter.ToInt32(bytes, SdOffsetLocation);
            if (sdOffset <= 0 || sdOffset >= bytes.Length)
                throw new InvalidDataException("SD offset out of range: " + sdOffset);

            // SD revision byte sanity check (self-relative SD starts with revision 0x01).
            if (bytes[sdOffset] != 0x01)
                throw new InvalidDataException(
                    "byte at SD offset is 0x" + bytes[sdOffset].ToString("X2") + ", expected 0x01");

            // Copy from the SD offset to the end; the converter reads only what it needs.
            int len = bytes.Length - sdOffset;
            byte[] sd = new byte[len];
            Array.Copy(bytes, sdOffset, sd, 0, len);

            return NativeMethods.SecurityDescriptorToSddl(sd);
        }
        
        private static IEnumerable<Rule> ParseAces(string sddl)
        {
            List<Rule> rules = new List<Rule>();

            // sddl looks like: D:ARAI(XA;;0x1fffffff;;;WD;(Exists APPID://PATH ...))(XD;;...)...
            foreach (string aceBody in SplitTopLevelGroups(DaclPortion(sddl)))
            {
                List<string> f = SplitFields(aceBody);
                if (f.Count < 6)
                    continue;

                string aceType = f[0];
                string action = AceTypeToAction(aceType);
                if (action == null)
                    continue;   // not an allow/deny rule ACE (e.g. audit)

                string sidToken = f[5];
                string condition = f.Count >= 7 ? StripOuterParens(f[6]) : "";

                rules.Add(new Rule
                {
                    Kind = KindFromCondition(condition),
                    Id = Guid.Empty,                 // not stored in the compiled form
                    Name = "",                       // names are stripped on compilation
                    Description = "",
                    Sid = NativeMethods.NormaliseSid(sidToken),
                    Action = action,
                    Inclusions = { new Condition { Kind = "SddlCondition", Summary = condition } }
                });
            }
            return rules;
        }

        private static string DaclPortion(string sddl)
        {
            // Trim anything before "D:"; we only requested the DACL so this is usually the whole string.
            int d = sddl.IndexOf("D:", StringComparison.Ordinal);
            return d < 0 ? sddl : sddl.Substring(d + 2);
        }
        
        private static IEnumerable<string> SplitTopLevelGroups(string s)
        {
            List<string> groups = new List<string>();
            int i = 0;
            while (i < s.Length)
            {
                if (s[i] != '(') { i++; continue; }

                int depth = 0;
                int start = i;
                bool inQuote = false;
                for (; i < s.Length; i++)
                {
                    char c = s[i];
                    if (c == '"') inQuote = !inQuote;
                    else if (c == '(' && !inQuote) depth++;
                    else if (c == ')' && !inQuote)
                    {
                        depth--;
                        if (depth == 0) { i++; break; }
                    }
                }

                groups.Add(s.Substring(start + 1, (i - 1) - (start + 1)));
            }
            return groups;
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

        private static string AceTypeToAction(string aceType)
        {
            switch (aceType)
            {
                case "XA":   // SDDL_CALLBACK_ACCESS_ALLOWED
                case "A":    // plain allow (shouldn't occur for AppLocker, handled for safety)
                    return "Allow";
                case "XD":   // SDDL_CALLBACK_ACCESS_DENIED
                case "D":
                    return "Deny";
                default:
                    return null;
            }
        }

        private static string KindFromCondition(string condition)
        {
            string c = condition.ToUpperInvariant();
            if (c.Contains("APPID://PATH")) return "FilePathRule";
            if (c.Contains("APPID://FQBN")) return "FilePublisherRule";
            if (c.Contains("HASH")) return "FileHashRule";   // SHA256HASH / SHA1HASH / SHA256FLATHASH
            return "UnknownRule";
        }

        private static string StripOuterParens(string s)
        {
            s = s.Trim();
            if (s.Length >= 2 && s[0] == '(' && s[s.Length - 1] == ')')
                return s.Substring(1, s.Length - 2);
            return s;
        }

        private static string HexDump(byte[] bytes, int offset, int count)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = offset; i < offset + count; i++)
                sb.Append(bytes[i].ToString("X2")).Append(' ');
            return sb.ToString().TrimEnd();
        }
    }
}