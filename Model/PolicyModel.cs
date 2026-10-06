using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Xml.Linq;

namespace SharpAppLockerAudit.Model
{
    internal sealed class PolicyDocument
    {
        public string Version;
        public List<RuleCollection> Collections = new List<RuleCollection>();
    }

    internal sealed class RuleCollection
    {
        public string Type;
        public string EnforcementMode;
        public List<Rule> Rules = new List<Rule>();
    }

    internal sealed class Rule
    {
        public string Kind;
        public Guid Id;
        public string Name;
        public string Description;
        public string Sid;
        public string Action;
        public List<Condition> Inclusions = new List<Condition>();
        public List<Condition> Exclusions = new List<Condition>();
    }

    internal sealed class Condition
    {
        public string Kind;
        public string Summary;
    }

    internal static class PolicyParser
    {
        public static PolicyDocument Parse(string xml)
        {
            XDocument doc = XDocument.Parse(xml);
            if (doc.Root == null)
                throw new InvalidDataException("Empty policy XML.");

            PolicyDocument result = new PolicyDocument { Version = Attr(doc.Root, "Version") ?? "?" };

            foreach (XElement rc in doc.Root.Elements().Where(e => e.Name.LocalName == "RuleCollection"))
            {
                RuleCollection collection = new RuleCollection
                {
                    Type = Attr(rc, "Type") ?? "?",
                    EnforcementMode = Attr(rc, "EnforcementMode") ?? "NotConfigured"
                };

                foreach (XElement r in rc.Elements().Where(e => e.Name.LocalName.EndsWith("Rule")))
                    collection.Rules.Add(ParseRule(r));

                result.Collections.Add(collection);
            }
            return result;
        }

        private static Rule ParseRule(XElement r)
        {
            Guid id;
            Guid.TryParse(Attr(r, "Id"), out id);

            Rule rule = new Rule
            {
                Kind = r.Name.LocalName,
                Id = id,
                Name = Attr(r, "Name") ?? "",
                Description = Attr(r, "Description") ?? "",
                Sid = Attr(r, "UserOrGroupSid") ?? "",
                Action = Attr(r, "Action") ?? ""
            };

            XElement conditions = Child(r, "Conditions");
            if (conditions != null)
                foreach (XElement c in conditions.Elements())
                    rule.Inclusions.Add(ParseCondition(c));

            XElement exceptions = Child(r, "Exceptions");
            if (exceptions != null)
                foreach (XElement c in exceptions.Elements())
                    rule.Exclusions.Add(ParseCondition(c));

            return rule;
        }

        private static Condition ParseCondition(XElement c)
        {
            string summary;
            switch (c.Name.LocalName)
            {
                case "FilePathCondition":
                    summary = "Path: " + Attr(c, "Path");
                    break;
                case "FilePublisherCondition":
                    XElement range = Child(c, "BinaryVersionRange");
                    summary = "Publisher: " + Attr(c, "PublisherName") +
                              " | Product: " + Attr(c, "ProductName") +
                              " | Binary: " + Attr(c, "BinaryName") +
                              " | Version: " + (range == null ? "*" : Attr(range, "LowSection") + " - " + Attr(range, "HighSection"));
                    break;
                case "FileHashCondition":
                    XElement hash = Child(c, "FileHash");
                    summary = hash == null
                        ? "(hash)"
                        : Attr(hash, "Type") + " " + Attr(hash, "Data") + " (" + Attr(hash, "SourceFileName") + ")";
                    break;
                default:
                    summary = c.Name.LocalName;
                    break;
            }
            return new Condition { Kind = c.Name.LocalName, Summary = summary };
        }

        private static string Attr(XElement e, string name)
        {
            XAttribute a = e.Attribute(name);
            return a == null ? null : a.Value;
        }

        private static XElement Child(XElement e, string localName)
        {
            return e.Elements().FirstOrDefault(c => c.Name.LocalName == localName);
        }
    }

    internal static class Sid
    {
        // SID -> display string. Caches both successes and failures so an unresolvable domain SID
        // doesn't incur a DC lookup/timeout more than once per run. Single-threaded CLI, so a plain
        // Dictionary is fine.
        private static readonly Dictionary<string, string> DescribeCache =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public static string Describe(string sid)
        {
            if (string.IsNullOrEmpty(sid)) return sid;

            string cached;
            if (DescribeCache.TryGetValue(sid, out cached))
                return cached;

            string result;
            try
            {
                string name = new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
                result = name + " (" + sid + ")";
            }
            catch
            {
                result = sid;
            }

            DescribeCache[sid] = result;
            return result;
        }

        // Accepts a SID or an account name ("DOMAIN\user", "Everyone") -> canonical SID string.
        public static string Resolve(string userOrSid)
        {
            if (userOrSid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
                return new SecurityIdentifier(userOrSid).Value;
            return ((SecurityIdentifier)new NTAccount(userOrSid).Translate(typeof(SecurityIdentifier))).Value;
        }
    }
}