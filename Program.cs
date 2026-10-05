using System;
using System.Collections.Generic;
using Mono.Options;
using SharpAppLocker.Analysis;
using SharpAppLocker.Model;
using SharpAppLocker.Output;
using SharpAppLocker.Sources;

namespace SharpAppLocker
{
    internal class Program
    {
        private static void PrintUsage(OptionSet options)
        {
            options.WriteOptionDescriptions(Console.Out);
        }

        [STAThread]
        public static void Main(string[] args)
        {
            string mode       = "com";
            string collection = null;
            bool   raw        = false;
            string sid        = null;
            bool   forMe      = false;
            string appliesTo  = null;
            bool   help       = false;
            string scope      = "effective";
            string ldap       = null;
            string dir        = @"C:\Windows\System32\AppLocker";
            bool   enforcementFromRegistry = false;
            bool   audit      = false;
            bool   testBypass = false;
            string action     = null;
            bool   json       = false;

            OptionSet options = new OptionSet()
                .Add("m|mode=", "com|file (default: com)", v => mode = v)
                .Add("c|collection=", "all|exe|msi|script|dll|appx (default: all)", v => collection = v)
                .Add("s|sid=", "exact: only rules targeting this SID/account", v => sid = v)
                .Add("me", "filter to rules that apply to the current user (incl. groups)", v => forMe = v != null)
                .Add("applies-to=", "filter to rules that apply to this user/group (expands groups)", v => appliesTo = v)
                .Add("a|action=", "listing filter: allow|deny (default: both)", v => action = v)
                .Add("r|raw", "dump raw XML (com) / records (file) and exit", v => raw = v != null)
                .Add("json", "emit machine-readable JSON instead of text", v => json = v != null)
                .Add("h|help", "show this help and exit", v => help = v != null)
                // com mode
                .Add("scope=", "com: effective|local|domain (default: effective)", v => scope = v)
                .Add("ldap=", "com: LDAP path (required for --scope domain)", v => ldap = v)
                // file mode
                .Add("dir=", "file: folder of .AppLocker files (default: %WINDIR%\\System32\\AppLocker)", v => dir = v)
                .Add("enforcement-from-registry", "file: read EnforcementMode from the registry (default off; it's not stored in the .AppLocker file)", v => enforcementFromRegistry = v != null)
                // analysis
                .Add("audit", "review the policy for weak rules / bypass surface and exit", v => audit = v != null)
                .Add("test-bypass", "test whether allowed locations are actually user-writable (local fs ACLs) and exit", v => testBypass = v != null);

            try
            {
                options.Parse(args);

                if (help)
                {
                    PrintUsage(options);
                    return;
                }

                if (mode != "com" && mode != "file")
                    throw new OptionException("--mode must be 'com' or 'file'", "mode");

                if (mode == "com" && scope == "domain" && string.IsNullOrEmpty(ldap))
                    throw new OptionException("--scope domain requires --ldap", "ldap");

                if (mode == "file" && scope != "effective")
                    Console.Error.WriteLine("note: --scope is ignored in file mode");

                int principalOpts = (forMe ? 1 : 0) + (appliesTo != null ? 1 : 0) + (sid != null ? 1 : 0);
                if (principalOpts > 1)
                    throw new OptionException("use only one of --me, --applies-to, --sid", "me");

                if (action != null && !action.Equals("allow", StringComparison.OrdinalIgnoreCase)
                                   && !action.Equals("deny", StringComparison.OrdinalIgnoreCase))
                    throw new OptionException("--action must be 'allow' or 'deny'", "action");
            }
            catch (OptionException e)
            {
                Console.WriteLine("[!] Failed to parse arguments: {0}", e.Message);
                PrintUsage(options);
                return;
            }

            if (string.Equals(collection, "all", StringComparison.OrdinalIgnoreCase))
                collection = null;

            try
            {
                IPolicySource source = BuildSource(mode, scope, ldap, dir, enforcementFromRegistry);

                if (raw)
                {
                    Console.WriteLine(source.LoadXml());
                    return;
                }

                if (audit)
                {
                    List<Finding> findings = PolicyAnalyser.Analyse(source.Load(), collection);
                    if (json) JsonPrinter.PrintFindings(findings);
                    else FindingsPrinter.Print(findings);
                    return;
                }

                if (testBypass)
                {
                    ISet<string> who = appliesTo != null ? PrincipalResolver.ForPrincipal(appliesTo)
                                     : sid != null       ? PrincipalResolver.Exact(sid)
                                     :                      PrincipalResolver.CurrentUser();
                    List<BypassResult> hits = BypassTester.Test(source.Load(), collection, who);
                    if (json) JsonPrinter.PrintBypass(hits);
                    else BypassPrinter.Print(hits);
                    return;
                }

                ISet<string> matchSids = null;
                if (forMe)
                    matchSids = PrincipalResolver.CurrentUser();
                else if (appliesTo != null)
                    matchSids = PrincipalResolver.ForPrincipal(appliesTo);
                else if (sid != null)
                    matchSids = PrincipalResolver.Exact(sid);

                PolicyDocument loaded = source.Load();
                if (json) JsonPrinter.PrintPolicy(loaded, collection, matchSids, action);
                else PolicyPrinter.Print(loaded, collection, matchSids, action);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[!] {0}: {1}", e.GetType().Name, e.Message);
            }
        }

        private static IPolicySource BuildSource(string mode, string scope, string ldap, string dir, bool enforcementFromRegistry)
        {
            switch (mode)
            {
                case "com":
                    return new ComPolicySource(scope, ldap);
                case "file":
                    return new FilePolicySource(dir, enforcementFromRegistry);
                default:
                    throw new OptionException("Unknown mode: " + mode, "mode");
            }
        }
    }
}