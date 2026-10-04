using System;
using System.Collections.Generic;
using Mono.Options;
using SharpAppLocker.Analysis;
using SharpAppLocker.Output;
using SharpAppLocker.Sources;

/*
 * Feature TODO List
 * Parse and display rules from COM                                  [done]
 * Parse and display rules from files                                [done]
 * Support ability to look at files extracted from another system    [done: --mode file --dir]
 * Filter by ruleset type                                            [done: --collection]
 * Filter by allow / deny
 * Identify all related to current user (user, or groups, etc)       [done: --me]
 * Identify rules related to a specific SID / principal              [done: --sid / --applies-to]
 * Identify potential global bypasses
 * Identify potentially weak rules ( *s, stuff in writable paths)
 * Test for bypasses locally
 */

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

            OptionSet options = new OptionSet()
                .Add("m|mode=", "com|file (default: com)", v => mode = v)
                .Add("c|collection=", "all|exe|msi|script|dll|appx (default: all)", v => collection = v)
                .Add("s|sid=", "exact: only rules targeting this SID/account", v => sid = v)
                .Add("me", "filter to rules that apply to the current user (incl. groups)", v => forMe = v != null)
                .Add("applies-to=", "filter to rules that apply to this user/group (expands groups)", v => appliesTo = v)
                .Add("r|raw", "dump raw XML (com) / records (file) and exit", v => raw = v != null)
                .Add("h|help", "show this help and exit", v => help = v != null)
                // com mode
                .Add("scope=", "com: effective|local|domain (default: effective)", v => scope = v)
                .Add("ldap=", "com: LDAP path (required for --scope domain)", v => ldap = v)
                // file mode
                .Add("dir=", "file: folder of .AppLocker files (default: %WINDIR%\\System32\\AppLocker)", v => dir = v)
                .Add("enforcement-from-registry", "file: read EnforcementMode from the registry (default off; it's not stored in the .AppLocker file)", v => enforcementFromRegistry = v != null);

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

                ISet<string> matchSids = null;
                if (forMe)
                    matchSids = PrincipalResolver.CurrentUser();
                else if (appliesTo != null)
                    matchSids = PrincipalResolver.ForPrincipal(appliesTo);
                else if (sid != null)
                    matchSids = PrincipalResolver.Exact(sid);

                PolicyPrinter.Print(source.Load(), collection, matchSids);
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