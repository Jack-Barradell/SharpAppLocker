using System;
using System.Collections.Generic;
using Mono.Options;
using SharpAppLocker.Sources;
using SharpAppLocker.Output;

/*
 * Feature TODO List
 * Parse and display rules from COM
 * Parse and display rules from files
 * Support ability to look at files directly where theyve been extracted from another system
 * Filter by ruleset type
 * Filter by allow / deny
 * Identify all related to current user (user, or groups, etc)
 * Identify rules related to a specific SID
 * Identify potential global bypasses
 * Identify potentially weak rules ( *s, stuff in generally writable paths)
 * Test for bypasses locally 
 * 
 */

namespace SharpAppLocker
{
    internal class Program
    {

        static void PrintUsage(OptionSet options)
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
            bool   help       = false;
            string scope      = "effective";
            string ldap       = null;
            string dir        = @"C:\Windows\System32\AppLocker";

            OptionSet options = new OptionSet()
                .Add("m|mode=", "com|file (default: com)", v => mode = v)
                .Add("c|collection=", "all|exe|msi|script|dll|appx (default: all)", v => collection = v)
                .Add("s|sid=", "only rules for this SID or account", v => sid = v)
                .Add("r|raw", "dump raw XML (com) / SDDL (file) and exit", v => raw = v != null)
                .Add("h|help", "show this help and exit", v => help = v != null)
                .Add("scope=", "com: effective|local|domain (default: effective)", v => scope = v)
                .Add("ldap=", "com: LDAP path (required for --scope domain)", v => ldap = v)
                .Add("dir=", "file: folder of .AppLocker files (default: %WINDIR%\\System32\\AppLocker)", v => dir = v);

            // --- parse + validate ---
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
            }
            catch (OptionException e)
            {
                Console.WriteLine("[!] Failed to parse arguments: {0}", e.Message);
                PrintUsage(options);
                return;
            }

            // "all" means no filter; the printer expects null for that.
            if (string.Equals(collection, "all", StringComparison.OrdinalIgnoreCase))
                collection = null;

            // --- run ---
            try
            {
                IPolicySource source = BuildSource(mode, scope, ldap, dir);

                if (raw)
                {
                    Console.WriteLine(source.LoadXml());
                    return;
                }

                PolicyPrinter.Print(source.Load(), collection, sid);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[!] {0}: {1}", e.GetType().Name, e.Message);
            }
        }

        private static IPolicySource BuildSource(string mode, string scope, string ldap, string dir)
        {
            switch (mode)
            {
                case "com":
                    return new ComPolicySource(scope, ldap);
                case "file":
                    // return new FilePolicySource(dir);
                    throw new NotImplementedException("file mode not written yet");
                default:
                    throw new OptionException("Unknown mode: " + mode, "mode");
            }
        }
    }
}