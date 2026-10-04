using System;
using System.Runtime.InteropServices;
using SharpAppLocker.Interop;
using SharpAppLocker.Model;

namespace SharpAppLocker.Sources
{
    internal sealed class ComPolicySource : IPolicySource
    {
        private readonly string _scope;   // effective | local | domain
        private readonly string _ldap;    // only used when scope == domain

        public ComPolicySource(string scope, string ldap)
        {
            _scope = scope;
            _ldap = ldap;
        }

        public string LoadXml()
        {
            IAppIdPolicyHandler handler = (IAppIdPolicyHandler)new AppIdPolicyHandler();
            try
            {
                switch (_scope)
                {
                    case "effective":
                        return handler.GetEffectivePolicy();
                    case "local":
                        return handler.GetPolicy(null);   // null LDAP path = local GPO
                    case "domain":
                        return handler.GetPolicy(_ldap);
                    default:
                        throw new ArgumentException("Unknown scope: " + _scope);
                }
            }
            finally
            {
                Marshal.FinalReleaseComObject(handler);
            }
        }

        public PolicyDocument Load()
        {
            return PolicyParser.Parse(LoadXml());
        }
    }
}