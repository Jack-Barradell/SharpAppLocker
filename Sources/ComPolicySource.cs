using System;
using System.Runtime.InteropServices;
using SharpAppLocker.Interop;
using SharpAppLocker.Model;

namespace SharpAppLocker.Sources
{
    internal sealed class ComPolicySource : IPolicySource
    {
        private readonly string _scope;
        private readonly string _ldap;

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
                        return handler.GetPolicy(null);
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