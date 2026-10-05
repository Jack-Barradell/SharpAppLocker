using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using SharpAppLocker.Model;

namespace SharpAppLocker.Analysis
{
    internal static class PrincipalResolver
    {
        public static HashSet<string> CurrentUser()
        {
            HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using (WindowsIdentity id = WindowsIdentity.GetCurrent())
            {
                if (id.User != null)
                    set.Add(id.User.Value);

                if (id.Groups != null)
                {
                    foreach (IdentityReference g in id.Groups)
                    {
                        try
                        {
                            SecurityIdentifier sid = (SecurityIdentifier)g.Translate(typeof(SecurityIdentifier));
                            set.Add(sid.Value);
                        }
                        catch {  }
                    }
                }
            }
            return set;
        }
        
        public static HashSet<string> Exact(string nameOrSid)
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Sid.Resolve(nameOrSid) };
        }
        
        public static HashSet<string> ForPrincipal(string nameOrSid)
        {
            HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string sid = Sid.Resolve(nameOrSid);
            set.Add(sid);

            foreach (ContextType ct in new[] { ContextType.Machine, ContextType.Domain })
            {
                try
                {
                    using (PrincipalContext ctx = new PrincipalContext(ct))
                    {
                        Principal p = Principal.FindByIdentity(ctx, IdentityType.Sid, sid);
                        if (p == null)
                            continue;

                        set.Add(p.Sid.Value);

                        UserPrincipal up = p as UserPrincipal;
                        if (up != null)
                        {
                            var e = up.GetAuthorizationGroups().GetEnumerator();
                            while (true)
                            {
                                try
                                {
                                    if (!e.MoveNext()) break;
                                    Principal g = e.Current;
                                    if (g != null && g.Sid != null) set.Add(g.Sid.Value);
                                }
                                catch (NoMatchingPrincipalException) {  }
                                catch { break; }
                            }
                            
                            set.Add("S-1-1-0");
                            set.Add("S-1-5-11");
                        }
                        return set;
                    }
                }
                catch {  }
            }
            return set;
        }
    }
}