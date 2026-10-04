using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using SharpAppLocker.Model;

namespace SharpAppLocker.Analysis
{
    /// <summary>
    /// Works out the set of SIDs a principal effectively "is", so we can find every rule that
    /// applies to them - whether the rule targets them directly or via a group they belong to.
    /// A rule applies to principal P if its UserOrGroupSid is in P's effective SID set.
    /// </summary>
    internal static class PrincipalResolver
    {
        /// <summary>
        /// Effective SIDs for the CURRENT user. Token-accurate: exactly what Windows evaluated
        /// at logon - user SID, every (nested) group, and well-known identities like Everyone /
        /// Authenticated Users. No extra references needed.
        /// </summary>
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
                        catch { /* skip anything that won't translate */ }
                    }
                }
            }
            return set;
        }

        /// <summary>Exact-match set: just this one SID/account, no group expansion (for --sid).</summary>
        public static HashSet<string> Exact(string nameOrSid)
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Sid.Resolve(nameOrSid) };
        }

        /// <summary>
        /// Effective SIDs for a NAMED user or group. For a user, expands (transitive) group
        /// membership via AccountManagement, plus the well-known world SIDs that apply to any
        /// interactive user. For a group, just the group's own SID (nested parents not expanded).
        /// Falls back to the bare SID if the account can't be enumerated (e.g. no DC reachable).
        /// </summary>
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
                            // GetAuthorizationGroups is transitive (includes nested groups).
                            // Iterating can throw per-item for unresolvable foreign SIDs, so guard it.
                            var e = up.GetAuthorizationGroups().GetEnumerator();
                            while (true)
                            {
                                try
                                {
                                    if (!e.MoveNext()) break;
                                    Principal g = e.Current;
                                    if (g != null && g.Sid != null) set.Add(g.Sid.Value);
                                }
                                catch (NoMatchingPrincipalException) { /* skip this one */ }
                                catch { break; }
                            }

                            // A rule targeting Everyone / Authenticated Users applies to any user.
                            set.Add("S-1-1-0");    // Everyone
                            set.Add("S-1-5-11");   // Authenticated Users
                        }
                        return set;
                    }
                }
                catch { /* try next context, else fall through to the bare SID */ }
            }
            return set;
        }
    }
}