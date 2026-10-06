using System;
using System.Runtime.InteropServices;

namespace SharpAppLockerAudit.Interop
{
    [ComImport]
    [Guid("B6FEA19E-32DD-4367-B5B7-2F5DA140E87D")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    public interface IAppIdPolicyHandler
    {
        void SetPolicy(
            [MarshalAs(UnmanagedType.BStr)] string ldapPath,
            [MarshalAs(UnmanagedType.BStr)] string xmlPolicy
        );

        [return: MarshalAs(UnmanagedType.BStr)]
        string GetPolicy([MarshalAs(UnmanagedType.BStr)] string ldapPath);

        [return: MarshalAs(UnmanagedType.BStr)]
        string GetEffectivePolicy();

        void IsFileAllowed(
            [MarshalAs(UnmanagedType.BStr)] string xmlPolicy,
            [MarshalAs(UnmanagedType.BStr)] string filePath,
            [MarshalAs(UnmanagedType.BStr)] string userSid,
            out Guid responsibleRuleId,
            out int status
        );

        void IsPackageAllowed(
            [MarshalAs(UnmanagedType.BStr)] string xmlPolicy,
            [MarshalAs(UnmanagedType.BStr)] string publisherName,
            [MarshalAs(UnmanagedType.BStr)] string packageName,
            uint packageVersion,
            [MarshalAs(UnmanagedType.BStr)] string userSid,
            out Guid responsibleRuleId,
            out int status
        );
    }
}