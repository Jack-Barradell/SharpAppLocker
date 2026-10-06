using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SharpAppLockerAudit.Interop
{
    internal static class NativeMethods
    {
        private const uint SDDL_REVISION_1 = 1;
        private const int DACL_SECURITY_INFORMATION = 0x00000004;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
            byte[] securityDescriptor,
            uint requestedStringSdRevision,
            int securityInformation,
            out IntPtr stringSecurityDescriptor,
            out int stringSecurityDescriptorLen);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertStringSidToSid(string stringSid, out IntPtr sid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);
        
        public static string SecurityDescriptorToSddl(byte[] selfRelativeSd)
        {
            IntPtr strPtr;
            int strLen;
            if (!ConvertSecurityDescriptorToStringSecurityDescriptor(
                    selfRelativeSd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, out strPtr, out strLen))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),
                    "ConvertSecurityDescriptorToStringSecurityDescriptor failed");
            }

            try
            {
                return Marshal.PtrToStringUni(strPtr);
            }
            finally
            {
                LocalFree(strPtr);
            }
        }
        
        public static string NormaliseSid(string sddlSidToken)
        {
            if (string.IsNullOrEmpty(sddlSidToken))
                return sddlSidToken;

            if (sddlSidToken.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
                return sddlSidToken;

            IntPtr sidPtr;
            if (!ConvertStringSidToSid(sddlSidToken, out sidPtr))
                return sddlSidToken;

            try
            {
                return new SecurityIdentifier(sidPtr).Value;
            }
            catch
            {
                return sddlSidToken;
            }
            finally
            {
                LocalFree(sidPtr);
            }
        }
    }
}