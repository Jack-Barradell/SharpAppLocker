using SharpAppLockerAudit.Model;

namespace SharpAppLockerAudit.Sources
{
    internal interface IPolicySource
    {
        string LoadXml();
        PolicyDocument Load();
    }
}