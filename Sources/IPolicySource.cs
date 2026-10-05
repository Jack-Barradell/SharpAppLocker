using SharpAppLocker.Model;

namespace SharpAppLocker.Sources
{
    internal interface IPolicySource
    {
        string LoadXml();
        PolicyDocument Load();
    }
}