using SharpAppLocker.Model;

namespace SharpAppLocker.Sources
{
    internal interface IPolicySource
    {
        string LoadXml();        // raw underlying text (XML for com, SDDL for file) - used by --raw
        PolicyDocument Load();   // parsed, mode-agnostic model
    }
}