# SharpAppLocker

## Summary 

A tool developed in .NET Framework 4.8 to aid both Red and Blue Teamers in auditing AppLocker rules and identifying bypasses.

## Usage

```
PS C:\Demo> .\SharpAppLocker.exe -h
  -m, --mode=VALUE           com|file (default: com)
  -c, --collection=VALUE     all|exe|msi|script|dll|appx (default: all)
  -s, --sid=VALUE            exact: only rules targeting this SID/account
      --me                   filter to rules that apply to the current user (
                               incl. groups)
      --applies-to=VALUE     filter to rules that apply to this user/group (
                               expands groups)
  -a, --action=VALUE         listing filter: allow|deny (default: both)
  -r, --raw                  dump raw XML (com) / records (file) and exit
      --json                 emit machine-readable JSON instead of text
  -h, --help                 show this help and exit
      --scope=VALUE          com: effective|local|domain (default: effective)
      --ldap=VALUE           com: LDAP path (required for --scope domain)
      --dir=VALUE            file: folder of .AppLocker files (default: %WINDIR%
                               \System32\AppLocker)
      --enforcement-from-registry
                             file: read EnforcementMode from the registry (
                               default off; it's not stored in the .AppLocker
                               file)
      --audit                review the policy for weak rules / bypass surface
                               and exit
      --test-bypass          test whether allowed locations are actually user-
                               writable (local fs ACLs) and exit
```

## Associated Blog Post 

[AppLocker Bypasses for Red and Blue Teams](https://google.com)