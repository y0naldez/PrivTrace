using System;
using System.Collections.Generic;
using PrivTrace.Models;

namespace PrivTrace.Tests
{
    // Independent synthetic inputs derived from generalized Windows conditions.
    // Expected results and classifications are intentionally kept in TestRunner.
    internal static class SyntheticScenarioFixtures
    {
        internal static AnalysisContext Create(string machine, string variant)
        {
            AnalysisContext c = Base(machine);
            if (machine == "SYN-INSTALLER-POLICY-001") InstallerPolicy(c, variant);
            else if (machine == "SYN-SVC-CONFIG-001") ServiceConfiguration(c, variant);
            else if (machine == "SYN-BACKUP-001") BackupOperators(c, variant);
            else if (machine == "SYN-DNS-001") DnsOperators(c, variant);
            else if (machine == "SYN-SVC-WRITE-001") ServiceBinary(c, variant, "SyntheticUpdateSvc", @"C:\SyntheticApps\Update\update-service.exe");
            else if (machine == "SYN-SVC-WRITE-002") ServiceBinary(c, variant, "SyntheticWebSvc", @"C:\SyntheticApps\Web\web-service.exe");
            else if (machine == "SYN-TASK-WRITE-001") ScheduledBinary(c, variant);
            else if (machine == "SYN-DLL-SEARCH-001") UnmodeledDllSearch(c, variant);
            else throw new ArgumentOutOfRangeException("machine", machine, "Unknown synthetic SYNTHETIC-MATRIX fixture.");
            return c;
        }

        private static AnalysisContext Base(string machine)
        {
            return new AnalysisContext
            {
                Token = new TokenSnapshot { UserName = machine.ToUpperInvariant() + @"\limited", UserSid = "S-1-5-21-42-42-42-1001", IntegrityLevel = "Medium", Elevated = TriState.No },
                System = new SystemSnapshot { IsWindows = true, Architecture = "x64", OsVersion = "Synthetic SYNTHETIC-MATRIX", AlwaysInstallElevatedMachine = TriState.No, AlwaysInstallElevatedUser = TriState.No }
            };
        }

        private static void InstallerPolicy(AnalysisContext c, string variant)
        {
            if (variant == "A" || variant == "B") { c.System.AlwaysInstallElevatedMachine = TriState.Yes; c.System.AlwaysInstallElevatedUser = TriState.Yes; }
            else if (variant == "C") { c.System.AlwaysInstallElevatedMachine = TriState.Yes; c.System.AlwaysInstallElevatedUser = TriState.No; }
            else if (variant == "D") { c.System.AlwaysInstallElevatedMachine = TriState.No; c.System.AlwaysInstallElevatedUser = TriState.Yes; }
            else if (variant == "E") { c.System.AlwaysInstallElevatedMachine = TriState.Unknown; c.System.AlwaysInstallElevatedUser = TriState.Yes; }
        }

        private static void ServiceConfiguration(AnalysisContext c, string variant)
        {
            c.Token.Groups.Add(new WindowsGroup { Sid = "S-1-5-32-549", Name = @"BUILTIN\Server Operators", Enabled = true });
            WindowsService service = PrivilegedService("VMTools", @"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe", TriState.No);
            service.CanChangeConfig = variant == "C" ? TriState.No : variant == "E" ? TriState.Unknown : TriState.Yes;
            if (variant == "D") service.StartType = "Disabled";
            c.Services.Add(service);
        }

        private static void BackupOperators(AnalysisContext c, string variant)
        {
            if (variant == "E") { c.Token.Errors.Add("Token information unavailable: access denied"); return; }
            c.Token.Groups.Add(new WindowsGroup { Sid = "S-1-5-32-551", Name = @"BUILTIN\Backup Operators", Enabled = true });
            if (variant == "C") return;
            TokenPrivilegeState state = variant == "D" ? TokenPrivilegeState.Disabled : TokenPrivilegeState.Enabled;
            AddPrivilege(c, "SeBackupPrivilege", state);
            if (variant == "A") c.Token.Errors.Add("SeRestorePrivilege presence/state not established by the consulted source");
            else AddPrivilege(c, "SeRestorePrivilege", state);
        }

        private static void DnsOperators(AnalysisContext c, string variant)
        {
            if (variant == "E") { c.Token.Errors.Add("Token groups unavailable: access denied"); return; }
            if (variant != "C") c.Token.Groups.Add(new WindowsGroup { Sid = "S-1-5-21-1-2-3-1101", Name = @"MEGABANK\DnsAdmins", Enabled = variant != "D" });
            WindowsService dns = PrivilegedService("DNS", @"C:\Windows\System32\dns.exe", TriState.No); dns.State = "Running"; c.Services.Add(dns);
        }

        private static void ServiceBinary(AnalysisContext c, string variant, string name, string path)
        {
            TriState write = variant == "C" ? TriState.No : variant == "E" ? TriState.Unknown : TriState.Yes;
            WindowsService service = PrivilegedService(name, path, write);
            service.StartType = variant == "D" ? "Disabled" : "Automatic"; service.State = "Stopped";
            c.Services.Add(service);
        }

        private static void ScheduledBinary(AnalysisContext c, string variant)
        {
            if (variant == "A")
            {
                c.Binaries.Add(new BinaryArtifact { Path = @"C:\Backup\TFTP.EXE", Exists = TriState.Yes, FilePermission = Permission(TriState.Yes, TriState.No) });
                return; // Documented low-privilege view: file visible, privileged task not enumerable.
            }
            if (variant == "E") { c.Errors.Add("Tasks: ACCESS_DENIED while enumerating privileged task definitions"); return; }
            TriState write = variant == "C" ? TriState.No : TriState.Yes; bool enabled = variant != "D";
            ScheduledTaskInfo task = new ScheduledTaskInfo { Name = "Backup", Path = @"\Synthetic\Backup", Enabled = enabled, State = enabled ? "Ready" : "Disabled", Principal = @"SYNTHETIC\Administrator", PrincipalIsHigher = TriState.Yes, CanModify = TriState.No };
            task.Triggers.Add("Every five minutes (synthetic variant)");
            task.Actions.Add(new ScheduledTaskAction { Type = "Exec", OriginalExecutable = @"C:\Backup\TFTP.EXE", Executable = @"C:\Backup\TFTP.EXE", Arguments = "-i 192.0.2.15 get backup.txt", WorkingDirectory = @"C:\Backup", TargetPermission = Permission(write, TriState.No), HijackCandidates = new List<string>() });
            c.Tasks.Add(task);
        }

        private static void UnmodeledDllSearch(AnalysisContext c, string variant)
        {
            WindowsService service = PrivilegedService("SyntheticScannerSvc", @"C:\SyntheticApps\Scanner\scanner-service.exe", TriState.No);
            service.State = "Running"; service.StartType = variant == "D" ? "Disabled" : "Automatic"; c.Services.Add(service);
            SecurityPermission pathPermission = Permission(TriState.No, variant == "C" ? TriState.No : variant == "E" ? TriState.Unknown : TriState.Yes);
            pathPermission.Target = @"C:\SyntheticApps\Temp"; pathPermission.ObjectType = "Directory";
            c.Binaries.Add(new BinaryArtifact { Path = @"C:\SyntheticApps\Temp\missing-helper.dll", Exists = TriState.No, IsAmbiguous = true, DirectoryPermission = pathPermission, OriginalReference = "DLL search-order candidate; not a configured ServiceDll" });
            c.ExecutionRelationships.Add(new ExecutionRelationship { Classification = "SYNTHETIC_UNMODELED", SourceKind = "DllSearchOrder", SourceId = "SyntheticScannerSvc", TargetPath = @"C:\SyntheticApps\Temp\missing-helper.dll", Detail = "Synthetic representation of PATH search plus named-pipe trigger; no current rule consumes this relation." });
        }

        private static WindowsService PrivilegedService(string name, string path, TriState write)
        {
            return new WindowsService { Name = name, DisplayName = name, BinaryPath = path, ExecutablePath = path, Account = "LocalSystem", State = "Stopped", StartType = "Automatic", CanStart = TriState.No, CanChangeConfig = TriState.No, ExecutablePermission = Permission(write, TriState.No), DirectoryPermission = Permission(TriState.No, TriState.No) };
        }

        private static SecurityPermission Permission(TriState write, TriState create)
        {
            return new SecurityPermission { CanWrite = write, CanCreate = create, CanDelete = TriState.No, CanChangePermissions = TriState.No, MandatoryIntegrityAllowsWrite = TriState.Yes };
        }

        private static void AddPrivilege(AnalysisContext c, string name, TokenPrivilegeState state)
        {
            c.Token.Privileges.Add(new TokenPrivilege { Name = name, State = state, Present = true, Enabled = state == TokenPrivilegeState.Enabled });
        }
    }
}
