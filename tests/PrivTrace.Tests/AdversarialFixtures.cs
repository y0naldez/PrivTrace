using System;
using System.Collections.Generic;
using PrivTrace.Models;

namespace PrivTrace.Tests
{
    // Inputs only. Expected findings live in TestRunner and docs/detection-validation.md.
    internal static class AdversarialFixtures
    {
        internal static AnalysisContext Create(string id)
        {
            AnalysisContext c = Base();
            switch (id)
            {
                case "E01": AddPrivilege(c, "SeImpersonatePrivilege", TokenPrivilegeState.Enabled); break;
                case "E02": AddPrivilege(c, "SeImpersonatePrivilege", TokenPrivilegeState.Disabled); break;
                case "E03": AddPrivilege(c, "SeBackupPrivilege", TokenPrivilegeState.Disabled); break;
                case "E04": break;
                case "E05": c.Services.Add(Service("WritableAuto", TriState.Yes, "Automatic", "Stopped")); break;
                case "E06": c.Services.Add(Service("ProtectedAuto", TriState.No, "Automatic", "Stopped")); break;
                case "E07": c.System.AlwaysInstallElevatedMachine = TriState.Yes; c.System.AlwaysInstallElevatedUser = TriState.Yes; break;
                case "E08": break;
                case "M01": c.Tasks.Add(Task(true, TriState.Yes, TriState.No)); break;
                case "M02": c.Tasks.Add(Task(false, TriState.Yes, TriState.No)); break;
                case "M03": c.Services.Add(Service("DisabledWritable", TriState.Yes, "Disabled", "Stopped")); break;
                case "M04": { WindowsService s = Service("ManualNoStart", TriState.Yes, "Manual", "Stopped"); s.CanStart = TriState.No; c.Services.Add(s); break; }
                case "M05": { WindowsService s = Service("UnquotedProtected", TriState.No, "Automatic", "Stopped"); s.BinaryPath = @"C:\Program Files\Safe Vendor\svc.exe -d"; s.UnquotedCandidates.Add(@"C:\Program.exe"); s.UnquotedCandidatePermissions.Add(Permission(TriState.No, TriState.No)); c.Services.Add(s); break; }
                case "M06": { WindowsService s = Service("ConfigOnly", TriState.No, "Disabled", "Stopped"); s.CanChangeConfig = TriState.Yes; c.Services.Add(s); break; }
                case "M07": { WindowsService s = Shared("ConfiguredDll", 700); s.RegistryEvidence.Add(DllEvidence(TriState.Yes, TriState.No, TriState.Yes)); c.Services.Add(s); break; }
                case "M08": { WindowsService s = Service("CreateOnlyRegistry", TriState.No, "Automatic", "Stopped"); s.RegistryEvidence.Add(RegistryEvidence("Registry64", TriState.No, TriState.Yes)); c.Services.Add(s); break; }
                case "H01": BuildCanonicalCorrelation(c); break;
                case "H02": { WindowsService s = Service("SpecificRights", TriState.No, "Automatic", "Stopped"); s.ExecutablePermission.CanDelete = TriState.Yes; c.Services.Add(s); break; }
                case "H03": { WindowsService s = Shared("MissingDll", 701); s.RegistryEvidence.Add(DllEvidence(TriState.No, TriState.Yes, TriState.No)); c.Services.Add(s); break; }
                case "H04": { WindowsService s = Service("DisabledConfigurable", TriState.Yes, "Disabled", "Stopped"); s.CanChangeConfig = TriState.Yes; c.Services.Add(s); break; }
                case "H05": c.Tasks.Add(Task(false, TriState.Yes, TriState.Yes)); break;
                case "H06": { c.Processes.Add(new WindowsProcess { ProcessId = 702, Name = "opaque", ImagePath = @"C:\Safe\opaque.exe", AccessStatus = "ACCESS_DENIED", IntegrityLevel = "Unknown" }); c.Services.Add(Service("IndependentSafe", TriState.No, "Automatic", "Running")); break; }
                case "H07": BuildSharedHost(c); break;
                case "H08": { WindowsService s = Service("MicDenied", TriState.Yes, "Automatic", "Stopped"); s.ExecutablePermission.MandatoryIntegrityAllowsWrite = TriState.No; s.ExecutablePermission.IntegrityConstraint = "NoWriteUp"; c.Services.Add(s); break; }
                case "H09": { WindowsService s = Service("Wow6432Only", TriState.No, "Automatic", "Stopped"); s.RegistryEvidence.Add(RegistryEvidence("Registry32", TriState.Yes, TriState.No)); c.Services.Add(s); break; }
                case "H10": c.Services.Add(Service("AclUnavailable", TriState.Unknown, "Automatic", "Stopped")); break;
                case "P01": AddPrivilege(c, "SeDebugPrivilege", TokenPrivilegeState.Disabled); break;
                case "P02": AddPrivilege(c, "SeRestorePrivilege", TokenPrivilegeState.Disabled); break;
                case "P03": AddPrivilege(c, "SeTcbPrivilege", TokenPrivilegeState.Disabled); break;
                case "P04": break;
                case "P05": c.Token.Errors.Add("Token privileges unavailable: access denied"); break;
                case "ZN": BuildZeroNoise(c); break;
                default: throw new ArgumentOutOfRangeException("id", id, "Unknown ADVERSARIAL fixture.");
            }
            return c;
        }

        private static AnalysisContext Base()
        {
            return new AnalysisContext
            {
                Token = new TokenSnapshot { UserName = @"LAB\operator", UserSid = "S-1-5-21-1-2-3-1001", IntegrityLevel = "Medium", Elevated = TriState.No },
                System = new SystemSnapshot { IsWindows = true, Architecture = "x64", OsVersion = "Synthetic ADVERSARIAL", AlwaysInstallElevatedMachine = TriState.No, AlwaysInstallElevatedUser = TriState.No }
            };
        }

        private static void AddPrivilege(AnalysisContext c, string name, TokenPrivilegeState state)
        {
            c.Token.Privileges.Add(new TokenPrivilege { Name = name, State = state, Present = state != TokenPrivilegeState.Removed, Enabled = state == TokenPrivilegeState.Enabled });
        }

        private static SecurityPermission Permission(TriState write, TriState create)
        {
            return new SecurityPermission { CanWrite = write, CanCreate = create, CanDelete = TriState.No, CanChangePermissions = TriState.No, MandatoryIntegrityAllowsWrite = TriState.Yes };
        }

        private static WindowsService Service(string name, TriState write, string startType, string state)
        {
            return new WindowsService
            {
                Name = name, BinaryPath = @"C:\Vendor\svc.exe", ExecutablePath = @"C:\Vendor\svc.exe", Account = "LocalSystem",
                State = state, StartType = startType, CanStart = startType == "Manual" ? TriState.Yes : TriState.No, CanChangeConfig = TriState.No,
                ExecutablePermission = Permission(write, TriState.No), DirectoryPermission = Permission(TriState.No, TriState.No)
            };
        }

        private static ScheduledTaskInfo Task(bool enabled, TriState write, TriState modify)
        {
            ScheduledTaskInfo task = new ScheduledTaskInfo { Name = "Backup", Path = @"\PrivTrace\Backup", Enabled = enabled, State = enabled ? "Ready" : "Disabled", Principal = "SYSTEM", PrincipalIsHigher = TriState.Yes, CanModify = modify };
            task.Actions.Add(new ScheduledTaskAction { Type = "Exec", Executable = @"C:\Jobs\backup.exe", OriginalExecutable = @"C:\Jobs\backup.exe", TargetPermission = Permission(write, TriState.No), HijackCandidates = new List<string>() });
            task.Triggers.Add("Periodic synthetic trigger");
            return task;
        }

        private static WindowsService Shared(string name, int pid)
        {
            WindowsService s = Service(name, TriState.No, "Manual", "Running"); s.ProcessId = pid; s.ServiceType = "0x20"; s.BinaryPath = @"C:\Windows\System32\svchost.exe -k Vendor"; s.ExecutablePath = @"C:\Windows\System32\svchost.exe"; return s;
        }

        private static ServiceRegistryEvidence RegistryEvidence(string view, TriState write, TriState create)
        {
            SecurityPermission serviceKey = Permission(write, create); serviceKey.Target = view + @":HKLM\SYSTEM\CurrentControlSet\Services\Synthetic"; serviceKey.ObjectType = "RegistryKey";
            SecurityPermission parameters = Permission(TriState.No, TriState.No); parameters.Target = view + @":HKLM\SYSTEM\CurrentControlSet\Services\Synthetic\Parameters"; parameters.ObjectType = "RegistryKey";
            return new ServiceRegistryEvidence { View = view, ServiceKeyPath = @"HKLM\SYSTEM\CurrentControlSet\Services\Synthetic", ServiceKeyPermission = serviceKey, ParametersKeyPermission = parameters };
        }

        private static ServiceRegistryEvidence DllEvidence(TriState dllWrite, TriState directoryCreate, TriState exists)
        {
            return new ServiceRegistryEvidence { View = "Registry64", ServiceDll = @"%SystemRoot%\System32\vendor.dll", ServiceDllPath = @"C:\Windows\System32\vendor.dll", ServiceDllExists = exists, ServiceDllPermission = Permission(dllWrite, TriState.No), ServiceDllDirectoryPermission = Permission(TriState.No, directoryCreate), ServiceKeyPermission = Permission(TriState.No, TriState.No), ParametersKeyPermission = Permission(TriState.No, TriState.No) };
        }

        private static void BuildCanonicalCorrelation(AnalysisContext c)
        {
            WindowsService s = Service("CanonicalService", TriState.Yes, "Automatic", "Running"); s.ProcessId = 900; c.Services.Add(s);
            c.Processes.Add(new WindowsProcess { ProcessId = 900, Name = "svc", ImagePath = @"C:\Vendor\svc.exe", OwnerAccount = "SYSTEM", IntegrityLevel = "System", AccessStatus = "ACCESSIBLE" });
            ScheduledTaskInfo task = Task(true, TriState.Yes, TriState.No); task.Actions[0].Executable = @"C:\Vendor\svc.exe"; task.Actions[0].OriginalExecutable = @"C:\Vendor\svc.exe"; c.Tasks.Add(task);
        }

        private static void BuildSharedHost(AnalysisContext c)
        {
            WindowsService a = Shared("WritableDllService", 910); a.RegistryEvidence.Add(DllEvidence(TriState.Yes, TriState.No, TriState.Yes));
            WindowsService b = Shared("ProtectedDllService", 910); b.RegistryEvidence.Add(DllEvidence(TriState.No, TriState.No, TriState.Yes)); b.RegistryEvidence[0].ServiceDllPath = @"C:\Windows\System32\protected.dll"; b.RegistryEvidence[0].ServiceDll = @"%SystemRoot%\System32\protected.dll";
            c.Services.Add(a); c.Services.Add(b); c.Processes.Add(new WindowsProcess { ProcessId = 910, Name = "svchost", ImagePath = @"C:\Windows\System32\svchost.exe", OwnerAccount = "SYSTEM", IntegrityLevel = "System", AccessStatus = "ACCESSIBLE" });
        }

        private static void BuildZeroNoise(AnalysisContext c)
        {
            AddPrivilege(c, "SeBackupPrivilege", TokenPrivilegeState.Disabled);
            AddPrivilege(c, "SeChangeNotifyPrivilege", TokenPrivilegeState.Enabled);
            c.Token.Groups.Add(new WindowsGroup { Sid = "S-1-5-32-545", Name = "Users", Enabled = true });
            for (int i = 0; i < 100; i++) c.Processes.Add(new WindowsProcess { ProcessId = 1000 + i, Name = "safe" + i, ImagePath = @"C:\Windows\System32\safe.exe", OwnerAccount = @"LAB\operator", IntegrityLevel = "Medium", AccessStatus = "ACCESSIBLE" });
            for (int i = 0; i < 50; i++) { WindowsService s = Service("SafeService" + i, TriState.No, "Automatic", "Stopped"); s.Account = @"NT AUTHORITY\LocalService"; c.Services.Add(s); }
            for (int i = 0; i < 30; i++) { ScheduledTaskInfo t = Task(true, TriState.No, TriState.No); t.Name = "SafeTask" + i; t.Path = @"\Safe\Task" + i; t.Principal = @"LAB\operator"; t.PrincipalIsHigher = TriState.No; c.Tasks.Add(t); }
            WindowsService finding = Service("OnlyConcreteFinding", TriState.Yes, "Automatic", "Stopped"); finding.RegistryEvidence.Add(RegistryEvidence("Registry64", TriState.No, TriState.No)); c.Services.Add(finding);
        }
    }
}
