using System;
using PrivTrace.Models;

namespace PrivTrace.Tests
{
    // Input-only fixtures. Expected statuses remain in TestRunner.
    internal static class CorrelationFixtures
    {
        internal static AnalysisContext Create(string id)
        {
            AnalysisContext c = Base(id);
            if (id.StartsWith("R", StringComparison.OrdinalIgnoreCase)) ServiceConfiguration(c, id);
            else if (id.StartsWith("B", StringComparison.OrdinalIgnoreCase)) BackupPrivileges(c, id);
            else if (id.StartsWith("D", StringComparison.OrdinalIgnoreCase)) DnsConfiguration(c, id);
            else throw new ArgumentOutOfRangeException("id", id, "Unknown CORRELATION fixture.");
            return c;
        }

        private static AnalysisContext Base(string id)
        {
            return new AnalysisContext { ScenarioId = id, Token = new TokenSnapshot { UserName = @"LAB\operator", UserSid = "S-1-5-21-500-500-500-1105", IntegrityLevel = "Medium", Elevated = TriState.No, RestrictedState = TriState.No }, System = new SystemSnapshot { IsWindows = true, Architecture = "x64", OsVersion = "Synthetic CORRELATION", AlwaysInstallElevatedMachine = TriState.No, AlwaysInstallElevatedUser = TriState.No } };
        }

        private static void ServiceConfiguration(AnalysisContext c, string id)
        {
            bool group = id != "R03";
            if (group) c.Token.Groups.Add(new WindowsGroup { Sid = "S-1-5-32-549", Name = @"BUILTIN\Server Operators", Enabled = true });
            WindowsService service = Service("VMTools");
            service.State = "Running"; service.CanChangeConfig = id == "R02" ? TriState.No : TriState.Yes; service.CanStart = TriState.Yes; service.CanStop = TriState.Yes;
            if (id == "R04") service.StartType = "Disabled";
            service.EffectiveRights.Add(new EffectiveServiceRight { Right = "SERVICE_CHANGE_CONFIG", Granted = service.CanChangeConfig, EvaluationMethod = "Synthetic SCM desired-access result", Provenance = "UNKNOWN", Detail = "No granting ACE was pre-attributed." });
            service.EffectiveRights.Add(new EffectiveServiceRight { Right = "SERVICE_START", Granted = service.CanStart, EvaluationMethod = "Synthetic SCM desired-access result", Provenance = "UNKNOWN" });
            service.EffectiveRights.Add(new EffectiveServiceRight { Right = "SERVICE_STOP", Granted = service.CanStop, EvaluationMethod = "Synthetic SCM desired-access result", Provenance = "UNKNOWN" });
            c.Services.Add(service);
        }

        private static void BackupPrivileges(AnalysisContext c, string id)
        {
            if (id != "B04") c.Token.Groups.Add(new WindowsGroup { Sid = "S-1-5-32-551", Name = @"BUILTIN\Backup Operators", Enabled = true });
            if (id == "B05") { c.Token.Errors.Add("Token privileges unavailable: synthetic access restriction."); return; }
            if (id == "B01" || id == "B04") AddPrivilege(c, "SeBackupPrivilege", TokenPrivilegeState.Enabled);
            else if (id == "B02") AddPrivilege(c, "SeBackupPrivilege", TokenPrivilegeState.Disabled);
            if (id == "B06") AddPrivilege(c, "SeRestorePrivilege", TokenPrivilegeState.Disabled);
        }

        private static void DnsConfiguration(AnalysisContext c, string id)
        {
            if (id != "D03") c.Token.Groups.Add(new WindowsGroup { Sid = "S-1-5-21-500-500-500-1107", Name = @"LAB\DnsAdmins", Enabled = true });
            if (id == "D02" || id == "D06") { c.DnsServer = new DnsServerSnapshot { Present = TriState.No, ConfigurationReadState = "NOT_APPLICABLE", CanConfigurePlugin = TriState.Unknown, RightProvenance = "UNKNOWN" }; if (id == "D06") c.Services.Add(new WindowsService { Name = "Dnscache", DisplayName = "DNS Client", Account = @"NT AUTHORITY\NetworkService", State = "Running", StartType = "Automatic" }); return; }
            WindowsService service = Service("DNS"); service.State = id == "D07" ? "Stopped" : "Running"; service.StartType = id == "D07" ? "Disabled" : "Automatic"; c.Services.Add(service);
            string readState = id == "D05" ? "ACCESS_DENIED" : "OBSERVED";
            c.DnsServer = new DnsServerSnapshot { Present = TriState.Yes, ServiceName = "DNS", DisplayName = "DNS Server", State = service.State, StartType = service.StartType, Account = service.Account, ServerLevelPluginDll = id == "D04" || id == "D07" ? @"C:\ProgramData\dns\plugin.dll" : null, ConfigurationReadState = readState, CanConfigurePlugin = id == "D01" ? TriState.Yes : TriState.Unknown, RightProvenance = id == "D01" ? "Registry AccessCheck (KEY_SET_VALUE); granting ACE not attributed" : "UNKNOWN" };
        }

        private static WindowsService Service(string name)
        {
            return new WindowsService { Name = name, DisplayName = name == "DNS" ? "DNS Server" : name, BinaryPath = name == "DNS" ? @"C:\Windows\System32\dns.exe" : @"C:\Program Files\Vendor\service.exe", ExecutablePath = name == "DNS" ? @"C:\Windows\System32\dns.exe" : @"C:\Program Files\Vendor\service.exe", Account = "LocalSystem", State = "Stopped", StartType = "Manual", CanChangeConfig = TriState.No, CanStart = TriState.No, CanStop = TriState.No, ExecutablePermission = Permission(TriState.No), DirectoryPermission = Permission(TriState.No) };
        }
        private static SecurityPermission Permission(TriState write) { return new SecurityPermission { CanWrite = write, CanCreate = TriState.No, CanDelete = TriState.No, CanChangePermissions = TriState.No, MandatoryIntegrityAllowsWrite = TriState.Yes }; }
        private static void AddPrivilege(AnalysisContext c, string name, TokenPrivilegeState state) { c.Token.Privileges.Add(new TokenPrivilege { Name = name, State = state, Present = state != TokenPrivilegeState.Removed, Enabled = state == TokenPrivilegeState.Enabled }); }
    }
}
