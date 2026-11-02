using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Text;
using Microsoft.Win32;
using PrivTrace.Interop;
using PrivTrace.Models;
using PrivTrace.Security;

namespace PrivTrace.Collectors
{
    public sealed class SystemCollector
    {
        public SystemSnapshot Collect()
        {
            SystemSnapshot snapshot = new SystemSnapshot
            {
                MachineName = Environment.MachineName,
                OsVersion = Environment.OSVersion.VersionString,
                Architecture = Environment.Is64BitOperatingSystem ? "x64" : "x86",
                ProcessId = Process.GetCurrentProcess().Id,
                IsWindows = Environment.OSVersion.Platform == PlatformID.Win32NT
            };
            if (snapshot.IsWindows)
            {
                snapshot.AlwaysInstallElevatedMachine = ReadInstallerPolicy(RegistryHive.LocalMachine);
                snapshot.AlwaysInstallElevatedUser = ReadInstallerPolicy(RegistryHive.CurrentUser);
            }
            return snapshot;
        }

        private static TriState ReadInstallerPolicy(RegistryHive hive)
        {
            try
            {
                using (RegistryKey root = RegistryKey.OpenBaseKey(hive, RegistryView.Default))
                using (RegistryKey key = root.OpenSubKey(@"Software\Policies\Microsoft\Windows\Installer", false))
                {
                    if (key == null) return TriState.No;
                    object value = key.GetValue("AlwaysInstallElevated", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    if (value == null) return TriState.No;
                    try { return Convert.ToInt32(value) == 1 ? TriState.Yes : TriState.No; } catch { return TriState.Unknown; }
                }
            }
            catch { return TriState.Unknown; }
        }
    }

    public sealed class TokenCollector
    {
        public TokenSnapshot Collect()
        {
            TokenSnapshot snapshot = new TokenSnapshot { Elevated = TriState.Unknown, IsAppContainer = TriState.Unknown, IntegrityLevel = "Unknown", ElevationType = "Unknown" };
            IntPtr token = IntPtr.Zero;
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                snapshot.UserName = identity.Name;
                snapshot.UserSid = identity.User == null ? null : identity.User.Value;
                if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), NativeMethods.TOKEN_QUERY, out token)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                ReadGroups(token, snapshot);
                ReadPrivileges(token, snapshot);
                ReadIntegrity(token, snapshot);
                int elevated = ReadInt(token, NativeMethods.TokenInformationClass.TokenElevation);
                snapshot.Elevated = elevated < 0 ? TriState.Unknown : elevated == 1 ? TriState.Yes : TriState.No;
                int elevationType = ReadInt(token, NativeMethods.TokenInformationClass.TokenElevationType);
                snapshot.ElevationType = elevationType == 1 ? "Default" : elevationType == 2 ? "Full" : elevationType == 3 ? "Limited" : "Unknown";
                int appContainer = ReadInt(token, NativeMethods.TokenInformationClass.TokenIsAppContainer);
                snapshot.IsAppContainer = appContainer < 0 ? TriState.Unknown : appContainer == 1 ? TriState.Yes : TriState.No;
                int restricted = ReadInt(token, NativeMethods.TokenInformationClass.TokenIsRestricted);
                snapshot.RestrictedState = restricted < 0 ? TriState.Unknown : restricted == 1 ? TriState.Yes : TriState.No;
                snapshot.Restricted = snapshot.RestrictedState == TriState.Yes;
                if (elevated < 0) snapshot.Errors.Add("Token elevation state unavailable.");
                if (elevationType < 0) snapshot.Errors.Add("Token elevation type unavailable.");
                if (appContainer < 0) snapshot.Errors.Add("Token AppContainer state unavailable.");
                if (restricted < 0) snapshot.Errors.Add("Restricted-token state unavailable.");
            }
            catch (Exception ex) { snapshot.Errors.Add(ex.GetType().Name + ": " + ex.Message); }
            finally { if (token != IntPtr.Zero) NativeMethods.CloseHandle(token); }
            return snapshot;
        }

        private static IntPtr Query(IntPtr token, NativeMethods.TokenInformationClass info, out int length)
        {
            NativeMethods.GetTokenInformation(token, info, IntPtr.Zero, 0, out length);
            if (length <= 0) return IntPtr.Zero;
            IntPtr data = Marshal.AllocHGlobal(length);
            if (!NativeMethods.GetTokenInformation(token, info, data, length, out length)) { Marshal.FreeHGlobal(data); return IntPtr.Zero; }
            return data;
        }

        private static int ReadInt(IntPtr token, NativeMethods.TokenInformationClass info)
        {
            int length; IntPtr data = Query(token, info, out length);
            if (data == IntPtr.Zero) return -1;
            try { return Marshal.ReadInt32(data); } finally { Marshal.FreeHGlobal(data); }
        }

        private static void ReadGroups(IntPtr token, TokenSnapshot snapshot)
        {
            int length; IntPtr data = Query(token, NativeMethods.TokenInformationClass.TokenGroups, out length);
            if (data == IntPtr.Zero) { snapshot.Errors.Add("Token groups unavailable."); return; }
            try
            {
                int count = Marshal.ReadInt32(data); int offset = IntPtr.Size;
                int size = Marshal.SizeOf(typeof(NativeMethods.SidAndAttributes));
                for (int i = 0; i < count; i++)
                {
                    NativeMethods.SidAndAttributes item = (NativeMethods.SidAndAttributes)Marshal.PtrToStructure(IntPtr.Add(data, offset + (i * size)), typeof(NativeMethods.SidAndAttributes));
                    SecurityIdentifier sid = new SecurityIdentifier(item.Sid);
                    string name;
                    try { name = sid.Translate(typeof(NTAccount)).Value; } catch { name = sid.Value; }
                    snapshot.Groups.Add(new WindowsGroup { Sid = sid.Value, Name = name, Enabled = (item.Attributes & NativeMethods.SE_GROUP_ENABLED) != 0, DenyOnly = (item.Attributes & NativeMethods.SE_GROUP_USE_FOR_DENY_ONLY) != 0 });
                }
            }
            finally { Marshal.FreeHGlobal(data); }
        }

        private static void ReadPrivileges(IntPtr token, TokenSnapshot snapshot)
        {
            int length; IntPtr data = Query(token, NativeMethods.TokenInformationClass.TokenPrivileges, out length);
            if (data == IntPtr.Zero) { snapshot.Errors.Add("Token privileges unavailable."); return; }
            try
            {
                int count = Marshal.ReadInt32(data); int size = Marshal.SizeOf(typeof(NativeMethods.LuidAndAttributes)); int offset = 4;
                for (int i = 0; i < count; i++)
                {
                    NativeMethods.LuidAndAttributes item = (NativeMethods.LuidAndAttributes)Marshal.PtrToStructure(IntPtr.Add(data, offset + (i * size)), typeof(NativeMethods.LuidAndAttributes));
                    int chars = 0; NativeMethods.Luid luid = item.Luid; NativeMethods.LookupPrivilegeName(null, ref luid, null, ref chars);
                    StringBuilder builder = new StringBuilder(chars + 1);
                    string name = NativeMethods.LookupPrivilegeName(null, ref luid, builder, ref chars) ? builder.ToString() : "LUID:" + item.Luid.HighPart + ":" + item.Luid.LowPart;
                    bool removed = (item.Attributes & NativeMethods.SE_PRIVILEGE_REMOVED) != 0; bool enabled = (item.Attributes & NativeMethods.SE_PRIVILEGE_ENABLED) != 0;
                    snapshot.Privileges.Add(new TokenPrivilege { Name = name, Present = !removed, Enabled = enabled && !removed, State = removed ? TokenPrivilegeState.Removed : enabled ? TokenPrivilegeState.Enabled : TokenPrivilegeState.Disabled });
                }
            }
            finally { Marshal.FreeHGlobal(data); }
        }

        private static void ReadIntegrity(IntPtr token, TokenSnapshot snapshot)
        {
            int length; IntPtr data = Query(token, NativeMethods.TokenInformationClass.TokenIntegrityLevel, out length);
            if (data == IntPtr.Zero) return;
            try
            {
                NativeMethods.TokenMandatoryLabel label = (NativeMethods.TokenMandatoryLabel)Marshal.PtrToStructure(data, typeof(NativeMethods.TokenMandatoryLabel));
                string sid = new SecurityIdentifier(label.Label.Sid).Value;
                int rid; if (!Int32.TryParse(sid.Substring(sid.LastIndexOf('-') + 1), out rid)) return;
                snapshot.IntegrityLevel = rid < 0x1000 ? "Untrusted" : rid < 0x2000 ? "Low" : rid < 0x3000 ? "Medium" : rid < 0x4000 ? "High" : rid < 0x5000 ? "System" : "Protected";
            }
            finally { Marshal.FreeHGlobal(data); }
        }
    }

    public sealed class GroupCollector
    {
        public List<WindowsGroup> Collect(TokenSnapshot token) { return new List<WindowsGroup>(token.Groups); }
    }

    public sealed class ProcessCollector
    {
        public ProcessCollector() { Errors = new List<string>(); }
        public List<string> Errors { get; private set; }

        public List<WindowsProcess> Collect()
        {
            List<WindowsProcess> result = new List<WindowsProcess>();
            if (Environment.OSVersion.Platform != PlatformID.Win32NT) { Errors.Add("Process enumeration is available only on Windows."); return result; }
            IntPtr snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPPROCESS, 0);
            if (snapshot == NativeMethods.INVALID_HANDLE_VALUE) { Errors.Add("CreateToolhelp32Snapshot failed: " + Marshal.GetLastWin32Error()); return result; }
            try
            {
                NativeMethods.ProcessEntry32 entry = new NativeMethods.ProcessEntry32(); entry.Size = (uint)Marshal.SizeOf(typeof(NativeMethods.ProcessEntry32));
                if (!NativeMethods.Process32First(snapshot, ref entry)) { Errors.Add("Process32First failed: " + Marshal.GetLastWin32Error()); return result; }
                do
                {
                    WindowsProcess process = new WindowsProcess { ProcessId = (int)entry.ProcessId, ParentProcessId = (int)entry.ParentProcessId, Name = entry.ExeFile, State = "RUNNING", AccessStatus = "UNKNOWN", IntegrityLevel = "Unknown", Architecture = "Unknown" };
                    ReadDetails(process); result.Add(process); entry.Size = (uint)Marshal.SizeOf(typeof(NativeMethods.ProcessEntry32));
                } while (NativeMethods.Process32Next(snapshot, ref entry));
            }
            finally { NativeMethods.CloseHandle(snapshot); }
            Dictionary<int, WindowsProcess> byId = new Dictionary<int, WindowsProcess>(); foreach (WindowsProcess process in result) byId[process.ProcessId] = process;
            foreach (WindowsProcess process in result) { WindowsProcess parent; if (byId.TryGetValue(process.ParentProcessId, out parent)) process.ParentImagePath = parent.ImagePath; }
            return result;
        }

        private static void ReadDetails(WindowsProcess process)
        {
            IntPtr handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)process.ProcessId);
            if (handle == IntPtr.Zero) handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_INFORMATION, false, (uint)process.ProcessId);
            if (handle == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error(); process.AccessStatus = error == 5 ? "ACCESS_DENIED" : "ERROR"; process.Errors.Add("OpenProcess: " + error); return;
            }
            try
            {
                StringBuilder path = new StringBuilder(32768); int length = path.Capacity;
                if (NativeMethods.QueryFullProcessImageName(handle, 0, path, ref length)) { process.ImagePath = path.ToString(); process.ImagePathSource = "QueryFullProcessImageName"; }
                else process.Errors.Add("QueryFullProcessImageName: " + Marshal.GetLastWin32Error());
                process.Architecture = ReadArchitecture(handle);
                ReadIdentity(handle, process);
                process.AccessStatus = process.ImagePath == null ? "PARTIAL" : "ACCESSIBLE";
            }
            finally { NativeMethods.CloseHandle(handle); }
        }

        private static void ReadIdentity(IntPtr processHandle, WindowsProcess process)
        {
            IntPtr token;
            if (!NativeMethods.OpenProcessToken(processHandle, NativeMethods.TOKEN_QUERY, out token)) { process.Errors.Add("OpenProcessToken: " + Marshal.GetLastWin32Error()); return; }
            try
            {
                int length; IntPtr data = QueryToken(token, NativeMethods.TokenInformationClass.TokenUser, out length);
                if (data != IntPtr.Zero)
                {
                    try
                    {
                        NativeMethods.SidAndAttributes user = (NativeMethods.SidAndAttributes)Marshal.PtrToStructure(data, typeof(NativeMethods.SidAndAttributes));
                        SecurityIdentifier sid = new SecurityIdentifier(user.Sid); process.OwnerSid = sid.Value;
                        try { process.OwnerAccount = sid.Translate(typeof(NTAccount)).Value; } catch { process.OwnerAccount = sid.Value; }
                    }
                    finally { Marshal.FreeHGlobal(data); }
                }
                data = QueryToken(token, NativeMethods.TokenInformationClass.TokenIntegrityLevel, out length);
                if (data != IntPtr.Zero)
                {
                    try
                    {
                        NativeMethods.TokenMandatoryLabel label = (NativeMethods.TokenMandatoryLabel)Marshal.PtrToStructure(data, typeof(NativeMethods.TokenMandatoryLabel));
                        string sid = new SecurityIdentifier(label.Label.Sid).Value; int rid;
                        if (Int32.TryParse(sid.Substring(sid.LastIndexOf('-') + 1), out rid)) process.IntegrityLevel = rid < 0x1000 ? "Untrusted" : rid < 0x2000 ? "Low" : rid < 0x3000 ? "Medium" : rid < 0x4000 ? "High" : rid < 0x5000 ? "System" : "Protected";
                    }
                    finally { Marshal.FreeHGlobal(data); }
                }
            }
            finally { NativeMethods.CloseHandle(token); }
        }

        private static IntPtr QueryToken(IntPtr token, NativeMethods.TokenInformationClass info, out int length)
        {
            NativeMethods.GetTokenInformation(token, info, IntPtr.Zero, 0, out length); if (length <= 0) return IntPtr.Zero;
            IntPtr data = Marshal.AllocHGlobal(length); if (!NativeMethods.GetTokenInformation(token, info, data, length, out length)) { Marshal.FreeHGlobal(data); return IntPtr.Zero; } return data;
        }

        private static string ReadArchitecture(IntPtr process)
        {
            try
            {
                ushort machine, native; if (NativeMethods.IsWow64Process2(process, out machine, out native)) return MachineName(machine == 0 ? native : machine);
            }
            catch (EntryPointNotFoundException) { }
            catch (DllNotFoundException) { }
            bool wow64; if (NativeMethods.IsWow64Process(process, out wow64)) return wow64 ? "x86" : Environment.Is64BitOperatingSystem ? "x64" : "x86";
            return "Unknown";
        }

        private static string MachineName(ushort machine) { return machine == 0x014c ? "x86" : machine == 0x8664 ? "x64" : machine == 0x01c4 ? "ARM" : machine == 0xAA64 ? "ARM64" : "0x" + machine.ToString("X4"); }
    }

    public sealed class FileAclCollector
    {
        private readonly AccessEvaluator evaluator = new AccessEvaluator();
        public SecurityPermission Collect(string path, bool directory) { return evaluator.EvaluatePath(path, directory); }
    }

    public sealed class ServiceCollector
    {
        private readonly AccessEvaluator access = new AccessEvaluator();
        private bool objectReadFailure;
        public ServiceCollector() { Errors = new List<string>(); Diagnostics = new List<CollectorDiagnostic>(); CollectionState = "UNKNOWN"; }
        public List<string> Errors { get; private set; }
        public List<CollectorDiagnostic> Diagnostics { get; private set; }
        public string CollectionState { get; private set; }
        public List<WindowsService> Collect()
        {
            List<WindowsService> result = new List<WindowsService>();
            objectReadFailure = false;
            IntPtr manager = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_ENUMERATE_SERVICE);
            if (manager == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error(); CollectionState = CollectorOutcomeClassifier.ServiceState(false, error, false, 0, 0, 0);
                AddDiagnostic("CONNECT", "OpenSCManager", null, "SC_MANAGER_ENUMERATE_SERVICE (0x0004)", error, error == 5 ? "GLOBAL_ACCESS_DENIED" : "API_ERROR", "Unable to open the Service Control Manager for enumeration.");
                return result;
            }
            try
            {
                int needed, returned, resume = 0;
                bool sized = NativeMethods.EnumServicesStatusEx(manager, NativeMethods.SC_ENUM_PROCESS_INFO, NativeMethods.SERVICE_WIN32, NativeMethods.SERVICE_STATE_ALL, IntPtr.Zero, 0, out needed, out returned, ref resume, null);
                int sizeError = sized ? 0 : Marshal.GetLastWin32Error();
                if (sized && needed == 0) { CollectionState = "OBSERVED"; return result; }
                if (needed <= 0 || (sizeError != 234 && sizeError != 122))
                {
                    CollectionState = CollectorOutcomeClassifier.ServiceState(true, 0, false, sizeError, 0, 0);
                    AddDiagnostic("ENUMERATE", "EnumServicesStatusEx", null, "SC_MANAGER_ENUMERATE_SERVICE", sizeError, sizeError == 5 ? "GLOBAL_ACCESS_DENIED" : "API_ERROR", "Unable to determine the service enumeration buffer size.");
                    return result;
                }
                resume = 0;
                while (needed > 0)
                {
                    IntPtr buffer = Marshal.AllocHGlobal(needed);
                    try
                    {
                        int bufferSize = needed;
                        bool complete = NativeMethods.EnumServicesStatusEx(manager, NativeMethods.SC_ENUM_PROCESS_INFO, NativeMethods.SERVICE_WIN32, NativeMethods.SERVICE_STATE_ALL, buffer, bufferSize, out needed, out returned, ref resume, null);
                        int error = complete ? 0 : Marshal.GetLastWin32Error();
                        ReadEnumerationBuffer(manager, buffer, returned, result);
                        if (complete) break;
                        if (error != 234)
                        {
                            CollectionState = CollectorOutcomeClassifier.ServiceState(true, 0, false, error, result.Count, 0);
                            AddDiagnostic("ENUMERATE", "EnumServicesStatusEx", null, "SC_MANAGER_ENUMERATE_SERVICE", error, error == 5 ? "GLOBAL_ACCESS_DENIED" : "API_ERROR", "Service enumeration stopped before completion.");
                            return result;
                        }
                    }
                    finally { Marshal.FreeHGlobal(buffer); }
                }
            }
            finally { NativeMethods.CloseServiceHandle(manager); }
            CollectionState = CollectorOutcomeClassifier.ServiceState(true, 0, true, 0, result.Count, objectReadFailure ? 1 : 0); return result;
        }

        private void ReadEnumerationBuffer(IntPtr manager, IntPtr buffer, int returned, List<WindowsService> result)
        {
            int size = Marshal.SizeOf(typeof(NativeMethods.EnumServiceStatusProcess));
            for (int i = 0; i < returned; i++)
            {
                NativeMethods.EnumServiceStatusProcess raw = (NativeMethods.EnumServiceStatusProcess)Marshal.PtrToStructure(IntPtr.Add(buffer, i * size), typeof(NativeMethods.EnumServiceStatusProcess));
                result.Add(ReadService(manager, raw));
            }
        }

        private WindowsService ReadService(IntPtr manager, NativeMethods.EnumServiceStatusProcess raw)
        {
            WindowsService item = new WindowsService { Name = raw.ServiceName, DisplayName = raw.DisplayName, State = StateName(raw.Status.CurrentState), ProcessId = (int)raw.Status.ProcessId, ServiceType = "0x" + raw.Status.ServiceType.ToString("X"), CanChangeConfig = TriState.Unknown, CanStart = TriState.Unknown, CanStop = TriState.Unknown, UnquotedCandidates = new List<string>() };
            IntPtr service = NativeMethods.OpenService(manager, raw.ServiceName, NativeMethods.SERVICE_QUERY_CONFIG);
            if (service == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error(); objectReadFailure = true;
                item.Errors.Add("Configuration unavailable: " + error);
                AddDiagnostic("SERVICE_CONFIG", "OpenService", raw.ServiceName, "SERVICE_QUERY_CONFIG (0x0001)", error, ErrorClassification(error, "SERVICE"), "The service remains enumerated; only its configuration is unknown.");
            }
            else
            {
                try
                {
                    int needed; NativeMethods.QueryServiceConfig(service, IntPtr.Zero, 0, out needed);
                    if (needed <= 0)
                    {
                        int error = Marshal.GetLastWin32Error(); objectReadFailure = true; item.Errors.Add("QueryServiceConfig size unavailable: " + error);
                        AddDiagnostic("SERVICE_CONFIG", "QueryServiceConfig", raw.ServiceName, "SERVICE_QUERY_CONFIG", error, ErrorClassification(error, "SERVICE"), "Unable to determine the configuration buffer size.");
                    }
                    else
                    {
                        IntPtr config = Marshal.AllocHGlobal(needed);
                        try
                        {
                            if (NativeMethods.QueryServiceConfig(service, config, needed, out needed))
                            {
                                NativeMethods.QueryServiceConfigStruct c = (NativeMethods.QueryServiceConfigStruct)Marshal.PtrToStructure(config, typeof(NativeMethods.QueryServiceConfigStruct));
                                item.BinaryPath = c.BinaryPathName; item.Account = c.ServiceStartName; item.StartType = StartName(c.StartType);
                                string executable, args;
                                PathResolver.SplitCommandLine(c.BinaryPathName, out executable, out args);
                                BinaryPathResolution resolution = BinaryPathResolver.Resolve(executable, null, false);
                                item.ExecutablePath = resolution.Path; item.Arguments = args; item.UnquotedCandidates = PathResolver.GetUnquotedCandidates(c.BinaryPathName);
                                foreach (string candidate in item.UnquotedCandidates)
                                {
                                    if (File.Exists(candidate)) item.UnquotedCandidatePermissions.Add(access.EvaluatePath(candidate, false));
                                    else item.UnquotedCandidatePermissions.Add(access.EvaluatePath(Path.GetDirectoryName(candidate), true));
                                }
                                item.ExecutablePermission = resolution.IsAmbiguous && !Path.IsPathRooted(resolution.Path ?? String.Empty) ? UnknownPermission(resolution.Path, "File", resolution.Detail) : access.EvaluatePath(resolution.Path, false);
                                string directory = String.IsNullOrEmpty(resolution.Path) ? null : Path.GetDirectoryName(resolution.Path);
                                item.DirectoryPermission = access.EvaluatePath(directory, true);
                            }
                            else
                            {
                                int error = Marshal.GetLastWin32Error(); objectReadFailure = true; item.Errors.Add("QueryServiceConfig failed: " + error);
                                AddDiagnostic("SERVICE_CONFIG", "QueryServiceConfig", raw.ServiceName, "SERVICE_QUERY_CONFIG", error, ErrorClassification(error, "SERVICE"), "The enumerated service configuration could not be read.");
                            }
                        }
                        finally { Marshal.FreeHGlobal(config); }
                    }
                }
                catch (Exception ex) { objectReadFailure = true; item.Errors.Add(ex.GetType().Name + ": " + ex.Message); AddDiagnostic("SERVICE_CONFIG", "QueryServiceConfig", raw.ServiceName, "SERVICE_QUERY_CONFIG", 0, "API_ERROR", ex.Message); }
                finally { NativeMethods.CloseServiceHandle(service); }
            }
            IntPtr securityHandle = NativeMethods.OpenService(manager, raw.ServiceName, NativeMethods.READ_CONTROL);
            if (securityHandle != IntPtr.Zero)
            {
                try
                {
                    uint securityNeeded; bool sized = NativeMethods.QueryServiceObjectSecurity(securityHandle, 0x00000007, null, 0, out securityNeeded);
                    if (securityNeeded > 0)
                    {
                        byte[] descriptor = new byte[securityNeeded];
                        if (NativeMethods.QueryServiceObjectSecurity(securityHandle, 0x00000007, descriptor, securityNeeded, out securityNeeded)) item.SecurityDescriptorSddl = new RawSecurityDescriptor(descriptor, 0).GetSddlForm(AccessControlSections.All);
                        else { int error = Marshal.GetLastWin32Error(); objectReadFailure = true; item.Errors.Add("Service security descriptor query failed: " + error); AddDiagnostic("SERVICE_SECURITY", "QueryServiceObjectSecurity", raw.ServiceName, "READ_CONTROL (0x00020000)", error, ErrorClassification(error, "SERVICE"), "Owner, group, and DACL could not be read."); }
                    }
                    else if (!sized) { int error = Marshal.GetLastWin32Error(); objectReadFailure = true; item.Errors.Add("Service security descriptor size unavailable: " + error); AddDiagnostic("SERVICE_SECURITY", "QueryServiceObjectSecurity", raw.ServiceName, "READ_CONTROL (0x00020000)", error, ErrorClassification(error, "SERVICE"), "Unable to determine the security descriptor buffer size."); }
                }
                catch (Exception ex) { item.Errors.Add("Security descriptor: " + ex.Message); }
                finally { NativeMethods.CloseServiceHandle(securityHandle); }
            }
            else { int error = Marshal.GetLastWin32Error(); objectReadFailure = true; item.Errors.Add("Service security descriptor unavailable: " + error); AddDiagnostic("SERVICE_SECURITY", "OpenService", raw.ServiceName, "READ_CONTROL (0x00020000)", error, ErrorClassification(error, "SERVICE"), "Rights probes continue independently."); }
            IntPtr change = NativeMethods.OpenService(manager, raw.ServiceName, NativeMethods.SERVICE_CHANGE_CONFIG);
            if (change != IntPtr.Zero) { item.CanChangeConfig = TriState.Yes; NativeMethods.CloseServiceHandle(change); }
            else { int error = Marshal.GetLastWin32Error(); item.CanChangeConfig = error == 5 ? TriState.No : TriState.Unknown; AddRightDiagnostic(raw.ServiceName, "SERVICE_CHANGE_CONFIG (0x0002)", error); }
            AddEffectiveRight(item, "SERVICE_CHANGE_CONFIG", item.CanChangeConfig);
            IntPtr start = NativeMethods.OpenService(manager, raw.ServiceName, NativeMethods.SERVICE_START);
            if (start != IntPtr.Zero) { item.CanStart = TriState.Yes; NativeMethods.CloseServiceHandle(start); }
            else { int error = Marshal.GetLastWin32Error(); item.CanStart = error == 5 ? TriState.No : TriState.Unknown; AddRightDiagnostic(raw.ServiceName, "SERVICE_START (0x0010)", error); }
            AddEffectiveRight(item, "SERVICE_START", item.CanStart);
            IntPtr stop = NativeMethods.OpenService(manager, raw.ServiceName, NativeMethods.SERVICE_STOP);
            if (stop != IntPtr.Zero) { item.CanStop = TriState.Yes; NativeMethods.CloseServiceHandle(stop); }
            else { int error = Marshal.GetLastWin32Error(); item.CanStop = error == 5 ? TriState.No : TriState.Unknown; AddRightDiagnostic(raw.ServiceName, "SERVICE_STOP (0x0020)", error); }
            AddEffectiveRight(item, "SERVICE_STOP", item.CanStop);
            return item;
        }

        private void AddDiagnostic(string stage, string api, string objectName, string requestedAccess, int error, string classification, string detail)
        {
            Diagnostics.Add(new CollectorDiagnostic { Collector = "Services", Stage = stage, Api = api, ObjectName = objectName, RequestedAccess = requestedAccess, Win32Error = error, Classification = classification, Detail = detail });
            Errors.Add(api + (String.IsNullOrEmpty(objectName) ? String.Empty : "(" + objectName + ")") + " failed: " + error + " [" + classification + "]");
        }

        private void AddRightDiagnostic(string serviceName, string requestedAccess, int error)
        {
            Diagnostics.Add(new CollectorDiagnostic { Collector = "Services", Stage = "EFFECTIVE_RIGHT", Api = "OpenService", ObjectName = serviceName, RequestedAccess = requestedAccess, Win32Error = error, Classification = error == 5 ? "RIGHT_DENIED" : error == 1060 ? "OBJECT_NOT_FOUND" : "API_ERROR", Detail = error == 5 ? "The current token was denied this exact right; no modification was attempted." : "The effective right is unknown because the access probe failed for a reason other than access denial." });
        }

        private static string ErrorClassification(int error, string scope)
        {
            if (error == 5) return scope + "_ACCESS_DENIED";
            if (error == 1060) return "OBJECT_NOT_FOUND";
            return "API_ERROR";
        }

        private static void AddEffectiveRight(WindowsService service, string right, TriState state)
        {
            service.EffectiveRights.Add(new EffectiveServiceRight { Right = right, Granted = state, EvaluationMethod = "OpenService desired-access check", Provenance = "UNKNOWN", Detail = "Effective aggregate access was tested against the current token; the granting ACE was not attributed." });
        }

        private static SecurityPermission UnknownPermission(string target, string type, string detail) { return new SecurityPermission { Target = target, ObjectType = type, CanWrite = TriState.Unknown, CanCreate = TriState.Unknown, CanDelete = TriState.Unknown, CanChangePermissions = TriState.Unknown, Detail = detail }; }

        private static string StateName(uint value) { return value == 4 ? "Running" : value == 1 ? "Stopped" : value.ToString(); }
        private static string StartName(uint value) { return value == 2 ? "Automatic" : value == 3 ? "Manual" : value == 4 ? "Disabled" : value.ToString(); }
    }

    public sealed class DnsServerCollector
    {
        private const string DnsParameters = @"SYSTEM\CurrentControlSet\Services\DNS\Parameters";
        private readonly AccessEvaluator access = new AccessEvaluator();

        public DnsServerSnapshot Collect(IList<WindowsService> services, string serviceEnumerationState)
        {
            return Collect(services, serviceEnumerationState, true);
        }

        public DnsServerSnapshot Collect(IList<WindowsService> services, string serviceEnumerationState, bool allowDirectedQuery)
        {
            DnsServerSnapshot result = new DnsServerSnapshot { Present = TriState.No, CanConfigurePlugin = TriState.Unknown, CanChangeConfig = TriState.Unknown, CanStart = TriState.Unknown, CanStop = TriState.Unknown, ConfigurationReadState = "NOT_APPLICABLE", RightProvenance = "UNKNOWN" };
            WindowsService dns = services == null ? null : new List<WindowsService>(services).Find(s => String.Equals(s.Name, "DNS", StringComparison.OrdinalIgnoreCase));
            if (dns == null)
            {
                if (String.Equals(serviceEnumerationState, "OBSERVED", StringComparison.OrdinalIgnoreCase)) return result;
                if (!allowDirectedQuery || !CollectDirected(result)) { result.Present = TriState.Unknown; result.ConfigurationReadState = "UNKNOWN"; result.Errors.Add("DNS Server presence is unknown because service enumeration state is " + (serviceEnumerationState ?? "UNKNOWN") + " and the directed DNS service query did not establish presence."); return result; }
                if (result.Present != TriState.Yes) return result;
            }
            else { result.Present = TriState.Yes; result.ServiceName = dns.Name; result.DisplayName = dns.DisplayName; result.State = dns.State; result.StartType = dns.StartType; result.Account = dns.Account; result.CanChangeConfig = dns.CanChangeConfig; result.CanStart = dns.CanStart; result.CanStop = dns.CanStop; }
            if (Environment.OSVersion.Platform != PlatformID.Win32NT) { result.ConfigurationReadState = "UNKNOWN"; result.Errors.Add("DNS Server registry collection is available only on Windows."); return result; }
            RegistryKey root = null, key = null;
            try
            {
                RegistryView view = Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default;
                root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                key = root.OpenSubKey(DnsParameters, false);
                if (key == null) { result.ConfigurationReadState = "UNKNOWN"; result.Errors.Add("DNS Server Parameters key is missing or inaccessible."); return result; }
                object value = key.GetValue("ServerLevelPluginDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                result.ServerLevelPluginDll = value == null ? null : Convert.ToString(value);
                result.ConfigurationReadState = "OBSERVED";
                SecurityPermission permission = access.EvaluateRegistryKey(key, @"HKLM\" + DnsParameters);
                result.CanConfigurePlugin = permission.CanWrite;
                result.RightProvenance = permission.CanWrite == TriState.Unknown ? "UNKNOWN" : "Registry AccessCheck (KEY_SET_VALUE); granting ACE not attributed";
            }
            catch (UnauthorizedAccessException ex) { result.ConfigurationReadState = "ACCESS_DENIED"; result.Errors.Add("Access denied: " + ex.Message); }
            catch (Exception ex) { result.ConfigurationReadState = "UNKNOWN"; result.Errors.Add(ex.GetType().Name + ": " + ex.Message); }
            finally { if (key != null) key.Dispose(); if (root != null) root.Dispose(); }
            return result;
        }

        private static bool CollectDirected(DnsServerSnapshot result)
        {
            IntPtr manager = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_CONNECT);
            if (manager == IntPtr.Zero) { result.Errors.Add("Directed OpenSCManager failed: " + Marshal.GetLastWin32Error()); return false; }
            IntPtr service = IntPtr.Zero;
            try
            {
                service = NativeMethods.OpenService(manager, "DNS", NativeMethods.SERVICE_QUERY_CONFIG | NativeMethods.SERVICE_QUERY_STATUS);
                if (service == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 1060) { result.Present = TriState.No; result.ConfigurationReadState = "NOT_APPLICABLE"; return true; }
                    result.Errors.Add("Directed OpenService(DNS) failed: " + error); return false;
                }
                result.Present = TriState.Yes; result.ServiceName = "DNS"; result.DisplayName = "DNS Server";
                int needed; NativeMethods.QueryServiceConfig(service, IntPtr.Zero, 0, out needed);
                if (needed > 0)
                {
                    IntPtr config = Marshal.AllocHGlobal(needed);
                    try { if (NativeMethods.QueryServiceConfig(service, config, needed, out needed)) { NativeMethods.QueryServiceConfigStruct c = (NativeMethods.QueryServiceConfigStruct)Marshal.PtrToStructure(config, typeof(NativeMethods.QueryServiceConfigStruct)); result.Account = c.ServiceStartName; result.StartType = c.StartType == 2 ? "Automatic" : c.StartType == 3 ? "Manual" : c.StartType == 4 ? "Disabled" : c.StartType.ToString(); } }
                    finally { Marshal.FreeHGlobal(config); }
                }
                NativeMethods.ServiceStatus status; if (NativeMethods.QueryServiceStatus(service, out status)) result.State = status.CurrentState == 4 ? "Running" : status.CurrentState == 1 ? "Stopped" : status.CurrentState.ToString();
            }
            finally { if (service != IntPtr.Zero) NativeMethods.CloseServiceHandle(service); NativeMethods.CloseServiceHandle(manager); }
            result.CanChangeConfig = CheckServiceRight(NativeMethods.SERVICE_CHANGE_CONFIG); result.CanStart = CheckServiceRight(NativeMethods.SERVICE_START); result.CanStop = CheckServiceRight(NativeMethods.SERVICE_STOP);
            return true;
        }

        private static TriState CheckServiceRight(uint right)
        {
            IntPtr manager = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_CONNECT); if (manager == IntPtr.Zero) return TriState.Unknown;
            try { IntPtr service = NativeMethods.OpenService(manager, "DNS", right); if (service != IntPtr.Zero) { NativeMethods.CloseServiceHandle(service); return TriState.Yes; } return Marshal.GetLastWin32Error() == 5 ? TriState.No : TriState.Unknown; }
            finally { NativeMethods.CloseServiceHandle(manager); }
        }
    }

    public sealed class RegistryCollector
    {
        private const string ServicesPath = @"SYSTEM\CurrentControlSet\Services";
        private readonly AccessEvaluator access = new AccessEvaluator();
        public RegistryCollector() { Errors = new List<string>(); }
        public List<string> Errors { get; private set; }

        public void Collect(IList<WindowsService> services)
        {
            if (services == null || services.Count == 0) return;
            if (Environment.OSVersion.Platform != PlatformID.Win32NT) { Errors.Add("Targeted service registry collection is available only on Windows."); return; }
            RegistryView[] views = Environment.Is64BitOperatingSystem ? new[] { RegistryView.Registry64, RegistryView.Registry32 } : new[] { RegistryView.Default };
            foreach (RegistryView view in views)
            {
                RegistryKey root = null;
                try
                {
                    root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                    foreach (WindowsService service in services) ReadService(root, view, service);
                }
                catch (Exception ex) { Errors.Add(view + ": " + ex.GetType().Name + ": " + ex.Message); }
                finally { if (root != null) root.Dispose(); }
            }
        }

        private void ReadService(RegistryKey root, RegistryView view, WindowsService service)
        {
            string relative = ServicesPath + @"\" + service.Name;
            string display = @"HKLM\" + relative;
            ServiceRegistryEvidence evidence = new ServiceRegistryEvidence { View = view.ToString(), ServiceKeyPath = display, ParametersKeyPath = display + @"\Parameters", ServiceDllExists = TriState.Unknown };
            RegistryKey key = null, parameters = null;
            try
            {
                key = root.OpenSubKey(relative, false);
                if (key == null)
                {
                    evidence.ServiceKeyPermission = Unknown(display, "Service registry key is missing or inaccessible.");
                    evidence.Errors.Add("Service registry key is missing or inaccessible.");
                    service.RegistryEvidence.Add(evidence); return;
                }
                evidence.ServiceKeyPermission = access.EvaluateRegistryKey(key, display);
                evidence.ImagePath = ReadString(key, "ImagePath", evidence.Errors);
                parameters = key.OpenSubKey("Parameters", false);
                evidence.ParametersKeyPermission = parameters == null ? Unknown(evidence.ParametersKeyPath, "Parameters subkey does not exist or is inaccessible.") : access.EvaluateRegistryKey(parameters, evidence.ParametersKeyPath);
                evidence.ServiceDll = parameters == null ? null : ReadString(parameters, "ServiceDll", evidence.Errors);
                if (String.IsNullOrWhiteSpace(evidence.ServiceDll)) evidence.ServiceDll = ReadString(key, "ServiceDll", evidence.Errors);
                if (!String.IsNullOrWhiteSpace(evidence.ServiceDll))
                {
                    evidence.ServiceDllPath = ResolveConfiguredFile(evidence.ServiceDll, evidence.Errors);
                    if (!String.IsNullOrWhiteSpace(evidence.ServiceDllPath))
                    {
                        evidence.ServiceDllExists = File.Exists(evidence.ServiceDllPath) ? TriState.Yes : TriState.No;
                        evidence.ServiceDllPermission = access.EvaluatePath(evidence.ServiceDllPath, false);
                        string directory = null; try { directory = Path.GetDirectoryName(evidence.ServiceDllPath); } catch { }
                        evidence.ServiceDllDirectoryPermission = access.EvaluatePath(directory, true);
                    }
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                evidence.Errors.Add("Access denied: " + ex.Message);
                if (evidence.ServiceKeyPermission == null) evidence.ServiceKeyPermission = Unknown(display, "Access denied: " + ex.Message);
            }
            catch (Exception ex) { evidence.Errors.Add(ex.GetType().Name + ": " + ex.Message); }
            finally
            {
                if (parameters != null) parameters.Dispose();
                if (key != null) key.Dispose();
            }
            service.RegistryEvidence.Add(evidence);
        }

        private static string ReadString(RegistryKey key, string name, List<string> errors)
        {
            try { object value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames); return value == null ? null : Convert.ToString(value); }
            catch (Exception ex) { errors.Add(name + ": " + ex.GetType().Name + ": " + ex.Message); return null; }
        }

        internal static string ResolveConfiguredFile(string value, List<string> errors)
        {
            if (String.IsNullOrWhiteSpace(value)) return null;
            try
            {
                string path = Environment.ExpandEnvironmentVariables(value.Trim().Trim('"'));
                if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), path.Substring(12));
                else if (path.StartsWith(@"SystemRoot\", StringComparison.OrdinalIgnoreCase)) path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), path.Substring(11));
                return Path.GetFullPath(path);
            }
            catch (Exception ex) { if (errors != null) errors.Add("ServiceDll path: " + ex.GetType().Name + ": " + ex.Message); return null; }
        }

        private static SecurityPermission Unknown(string target, string detail)
        {
            return new SecurityPermission { Target = target, ObjectType = "RegistryKey", CanWrite = TriState.Unknown, CanCreate = TriState.Unknown, CanDelete = TriState.Unknown, CanChangePermissions = TriState.Unknown, Detail = detail };
        }
    }

    public sealed class ScheduledTaskCollector
    {
        private readonly AccessEvaluator access = new AccessEvaluator();
        private bool partial;
        public ScheduledTaskCollector() { Errors = new List<string>(); Diagnostics = new List<CollectorDiagnostic>(); CollectionState = "UNKNOWN"; }
        public List<string> Errors { get; private set; }
        public List<CollectorDiagnostic> Diagnostics { get; private set; }
        public string CollectionState { get; private set; }
        public List<ScheduledTaskInfo> Collect()
        {
            List<ScheduledTaskInfo> result = new List<ScheduledTaskInfo>();
            Type type = Type.GetTypeFromProgID("Schedule.Service");
            if (type == null) { AddDiagnostic("CONNECT", "Type.GetTypeFromProgID", null, 0, "INTERFACE_UNAVAILABLE", "Task Scheduler COM service is unavailable."); return result; }
            object service = null;
            try
            {
                service = Activator.CreateInstance(type); dynamic scheduler = service;
                try { scheduler.Connect(); }
                catch (Exception ex) { CollectionState = CollectorOutcomeClassifier.TaskState(false, ExceptionHResult(ex), 0, 0, 0); AddExceptionDiagnostic("CONNECT", "ITaskService.Connect", null, ex, IsAccessDenied(ex) ? "GLOBAL_ACCESS_DENIED" : "API_ERROR"); return result; }
                dynamic root;
                try { root = scheduler.GetFolder("\\"); }
                catch (Exception ex) { CollectionState = CollectorOutcomeClassifier.TaskState(false, ExceptionHResult(ex), 0, 0, 0); AddExceptionDiagnostic("ROOT_FOLDER", "ITaskService.GetFolder", "\\", ex, IsAccessDenied(ex) ? "GLOBAL_ACCESS_DENIED" : "API_ERROR"); return result; }
                partial = false; Walk(root, "\\", result); CollectionState = CollectorOutcomeClassifier.TaskState(true, 0, result.Count, partial ? 1 : 0, 0);
            }
            catch (Exception ex) { CollectionState = IsAccessDenied(ex) ? "ACCESS_DENIED" : "UNKNOWN"; AddExceptionDiagnostic("INITIALIZE", "Schedule.Service", null, ex, IsAccessDenied(ex) ? "GLOBAL_ACCESS_DENIED" : "API_ERROR"); }
            finally { if (service != null && Marshal.IsComObject(service)) Marshal.FinalReleaseComObject(service); }
            return result;
        }

        private void Walk(dynamic folder, string folderPath, List<ScheduledTaskInfo> result)
        {
            dynamic tasks = null;
            try
            {
                tasks = folder.GetTasks(1);
                int count = Convert.ToInt32(tasks.Count);
                for (int i = 1; i <= count; i++)
                {
                    try
                    {
                        dynamic task = tasks[i];
                        ScheduledTaskInfo item = ReadTask(task, folderPath);
                        if (item != null) result.Add(item);
                    }
                    catch (Exception ex) { partial = true; AddExceptionDiagnostic("TASK", "IRegisteredTaskCollection.Item", folderPath + "#" + i, ex, IsAccessDenied(ex) ? "TASK_ACCESS_DENIED" : "API_ERROR"); }
                }
            }
            catch (Exception ex) { partial = true; AddExceptionDiagnostic("FOLDER_TASKS", "ITaskFolder.GetTasks", folderPath, ex, IsAccessDenied(ex) ? "FOLDER_ACCESS_DENIED" : "API_ERROR"); }

            try
            {
                dynamic folders = folder.GetFolders(0);
                int count = Convert.ToInt32(folders.Count);
                for (int i = 1; i <= count; i++)
                {
                    try
                    {
                        dynamic child = folders[i]; string childPath = SafeString(delegate { return Convert.ToString(child.Path); }, folderPath + "#folder" + i);
                        Walk(child, childPath, result);
                    }
                    catch (Exception ex) { partial = true; AddExceptionDiagnostic("FOLDER", "ITaskFolderCollection.Item", folderPath + "#" + i, ex, IsAccessDenied(ex) ? "FOLDER_ACCESS_DENIED" : "API_ERROR"); }
                }
            }
            catch (Exception ex) { partial = true; AddExceptionDiagnostic("FOLDER_CHILDREN", "ITaskFolder.GetFolders", folderPath, ex, IsAccessDenied(ex) ? "FOLDER_ACCESS_DENIED" : "API_ERROR"); }
        }

        private ScheduledTaskInfo ReadTask(dynamic task, string folderPath)
        {
            ScheduledTaskInfo item = new ScheduledTaskInfo();
            try
            {
                item.Name = Convert.ToString(task.Name); item.Path = Convert.ToString(task.Path); item.Enabled = Convert.ToBoolean(task.Enabled); item.State = Convert.ToString(task.State);
                dynamic definition = task.Definition; item.Principal = Convert.ToString(definition.Principal.UserId); item.RunLevel = Convert.ToString(definition.Principal.RunLevel);
                item.PrincipalIsHigher = String.IsNullOrWhiteSpace(item.Principal) ? TriState.Unknown : (PathResolver.IsPrivilegedPrincipal(item.Principal) || item.RunLevel == "1" ? TriState.Yes : TriState.No);
                try { string sddl = Convert.ToString(task.GetSecurityDescriptor(4)); item.CanModify = access.EvaluateSddl(sddl, 0x00040000); }
                catch (Exception ex) { item.CanModify = TriState.Unknown; partial = true; AddExceptionDiagnostic("TASK_SECURITY", "IRegisteredTask.GetSecurityDescriptor", item.Path, ex, IsAccessDenied(ex) ? "TASK_ACCESS_DENIED" : "API_ERROR"); }
                try { foreach (dynamic trigger in definition.Triggers) item.Triggers.Add(Convert.ToString(trigger.Type) + ": " + Convert.ToString(trigger)); }
                catch (Exception ex) { partial = true; item.Errors.Add("Triggers: " + ex.Message); AddExceptionDiagnostic("TASK_TRIGGERS", "ITaskDefinition.Triggers", item.Path, ex, IsAccessDenied(ex) ? "TASK_ACCESS_DENIED" : "API_ERROR"); }
                foreach (dynamic action in definition.Actions)
                {
                    ScheduledTaskAction a = new ScheduledTaskAction();
                    try
                    {
                        a.Type = Convert.ToString(action.Type);
                        if (Convert.ToInt32(action.Type) == 0)
                        {
                            a.OriginalExecutable = Convert.ToString(action.Path); a.Arguments = Convert.ToString(action.Arguments); a.WorkingDirectory = Convert.ToString(action.WorkingDirectory);
                            BinaryPathResolution resolution = BinaryPathResolver.Resolve(a.OriginalExecutable, a.WorkingDirectory, false); a.Executable = resolution.Path; a.PathAmbiguous = resolution.IsAmbiguous; a.PathResolutionDetail = resolution.Detail;
                            a.TargetPermission = resolution.IsAmbiguous && !Path.IsPathRooted(resolution.Path ?? String.Empty) ? new SecurityPermission { Target = resolution.Path, ObjectType = "File", CanWrite = TriState.Unknown, CanCreate = TriState.Unknown, CanDelete = TriState.Unknown, CanChangePermissions = TriState.Unknown, Detail = resolution.Detail } : access.EvaluatePath(a.Executable, false);
                            a.HijackCandidates = PathResolver.GetUnquotedCandidates(a.OriginalExecutable + (String.IsNullOrEmpty(a.Arguments) ? "" : " " + a.Arguments));
                            foreach (string candidate in a.HijackCandidates)
                            {
                                if (File.Exists(candidate)) a.HijackCandidatePermissions.Add(access.EvaluatePath(candidate, false));
                                else a.HijackCandidatePermissions.Add(access.EvaluatePath(Path.GetDirectoryName(candidate), true));
                            }
                            a.ReferencedScript = PathResolver.IsScript(a.Executable) ? a.Executable : PathResolver.FindScriptReference(a.Arguments, a.WorkingDirectory);
                            if (!String.IsNullOrWhiteSpace(a.ReferencedScript)) a.ScriptPermission = PathResolver.IsScript(a.Executable) && BinaryPathResolver.SamePath(a.Executable, a.ReferencedScript) ? a.TargetPermission : access.EvaluatePath(a.ReferencedScript, false);
                        }
                    }
                    catch (Exception ex) { partial = true; item.Errors.Add("Action: " + ex.Message); AddExceptionDiagnostic("TASK_ACTION", "IActionCollection.Item", item.Path, ex, IsAccessDenied(ex) ? "TASK_ACCESS_DENIED" : "API_ERROR"); }
                    item.Actions.Add(a);
                }
            }
            catch (Exception ex) { partial = true; item.Errors.Add(ex.GetType().Name + ": " + ex.Message); AddExceptionDiagnostic("TASK_DEFINITION", "IRegisteredTask.Definition", item.Path ?? folderPath, ex, IsAccessDenied(ex) ? "TASK_ACCESS_DENIED" : "API_ERROR"); }
            return item;
        }

        private void AddExceptionDiagnostic(string stage, string api, string objectName, Exception ex, string classification)
        {
            AddDiagnostic(stage, api, objectName, ExceptionHResult(ex), classification, ex.Message);
        }

        private void AddDiagnostic(string stage, string api, string objectName, int hresult, string classification, string detail)
        {
            Diagnostics.Add(new CollectorDiagnostic { Collector = "Tasks", Stage = stage, Api = api, ObjectName = objectName, HResult = hresult, Win32Error = (hresult & 0xFFFF), Classification = classification, Detail = detail });
            Errors.Add(api + (String.IsNullOrEmpty(objectName) ? String.Empty : "(" + objectName + ")") + ": " + detail + " [" + classification + "]");
        }

        internal static bool IsAccessDenied(Exception ex)
        {
            if (ex == null) return false;
            return ex is UnauthorizedAccessException || ExceptionHResult(ex) == unchecked((int)0x80070005) || ex.Message.IndexOf("0x80070005", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static int ExceptionHResult(Exception ex) { return ex == null ? 0 : Marshal.GetHRForException(ex); }

        private static string SafeString(Func<string> getter, string fallback)
        {
            try { string value = getter(); return String.IsNullOrEmpty(value) ? fallback : value; } catch { return fallback; }
        }
    }

    // Pure classification seam used by collectors and controlled-response regression tests.
    // It performs no Windows operation and never turns missing evidence into absence.
    public static class CollectorOutcomeClassifier
    {
        public const uint ScManagerEnumerateService = 0x0004;
        public const uint ServiceQueryConfig = 0x0001;
        public const uint ServiceChangeConfig = 0x0002;
        public const uint ServiceQueryStatus = 0x0004;

        public static string ServiceState(bool managerOpened, int managerError, bool enumerationComplete, int enumerationError, int observedObjects, int objectReadFailures)
        {
            if (!managerOpened) return managerError == 5 ? "ACCESS_DENIED" : "UNKNOWN";
            if (!enumerationComplete) return observedObjects > 0 ? "PARTIAL" : enumerationError == 5 ? "ACCESS_DENIED" : "UNKNOWN";
            return objectReadFailures > 0 ? "PARTIAL" : "OBSERVED";
        }

        public static string TaskState(bool connected, int connectionHResult, int observedObjects, int folderFailures, int taskFailures)
        {
            if (!connected) return connectionHResult == unchecked((int)0x80070005) ? "ACCESS_DENIED" : "UNKNOWN";
            return folderFailures > 0 || taskFailures > 0 ? "PARTIAL" : "OBSERVED";
        }

        public static string AccessProbeClassification(int win32Error)
        {
            if (win32Error == 0) return "GRANTED";
            if (win32Error == 5) return "DENIED";
            if (win32Error == 1060) return "OBJECT_NOT_FOUND";
            return "UNKNOWN";
        }
    }
}
