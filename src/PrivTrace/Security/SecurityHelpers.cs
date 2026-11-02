using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using PrivTrace.Interop;
using PrivTrace.Models;

namespace PrivTrace.Security
{
    public sealed class BinaryPathResolution
    {
        public string Original { get; set; }
        public string Path { get; set; }
        public string Arguments { get; set; }
        public TriState Exists { get; set; }
        public bool IsAmbiguous { get; set; }
        public bool ObservedImage { get; set; }
        public string Detail { get; set; }
    }

    public static class BinaryPathResolver
    {
        public static BinaryPathResolution Resolve(string reference, string workingDirectory, bool observedImage)
        {
            BinaryPathResolution result = new BinaryPathResolution { Original = reference, ObservedImage = observedImage, Exists = TriState.Unknown };
            if (String.IsNullOrWhiteSpace(reference)) { result.IsAmbiguous = true; result.Detail = "No executable reference was available."; return result; }
            string executable, arguments;
            if (observedImage) { executable = reference.Trim().Trim('"'); arguments = String.Empty; }
            else PathResolver.SplitCommandLine(reference, out executable, out arguments);
            result.Arguments = arguments;
            if (String.IsNullOrWhiteSpace(executable)) { result.IsAmbiguous = true; result.Detail = "The executable component could not be parsed."; return result; }
            executable = Environment.ExpandEnvironmentVariables(executable.Trim());
            if (executable.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), executable.Substring(12));
            else if (executable.StartsWith(@"SystemRoot\", StringComparison.OrdinalIgnoreCase)) executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), executable.Substring(11));
            try
            {
                if (!Path.IsPathRooted(executable))
                {
                    result.IsAmbiguous = true;
                    if (String.IsNullOrWhiteSpace(workingDirectory)) { result.Detail = "Relative path has no verified working directory."; result.Path = executable; return result; }
                    executable = Path.Combine(Environment.ExpandEnvironmentVariables(workingDirectory), executable);
                }
                result.Path = Path.GetFullPath(executable);
                result.Exists = File.Exists(result.Path) ? TriState.Yes : TriState.No;
                result.Detail = observedImage ? "Observed through QueryFullProcessImageName." : result.IsAmbiguous ? "Resolved relative to the configured working directory; runtime resolution remains context dependent." : "Resolved from configured execution metadata.";
            }
            catch (Exception ex) { result.Path = executable; result.IsAmbiguous = true; result.Detail = ex.GetType().Name + ": " + ex.Message; }
            return result;
        }

        public static bool SamePath(string left, string right)
        {
            if (String.IsNullOrWhiteSpace(left) || String.IsNullOrWhiteSpace(right)) return false;
            try { return String.Equals(Path.GetFullPath(left).TrimEnd('\\'), Path.GetFullPath(right).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase); }
            catch { return String.Equals(left.Trim().TrimEnd('\\'), right.Trim().TrimEnd('\\'), StringComparison.OrdinalIgnoreCase); }
        }
    }

    public static class PathResolver
    {
        private static readonly string[] ExecutableExtensions = { ".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js" };

        public static void SplitCommandLine(string commandLine, out string executable, out string arguments)
        {
            executable = null; arguments = null;
            if (String.IsNullOrWhiteSpace(commandLine)) return;
            string value = Environment.ExpandEnvironmentVariables(commandLine.Trim());
            if (value[0] == '"')
            {
                int end = value.IndexOf('"', 1);
                if (end > 0) { executable = value.Substring(1, end - 1); arguments = value.Substring(end + 1).Trim(); return; }
            }
            string lower = value.ToLowerInvariant();
            int best = -1;
            foreach (string ext in ExecutableExtensions)
            {
                int index = lower.IndexOf(ext, StringComparison.Ordinal);
                if (index >= 0 && (best < 0 || index < best)) best = index + ext.Length;
            }
            if (best > 0) { executable = value.Substring(0, best).Trim(); arguments = value.Substring(best).Trim(); }
            else
            {
                int space = value.IndexOf(' ');
                executable = space < 0 ? value : value.Substring(0, space);
                arguments = space < 0 ? String.Empty : value.Substring(space + 1).Trim();
            }
        }

        public static List<string> GetUnquotedCandidates(string commandLine)
        {
            List<string> candidates = new List<string>();
            if (String.IsNullOrWhiteSpace(commandLine) || commandLine.TrimStart().StartsWith("\"", StringComparison.Ordinal)) return candidates;
            string executable, args; SplitCommandLine(commandLine, out executable, out args);
            if (String.IsNullOrEmpty(executable) || executable.IndexOf(' ') < 0) return candidates;
            for (int i = executable.IndexOf(' '); i > 0; i = executable.IndexOf(' ', i + 1)) candidates.Add(executable.Substring(0, i) + ".exe");
            return candidates;
        }

        public static bool IsScript(string path)
        {
            string ext = Path.GetExtension(path ?? String.Empty).ToLowerInvariant();
            return ext == ".ps1" || ext == ".bat" || ext == ".cmd" || ext == ".vbs" || ext == ".js" || ext == ".wsf" || ext == ".py";
        }

        public static string FindScriptReference(string arguments, string workingDirectory)
        {
            if (String.IsNullOrWhiteSpace(arguments)) return null;
            List<string> tokens = new List<string>(); StringBuilder token = new StringBuilder(); bool quoted = false;
            foreach (char c in arguments)
            {
                if (c == '"') { quoted = !quoted; continue; }
                if (Char.IsWhiteSpace(c) && !quoted) { if (token.Length > 0) { tokens.Add(token.ToString()); token.Length = 0; } }
                else token.Append(c);
            }
            if (token.Length > 0) tokens.Add(token.ToString());
            foreach (string value in tokens)
            {
                string candidate = Environment.ExpandEnvironmentVariables(value.Trim());
                if (!IsScript(candidate)) continue;
                try { if (!Path.IsPathRooted(candidate) && !String.IsNullOrWhiteSpace(workingDirectory)) candidate = Path.GetFullPath(Path.Combine(Environment.ExpandEnvironmentVariables(workingDirectory), candidate)); } catch { }
                return candidate;
            }
            return null;
        }

        public static bool IsPrivilegedPrincipal(string principal)
        {
            if (String.IsNullOrWhiteSpace(principal)) return false;
            string p = principal.Replace(" ", String.Empty).ToUpperInvariant();
            return p == "SYSTEM" || p == "LOCALSYSTEM" || p == "NTAUTHORITY\\SYSTEM" ||
                p == "LOCALSERVICE" || p == "NTAUTHORITY\\LOCALSERVICE" ||
                p == "NETWORKSERVICE" || p == "NTAUTHORITY\\NETWORKSERVICE" ||
                p.EndsWith("\\ADMINISTRATOR", StringComparison.Ordinal) || p.EndsWith("\\ADMINISTRATORS", StringComparison.Ordinal);
        }
    }

    public sealed class AccessEvaluator
    {
        private int lastAccessCheckError;
        public int LastAccessCheckError { get { return lastAccessCheckError; } }
        private const uint FileWriteData = 0x0002, FileAppendData = 0x0004, FileDeleteChild = 0x0040, FileWriteAttributes = 0x0100;
        private const uint Delete = 0x00010000, WriteDac = 0x00040000, GenericRead = 0x80000000, GenericWrite = 0x40000000, GenericExecute = 0x20000000, GenericAll = 0x10000000;

        public SecurityPermission EvaluatePath(string path, bool directory)
        {
            SecurityPermission result = new SecurityPermission { Target = path, ObjectType = directory ? "Directory" : "File", CanWrite = TriState.Unknown, CanCreate = TriState.Unknown, CanDelete = TriState.Unknown, CanDeleteChildren = TriState.Unknown, CanChangePermissions = TriState.Unknown };
            try
            {
                if (String.IsNullOrWhiteSpace(path) || (!File.Exists(path) && !Directory.Exists(path))) { result.Detail = "Path does not exist or is inaccessible."; return result; }
                FileSystemSecurity security = directory ? (FileSystemSecurity)Directory.GetAccessControl(path, AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group) : File.GetAccessControl(path, AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group);
                byte[] descriptor = security.GetSecurityDescriptorBinaryForm();
                result.CanWrite = Check(descriptor, directory ? FileWriteData | FileAppendData : FileWriteData | FileAppendData | FileWriteAttributes);
                result.CanCreate = directory ? Check(descriptor, FileWriteData | FileAppendData) : TriState.No;
                result.CanDelete = Check(descriptor, Delete);
                result.CanDeleteChildren = directory ? Check(descriptor, FileDeleteChild) : TriState.No;
                result.CanChangePermissions = Check(descriptor, WriteDac);
                IdentityReference owner = security.GetOwner(typeof(SecurityIdentifier));
                if (owner != null)
                {
                    result.OwnerSid = owner.Value;
                    try { result.OwnerAccount = owner.Translate(typeof(NTAccount)).Value; } catch { result.OwnerAccount = owner.Value; }
                }
                AuthorizationRuleCollection entries = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
                foreach (FileSystemAccessRule entry in entries)
                {
                    string account; try { account = entry.IdentityReference.Translate(typeof(NTAccount)).Value; } catch { account = entry.IdentityReference.Value; }
                    result.AccessEntries.Add(new AccessEntryEvidence { Sid = entry.IdentityReference.Value, Account = account, Type = entry.AccessControlType.ToString(), Rights = entry.FileSystemRights.ToString(), Inherited = entry.IsInherited });
                }
                result.IntegrityConstraint = "UNKNOWN: mandatory integrity label requires SACL access and is not assumed from the DACL.";
                result.Detail = "DACL evaluated with AccessCheck against the current effective token; owner and allow/deny ACE evidence collected read-only." + (lastAccessCheckError == 0 ? String.Empty : " Last AccessCheck error=" + lastAccessCheckError + ".");
            }
            catch (UnauthorizedAccessException ex) { result.Detail = "Access denied: " + ex.Message; }
            catch (Exception ex) { result.Detail = ex.GetType().Name + ": " + ex.Message; }
            return result;
        }

        public TriState EvaluateSddl(string sddl, uint desiredAccess)
        {
            try { return Check(new RawSecurityDescriptor(sddl).GetBinaryForm(), desiredAccess); }
            catch { return TriState.Unknown; }
        }

        public TriState EvaluateRegistrySddl(string sddl, uint desiredAccess)
        {
            try { return Check(new RawSecurityDescriptor(sddl).GetBinaryForm(), desiredAccess, new NativeMethods.GenericMapping { GenericRead = 0x00020019, GenericWrite = 0x00020006, GenericExecute = 0x00020019, GenericAll = 0x000F003F }); }
            catch { return TriState.Unknown; }
        }

        public SecurityPermission EvaluateRegistryKey(RegistryKey key, string target)
        {
            SecurityPermission result = new SecurityPermission { Target = target, ObjectType = "RegistryKey", CanWrite = TriState.Unknown, CanCreate = TriState.Unknown, CanDelete = TriState.Unknown, CanDeleteChildren = TriState.No, CanChangePermissions = TriState.Unknown };
            if (key == null) { result.Detail = "Registry key does not exist or is inaccessible."; return result; }
            try
            {
                RegistrySecurity security = key.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group);
                byte[] descriptor = security.GetSecurityDescriptorBinaryForm();
                NativeMethods.GenericMapping mapping = new NativeMethods.GenericMapping { GenericRead = 0x00020019, GenericWrite = 0x00020006, GenericExecute = 0x00020019, GenericAll = 0x000F003F };
                result.CanWrite = Check(descriptor, 0x0002, mapping); // KEY_SET_VALUE
                result.CanCreate = Check(descriptor, 0x0004, mapping); // KEY_CREATE_SUB_KEY
                result.CanDelete = Check(descriptor, Delete, mapping);
                result.CanChangePermissions = Check(descriptor, WriteDac, mapping);
                IdentityReference owner = security.GetOwner(typeof(SecurityIdentifier));
                if (owner != null)
                {
                    result.OwnerSid = owner.Value;
                    try { result.OwnerAccount = owner.Translate(typeof(NTAccount)).Value; } catch { result.OwnerAccount = owner.Value; }
                }
                AuthorizationRuleCollection entries = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
                foreach (RegistryAccessRule entry in entries)
                {
                    string account; try { account = entry.IdentityReference.Translate(typeof(NTAccount)).Value; } catch { account = entry.IdentityReference.Value; }
                    result.AccessEntries.Add(new AccessEntryEvidence { Sid = entry.IdentityReference.Value, Account = account, Type = entry.AccessControlType.ToString(), Rights = entry.RegistryRights.ToString(), Inherited = entry.IsInherited });
                }
                result.IntegrityConstraint = "UNKNOWN: mandatory integrity label requires SACL access and is not assumed from the DACL.";
                result.Detail = "Registry DACL evaluated read-only with AccessCheck against the current effective token (KEY_SET_VALUE, KEY_CREATE_SUB_KEY, DELETE, WRITE_DAC).";
            }
            catch (UnauthorizedAccessException ex) { result.Detail = "Access denied: " + ex.Message; }
            catch (Exception ex) { result.Detail = ex.GetType().Name + ": " + ex.Message; }
            return result;
        }

        private TriState Check(byte[] descriptor, uint desiredAccess)
        {
            return Check(descriptor, desiredAccess, new NativeMethods.GenericMapping { GenericRead = 0x00120089, GenericWrite = 0x00120116, GenericExecute = 0x001200A0, GenericAll = 0x001F01FF });
        }

        private TriState Check(byte[] descriptor, uint desiredAccess, NativeMethods.GenericMapping mapping)
        {
            IntPtr primary = IntPtr.Zero, impersonation = IntPtr.Zero, privileges = IntPtr.Zero;
            try
            {
                lastAccessCheckError = 0;
                if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), NativeMethods.TOKEN_QUERY | NativeMethods.TOKEN_DUPLICATE, out primary)) { lastAccessCheckError = Marshal.GetLastWin32Error(); return TriState.Unknown; }
                if (!NativeMethods.DuplicateToken(primary, 2, out impersonation)) { lastAccessCheckError = Marshal.GetLastWin32Error(); return TriState.Unknown; }
                uint mapped = desiredAccess; NativeMethods.MapGenericMask(ref mapped, ref mapping);
                uint privilegeSize = 4096, granted; bool allowed;
                privileges = Marshal.AllocHGlobal((int)privilegeSize);
                bool ok = NativeMethods.AccessCheck(descriptor, impersonation, mapped, ref mapping, privileges, ref privilegeSize, out granted, out allowed);
                if (!ok && Marshal.GetLastWin32Error() == 122 && privilegeSize > 4096)
                {
                    Marshal.FreeHGlobal(privileges); privileges = Marshal.AllocHGlobal((int)privilegeSize);
                    ok = NativeMethods.AccessCheck(descriptor, impersonation, mapped, ref mapping, privileges, ref privilegeSize, out granted, out allowed);
                }
                if (!ok) lastAccessCheckError = Marshal.GetLastWin32Error();
                return ok ? (allowed ? TriState.Yes : TriState.No) : TriState.Unknown;
            }
            finally
            {
                if (privileges != IntPtr.Zero) Marshal.FreeHGlobal(privileges);
                if (impersonation != IntPtr.Zero) NativeMethods.CloseHandle(impersonation);
                if (primary != IntPtr.Zero) NativeMethods.CloseHandle(primary);
            }
        }
    }

    internal static class SecurityDescriptorExtensions
    {
        internal static byte[] GetBinaryForm(this RawSecurityDescriptor descriptor)
        {
            byte[] data = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(data, 0); return data;
        }
    }
}
