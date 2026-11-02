using System;
using System.Runtime.InteropServices;
using System.Text;

namespace PrivTrace.Interop
{
    internal static class NativeMethods
    {
        internal const uint TOKEN_QUERY = 0x0008;
        internal const uint TOKEN_DUPLICATE = 0x0002;
        internal const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const uint SE_PRIVILEGE_REMOVED = 0x00000004;
        internal const uint SE_GROUP_ENABLED = 0x00000004;
        internal const uint SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010;
        internal const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
        internal const uint SC_MANAGER_CONNECT = 0x0001;
        internal const uint SERVICE_QUERY_CONFIG = 0x0001;
        internal const uint SERVICE_CHANGE_CONFIG = 0x0002;
        internal const uint SERVICE_QUERY_STATUS = 0x0004;
        internal const uint SERVICE_START = 0x0010;
        internal const uint SERVICE_STOP = 0x0020;
        internal const uint READ_CONTROL = 0x00020000;
        internal const uint SERVICE_WIN32 = 0x00000030;
        internal const uint SERVICE_STATE_ALL = 0x00000003;
        internal const int SC_ENUM_PROCESS_INFO = 0;
        internal const uint PROCESS_QUERY_INFORMATION = 0x0400;
        internal const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        internal const uint TH32CS_SNAPPROCESS = 0x00000002;
        internal static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        internal enum TokenInformationClass
        {
            TokenUser = 1, TokenGroups = 2, TokenPrivileges = 3,
            TokenElevationType = 18, TokenElevation = 20, TokenIntegrityLevel = 25,
            TokenIsAppContainer = 29, TokenIsRestricted = 40
        }

        [StructLayout(LayoutKind.Sequential)] internal struct Luid { internal uint LowPart; internal int HighPart; }
        [StructLayout(LayoutKind.Sequential)] internal struct LuidAndAttributes { internal Luid Luid; internal uint Attributes; }
        [StructLayout(LayoutKind.Sequential)] internal struct SidAndAttributes { internal IntPtr Sid; internal uint Attributes; }
        [StructLayout(LayoutKind.Sequential)] internal struct TokenMandatoryLabel { internal SidAndAttributes Label; }
        [StructLayout(LayoutKind.Sequential)] internal struct TokenElevation { internal int TokenIsElevated; }
        [StructLayout(LayoutKind.Sequential)] internal struct GenericMapping { internal uint GenericRead, GenericWrite, GenericExecute, GenericAll; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct EnumServiceStatusProcess
        {
            [MarshalAs(UnmanagedType.LPWStr)] internal string ServiceName;
            [MarshalAs(UnmanagedType.LPWStr)] internal string DisplayName;
            internal ServiceStatusProcess Status;
        }
        [StructLayout(LayoutKind.Sequential)] internal struct ServiceStatusProcess
        {
            internal uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode,
                ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessId, ServiceFlags;
        }
        [StructLayout(LayoutKind.Sequential)] internal struct ServiceStatus
        {
            internal uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct QueryServiceConfigStruct
        {
            internal uint ServiceType, StartType, ErrorControl;
            [MarshalAs(UnmanagedType.LPWStr)] internal string BinaryPathName;
            [MarshalAs(UnmanagedType.LPWStr)] internal string LoadOrderGroup;
            internal uint TagId;
            [MarshalAs(UnmanagedType.LPWStr)] internal string Dependencies;
            [MarshalAs(UnmanagedType.LPWStr)] internal string ServiceStartName;
            [MarshalAs(UnmanagedType.LPWStr)] internal string DisplayName;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct ProcessEntry32
        {
            internal uint Size, Usage, ProcessId;
            internal IntPtr DefaultHeapId;
            internal uint ModuleId, Threads, ParentProcessId;
            internal int BasePriority;
            internal uint Flags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] internal string ExeFile;
        }

        [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern uint GetFinalPathNameByHandle(IntPtr file, StringBuilder path, uint pathLength, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder imageName, ref int size);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool IsWow64Process(IntPtr process, out bool wow64);
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "IsWow64Process2")] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool CloseHandle(IntPtr handle);
        [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool GetTokenInformation(IntPtr token, TokenInformationClass infoClass, IntPtr info, int length, out int returnLength);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool LookupPrivilegeName(string systemName, ref Luid luid, System.Text.StringBuilder name, ref int length);
        [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool DuplicateToken(IntPtr existingToken, int level, out IntPtr duplicateToken);
        [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool AccessCheck(byte[] securityDescriptor, IntPtr clientToken, uint desiredAccess, ref GenericMapping mapping, IntPtr privilegeSet, ref uint privilegeSetLength, out uint grantedAccess, out bool accessStatus);
        [DllImport("advapi32.dll")] internal static extern void MapGenericMask(ref uint accessMask, ref GenericMapping mapping);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern IntPtr OpenSCManager(string machineName, string databaseName, uint desiredAccess);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern IntPtr OpenService(IntPtr manager, string serviceName, uint desiredAccess);
        [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool CloseServiceHandle(IntPtr handle);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool EnumServicesStatusEx(IntPtr manager, int infoLevel, uint serviceType, uint serviceState, IntPtr services, int bufferSize, out int bytesNeeded, out int returned, ref int resume, string groupName);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool QueryServiceConfig(IntPtr service, IntPtr config, int bufferSize, out int bytesNeeded);
        [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool QueryServiceStatus(IntPtr service, out ServiceStatus status);
        [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, out ServiceStatusProcess status, int bufferSize, out int bytesNeeded);
        [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool QueryServiceObjectSecurity(IntPtr service, uint securityInformation, byte[] descriptor, uint bufferSize, out uint bytesNeeded);
    }
}
