using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using PrivTrace.Models;

namespace PrivTrace.Security
{
    public static class AuthenticodeVerifier
    {
        private static readonly Guid GenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        private const uint WtdUiNone = 2, WtdRevokeNone = 0, WtdChoiceFile = 1, WtdStateActionIgnore = 0, WtdCacheOnlyUrlRetrieval = 0x1000;
        private const int TrustENoSignature = unchecked((int)0x800B0100), TrustESubjectFormUnknown = unchecked((int)0x800B0003), TrustEProviderUnknown = unchecked((int)0x800B0001);

        public static void Verify(string path, FileIdentityMetadata target)
        {
            if (target == null) return;
            target.SignatureStatus = SignatureStatus.Unknown; target.SignatureHResult = 0;
            if (Environment.OSVersion.Platform != PlatformID.Win32NT) { target.SignatureError = "WinVerifyTrust is available only on Windows."; return; }
            if (String.IsNullOrWhiteSpace(path) || !File.Exists(path)) { target.SignatureError = "The executable was absent or inaccessible."; return; }
            IntPtr pathPointer = IntPtr.Zero, filePointer = IntPtr.Zero;
            try
            {
                pathPointer = Marshal.StringToCoTaskMemUni(path);
                WintrustFileInfo file = new WintrustFileInfo { StructSize = (uint)Marshal.SizeOf(typeof(WintrustFileInfo)), FilePath = pathPointer };
                filePointer = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WintrustFileInfo))); Marshal.StructureToPtr(file, filePointer, false);
                WintrustData data = new WintrustData
                {
                    StructSize = (uint)Marshal.SizeOf(typeof(WintrustData)), UiChoice = WtdUiNone, RevocationChecks = WtdRevokeNone,
                    UnionChoice = WtdChoiceFile, FileInfoPointer = filePointer, StateAction = WtdStateActionIgnore, ProviderFlags = WtdCacheOnlyUrlRetrieval
                };
                Guid action = GenericVerifyV2; int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data); target.SignatureHResult = result;
                if (result == 0) { target.SignatureStatus = SignatureStatus.Valid; ReadSigner(path, target); }
                else if (result == TrustENoSignature || result == TrustESubjectFormUnknown) { target.SignatureStatus = SignatureStatus.Absent; target.SignatureError = "No verifiable embedded Authenticode signature was present."; }
                else if (result == TrustEProviderUnknown) { target.SignatureStatus = SignatureStatus.Unknown; target.SignatureError = "The trust provider could not evaluate this subject."; }
                else { target.SignatureStatus = SignatureStatus.Invalid; target.SignatureError = "WinVerifyTrust rejected the signature: 0x" + result.ToString("X8") + "."; ReadSigner(path, target); }
            }
            catch (EntryPointNotFoundException ex) { target.SignatureStatus = SignatureStatus.Unknown; target.SignatureError = ex.Message; }
            catch (DllNotFoundException ex) { target.SignatureStatus = SignatureStatus.Unknown; target.SignatureError = ex.Message; }
            catch (Exception ex) { target.SignatureStatus = SignatureStatus.Unknown; target.SignatureError = ex.GetType().Name + ": " + ex.Message; }
            finally { if (filePointer != IntPtr.Zero) Marshal.FreeCoTaskMem(filePointer); if (pathPointer != IntPtr.Zero) Marshal.FreeCoTaskMem(pathPointer); }
        }

        private static void ReadSigner(string path, FileIdentityMetadata target)
        {
            try { X509Certificate2 certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path)); target.SignerSubject = certificate.Subject; certificate.Reset(); }
            catch (Exception ex) { if (target.SignatureStatus == SignatureStatus.Valid) target.SignatureError = "Trust validation succeeded, but embedded signer identity was unavailable: " + ex.GetType().Name + "."; }
        }

        [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true, SetLastError = false)]
        private static extern int WinVerifyTrust(IntPtr window, [In] ref Guid actionId, [In] ref WintrustData data);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WintrustFileInfo
        {
            internal uint StructSize;
            internal IntPtr FilePath;
            internal IntPtr FileHandle;
            internal IntPtr KnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WintrustData
        {
            internal uint StructSize;
            internal IntPtr PolicyCallbackData;
            internal IntPtr SipClientData;
            internal uint UiChoice;
            internal uint RevocationChecks;
            internal uint UnionChoice;
            internal IntPtr FileInfoPointer;
            internal uint StateAction;
            internal IntPtr StateData;
            internal IntPtr UrlReference;
            internal uint ProviderFlags;
            internal uint UiContext;
        }
    }
}
