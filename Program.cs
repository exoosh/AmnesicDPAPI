using Interop;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace Util
{
    internal class OllisConsoleTraceListener : ConsoleTraceListener
    {
        private ThreadLocal<string?> _LineIdPrefix = new ThreadLocal<string?>();

        private string? LineIdPrefix
        {
            get
            {
                if (_LineIdPrefix.Value is null)
                {
                    if (base.TraceOutputOptions.HasFlag(TraceOptions.ThreadId) || base.TraceOutputOptions.HasFlag(TraceOptions.ProcessId))
                        _LineIdPrefix.Value = $"[{Environment.ProcessId}:{Thread.CurrentThread.ManagedThreadId}]";
                    else
                        _LineIdPrefix.Value = "";
                }
                return _LineIdPrefix.Value;
            }
        }

        public OllisConsoleTraceListener()
            : base(true)
        {
            // The trace options have no bearing on the Write/WriteLine methods of the default ConsoleTraceListener
            base.TraceOutputOptions = TraceOptions.ThreadId | TraceOptions.ProcessId | TraceOptions.DateTime;
        }

        public override void Write(string? x)
        {
            var LinePrefix = LineIdPrefix;
            if (LinePrefix is null || LinePrefix.Length == 0)
            {
                if (base.TraceOutputOptions.HasFlag(TraceOptions.DateTime))
                    base.Write($"{DateTime.UtcNow:o}: {x}");
                else
                    base.Write(x);
            }
            else
            {
                if (base.TraceOutputOptions.HasFlag(TraceOptions.DateTime))
                    base.Write($"{LinePrefix} {DateTime.UtcNow:o}: {x}");
                else
                    base.Write($"{LinePrefix}: {x}");
            }
        }

        public override void WriteLine(string? x)
        {
            var LinePrefix = LineIdPrefix;
            if (LinePrefix is null || LinePrefix.Length == 0)
            {
                if (base.TraceOutputOptions.HasFlag(TraceOptions.DateTime))
                    base.WriteLine($"{DateTime.UtcNow:o}: {x}");
                else
                    base.WriteLine(x);
            }
            else
            {
                if (base.TraceOutputOptions.HasFlag(TraceOptions.DateTime))
                    base.WriteLine($"{LinePrefix} {DateTime.UtcNow:o}: {x}");
                else
                    base.WriteLine($"{LinePrefix}: {x}");
            }
        }
    }
}

namespace Interop
{
    [SupportedOSPlatform("windows")]
    [SuppressUnmanagedCodeSecurity]
    internal static class Crypt32
    {
        private const string CRYPT32_LIB = "crypt32.dll";

        [Flags]
        internal enum CryptProtectDataFlags : int
        {
            CRYPTPROTECT_UI_FORBIDDEN = 0x1,
            CRYPTPROTECT_LOCAL_MACHINE = 0x4,
            CRYPTPROTECT_CRED_SYNC = 0x8,
            CRYPTPROTECT_AUDIT = 0x10,
            CRYPTPROTECT_NO_RECOVERY = 0x20,
            CRYPTPROTECT_VERIFY_PROTECTION = 0x40,
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct DATA_BLOB
        {
            internal uint cbData;
            internal IntPtr pbData;

            internal DATA_BLOB(IntPtr handle, uint size)
            {
                cbData = size;
                pbData = handle;
            }

            internal byte[] ToByteArray()
            {
                if (cbData == 0)
                {
                    return Array.Empty<byte>();
                }

                byte[] array = new byte[cbData];
                Marshal.Copy(pbData, array, 0, (int)cbData);
                return array;
            }
        }

        [DllImport(CRYPT32_LIB, SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptProtectData(
            in DATA_BLOB pDataIn,
            string? szDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            IntPtr pPromptStruct,
            CryptProtectDataFlags dwFlags,
            out DATA_BLOB pDataOut);

        [DllImport(CRYPT32_LIB, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptUnprotectData(
            in DATA_BLOB pDataIn,
            IntPtr ppszDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            IntPtr pPromptStruct,
            CryptProtectDataFlags dwFlags,
            out DATA_BLOB pDataOut);
    }

    [SupportedOSPlatform("windows")]
    [SuppressUnmanagedCodeSecurity]
    internal static unsafe class NCrypt // mostly taken from aspnetcore, but slightly adjusted (terms: "The .NET Foundation licenses this file to you under the MIT license.")
    {
        private const string NCRYPT_LIB = "ncrypt.dll";

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void ThrowExceptionForNCryptStatus(int ntstatus)
        {
            // This wrapper method exists because 'throw' statements won't always be inlined.
            if (ntstatus != 0)
            {
                ThrowExceptionForNCryptStatusImpl(ntstatus);
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void ThrowExceptionForNCryptStatusImpl(int ntstatus)
        {
            throw new CryptographicException(ntstatus);
        }

        // This isn't a typical Debug.Fail; an error always occurs, even in retail builds.
        // This method doesn't return, but since the CLR doesn't allow specifying a 'never'
        // return type, we mimic it by specifying our return type as Exception. That way
        // callers can write 'throw Fail(...);' to make the C# compiler happy, as the
        // throw keyword is implicitly of type O.
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static Exception Fail(string message)
        {
            Debug.Fail(message);
            throw new CryptographicException("Assertion failed: " + message);
        }

        // This isn't a typical Debug.Assert; the check is always performed, even in retail builds.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Assert([DoesNotReturnIf(false)] bool condition, string message)
        {
            if (!condition)
            {
                Fail(message);
            }
        }

        // This isn't a typical Debug.Assert; the check is always performed, even in retail builds.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void AssertSafeHandleIsValid(SafeHandle safeHandle)
        {
            Assert(safeHandle != null && !safeHandle.IsInvalid, "Safe handle is invalid.");
        }

        internal class LocalAllocHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            // Called by P/Invoke when returning SafeHandles
            public LocalAllocHandle()
                : base(ownsHandle: true) { }

            // Do not provide a finalizer - SafeHandle's critical finalizer will call ReleaseHandle for you.
            protected override bool ReleaseHandle()
            {
                Marshal.FreeHGlobal(handle); // actually calls LocalFree
                return true;
            }
        }

        internal sealed unsafe class NCryptDescriptorHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public NCryptDescriptorHandle()
                : base(ownsHandle: true)
            {
            }

            /*
                        public string GetProtectionDescriptorRuleString()
                        {
                            // from ncryptprotect.h
                            const int NCRYPT_PROTECTION_INFO_TYPE_DESCRIPTOR_STRING = 0x00000001;

                            LocalAllocHandle ruleStringHandle;
                            int ntstatus = NCryptGetProtectionDescriptorInfo(
                                hDescriptor: this,
                                pMemPara: IntPtr.Zero,
                                dwInfoType: NCRYPT_PROTECTION_INFO_TYPE_DESCRIPTOR_STRING,
                                ppvInfo: out ruleStringHandle);
                            ThrowExceptionForNCryptStatus(ntstatus);
                            AssertSafeHandleIsValid(ruleStringHandle);

                            using (ruleStringHandle)
                            {
                                return new string((char*)ruleStringHandle.DangerousGetHandle());
                            }
                        }
            */

            // Do not provide a finalizer - SafeHandle's critical finalizer will call ReleaseHandle for you.
            protected override bool ReleaseHandle()
            {
                return (NCryptCloseProtectionDescriptor(handle) == 0);
            }
        }

        /// <summary>
        /// Creates a rule string tied to the current Windows user and which is transferable
        /// across machines (backed up in AD).
        /// </summary>
        internal static string GetDefaultProtectionDescriptorString()
        {
            // Creates a SID=... protection descriptor string for the current user.
            // Reminder: DPAPI:NG provides only encryption, not authentication.
            using (var currentIdentity = WindowsIdentity.GetCurrent())
            {
                // use the SID to create an SDDL string
                return string.Format(CultureInfo.InvariantCulture, "SID={0}", currentIdentity?.User?.Value);
            }
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptcloseprotectiondescriptor
        [DllImport(NCRYPT_LIB)]
        internal static extern int NCryptCloseProtectionDescriptor(
                IntPtr hDescriptor);

        // https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptcreateprotectiondescriptor
        [DllImport(NCRYPT_LIB)]
        internal static extern int NCryptCreateProtectionDescriptor(
                [MarshalAs(UnmanagedType.LPWStr)] string pwszDescriptorString,
                uint dwFlags,
                out NCryptDescriptorHandle phDescriptor);

        // https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptgetprotectiondescriptorinfo
        [DllImport(NCRYPT_LIB)]
        internal static extern int NCryptGetProtectionDescriptorInfo(
                NCryptDescriptorHandle hDescriptor,
                IntPtr pMemPara,
                uint dwInfoType,
                out LocalAllocHandle ppvInfo);

        // https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptprotectsecret
        [DllImport(NCRYPT_LIB)]
        internal static extern int NCryptProtectSecret(
                NCryptDescriptorHandle hDescriptor,
                uint dwFlags,
                byte* pbData,
                uint cbData,
                IntPtr pMemPara,
                IntPtr hWnd,
                out LocalAllocHandle ppbProtectedBlob,
                out uint pcbProtectedBlob);

        // https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptunprotectsecret
        [DllImport(NCRYPT_LIB)]
        internal static extern int NCryptUnprotectSecret(
                IntPtr phDescriptor,
                uint dwFlags,
                byte* pbProtectedBlob,
                uint cbProtectedBlob,
                IntPtr pMemPara,
                IntPtr hWnd,
                out LocalAllocHandle ppbData,
                out uint pcbData);

        internal static unsafe class UnsafeBufferUtil
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static void BlockCopy(void* from, void* to, int byteCount)
            {
                BlockCopy(from, to, checked((uint)byteCount)); // will be checked before invoking the delegate
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static void BlockCopy(void* from, void* to, uint byteCount)
            {
                if (byteCount != 0)
                {
                    BlockCopyCore((byte*)from, (byte*)to, byteCount);
                }
            }

            public static void BlockCopy(LocalAllocHandle from, void* to, uint byteCount)
            {
                bool refAdded = false;
                try
                {
                    from.DangerousAddRef(ref refAdded);
                    BlockCopy((void*)from.DangerousGetHandle(), to, byteCount);
                }
                finally
                {
                    if (refAdded)
                    {
                        from.DangerousRelease();
                    }
                }
            }

            public static void BlockCopy(void* from, LocalAllocHandle to, uint byteCount)
            {
                bool refAdded = false;
                try
                {
                    to.DangerousAddRef(ref refAdded);
                    BlockCopy(from, (void*)to.DangerousGetHandle(), byteCount);
                }
                finally
                {
                    if (refAdded)
                    {
                        to.DangerousRelease();
                    }
                }
            }

            public static void BlockCopy(LocalAllocHandle from, LocalAllocHandle to, IntPtr length)
            {
                if (length == IntPtr.Zero)
                {
                    return;
                }

                bool fromRefAdded = false;
                bool toRefAdded = false;
                try
                {
                    from.DangerousAddRef(ref fromRefAdded);
                    to.DangerousAddRef(ref toRefAdded);
                    if (sizeof(IntPtr) == 4)
                    {
                        BlockCopyCore(from: (byte*)from.DangerousGetHandle(), to: (byte*)to.DangerousGetHandle(), byteCount: (uint)length.ToInt32());
                    }
                    else
                    {
                        BlockCopyCore(from: (byte*)from.DangerousGetHandle(), to: (byte*)to.DangerousGetHandle(), byteCount: (ulong)length.ToInt64());
                    }
                }
                finally
                {
                    if (fromRefAdded)
                    {
                        from.DangerousRelease();
                    }
                    if (toRefAdded)
                    {
                        to.DangerousRelease();
                    }
                }
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static void BlockCopyCore(byte* from, byte* to, uint byteCount)
            {
                Buffer.MemoryCopy(from, to, (ulong)byteCount, (ulong)byteCount);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static void BlockCopyCore(byte* from, byte* to, ulong byteCount)
            {
                Buffer.MemoryCopy(from, to, byteCount, byteCount);
            }

            /// <summary>
            /// Securely clears a memory buffer.
            /// </summary>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static void SecureZeroMemory(byte* buffer, int byteCount)
            {
                SecureZeroMemory(buffer, checked((uint)byteCount));
            }

            /// <summary>
            /// Securely clears a memory buffer.
            /// </summary>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static void SecureZeroMemory(byte* buffer, uint byteCount)
            {
                if (byteCount != 0)
                {
                    do
                    {
                        buffer[--byteCount] = 0;
                    } while (byteCount != 0);

                    // Volatile to make sure the zero-writes don't get optimized away
                    Volatile.Write(ref *buffer, 0);
                }
            }

            /// <summary>
            /// Securely clears a memory buffer.
            /// </summary>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static void SecureZeroMemory(byte* buffer, ulong byteCount)
            {
                if (byteCount != 0)
                {
                    do
                    {
                        buffer[--byteCount] = 0;
                    } while (byteCount != 0);

                    // Volatile to make sure the zero-writes don't get optimized away
                    Volatile.Write(ref *buffer, 0);
                }
            }

            /// <summary>
            /// Securely clears a memory buffer.
            /// </summary>
            public static void SecureZeroMemory(byte* buffer, IntPtr length)
            {
                if (sizeof(IntPtr) == 4)
                {
                    SecureZeroMemory(buffer, (uint)length.ToInt32());
                }
                else
                {
                    SecureZeroMemory(buffer, (ulong)length.ToInt64());
                }
            }
        }

        /// <summary>
        /// Represents a handle returned by LocalAlloc.
        /// The memory will be zeroed out before it's freed.
        /// </summary>
        internal sealed unsafe class SecureLocalAllocHandle : LocalAllocHandle
        {
            private readonly IntPtr _cb;

            private SecureLocalAllocHandle(IntPtr cb)
            {
                _cb = cb;
            }

            public IntPtr Length
            {
                get
                {
                    return _cb;
                }
            }

            /// <summary>
            /// Allocates some amount of memory using LocalAlloc.
            /// </summary>
            public static SecureLocalAllocHandle Allocate(IntPtr cb)
            {
                SecureLocalAllocHandle newHandle = new SecureLocalAllocHandle(cb);
                newHandle.AllocateImpl(cb);
                return newHandle;
            }

            private void AllocateImpl(IntPtr cb)
            {
                handle = Marshal.AllocHGlobal(cb); // actually calls LocalAlloc
            }

            public SecureLocalAllocHandle Duplicate()
            {
                SecureLocalAllocHandle duplicateHandle = Allocate(_cb);
                UnsafeBufferUtil.BlockCopy(from: this, to: duplicateHandle, length: _cb);
                return duplicateHandle;
            }

            // Do not provide a finalizer - SafeHandle's critical finalizer will call ReleaseHandle for you.
            protected override bool ReleaseHandle()
            {
                UnsafeBufferUtil.SecureZeroMemory((byte*)handle, _cb); // compiler won't optimize this away
                return base.ReleaseHandle();
            }
        }

        // from ncrypt.h
        private const uint NCRYPT_SILENT_FLAG = 0x00000040;

        private static unsafe byte[] ProtectWithDpapiNGCore(byte* pbData, uint cbData)
        {
            NCryptDescriptorHandle protectionDescriptorHandle; // no longer a parameter like in ASP.NET
            var ntstatus = NCryptCreateProtectionDescriptor(GetDefaultProtectionDescriptorString(), (uint)0, out protectionDescriptorHandle);
            ThrowExceptionForNCryptStatus(ntstatus);

            Debug.Assert(protectionDescriptorHandle != null);
            Debug.Assert(pbData != null);

            // Perform the encryption operation, putting the protected data into LocalAlloc-allocated memory.
            LocalAllocHandle protectedData;
            uint cbProtectedData;
            ntstatus = NCryptProtectSecret(
                hDescriptor: protectionDescriptorHandle,
                dwFlags: NCRYPT_SILENT_FLAG,
                pbData: pbData,
                cbData: cbData,
                pMemPara: IntPtr.Zero,
                hWnd: IntPtr.Zero,
                ppbProtectedBlob: out protectedData,
                pcbProtectedBlob: out cbProtectedData);
            ThrowExceptionForNCryptStatus(ntstatus);
            AssertSafeHandleIsValid(protectedData);

            // Copy the data from LocalAlloc-allocated memory into a managed memory buffer.
            using (protectedData)
            {
                var retVal = new byte[cbProtectedData];
                if (cbProtectedData > 0)
                {
                    fixed (byte* pbRetVal = retVal)
                    {
                        var handleAcquired = false;

                        try
                        {
                            protectedData.DangerousAddRef(ref handleAcquired);
                            UnsafeBufferUtil.BlockCopy(from: (void*)protectedData.DangerousGetHandle(), to: pbRetVal, byteCount: cbProtectedData);
                        }
                        finally
                        {
                            if (handleAcquired)
                            {
                                protectedData.DangerousRelease();
                            }
                        }
                    }
                }
                return retVal;
            }
        }

        // Changed to return a byte[] ... this may not be ideal from a security point of view. In that case better use Secret/ISecret from ASP.NET Core
        private static unsafe byte[] UnprotectWithDpapiNGCore(byte* pbData, uint cbData)
        {
            Debug.Assert(pbData != null);

            // First, decrypt the payload into LocalAlloc-allocated memory.
            LocalAllocHandle unencryptedPayloadHandle;
            uint cbUnencryptedPayload;
            var ntstatus = NCryptUnprotectSecret(
                phDescriptor: IntPtr.Zero,
                dwFlags: NCRYPT_SILENT_FLAG,
                pbProtectedBlob: pbData,
                cbProtectedBlob: cbData,
                pMemPara: IntPtr.Zero,
                hWnd: IntPtr.Zero,
                ppbData: out unencryptedPayloadHandle,
                pcbData: out cbUnencryptedPayload);
            ThrowExceptionForNCryptStatus(ntstatus);
            AssertSafeHandleIsValid(unencryptedPayloadHandle);

            using (unencryptedPayloadHandle)
            {
                var handleAcquired = false;

                try
                {
                    unencryptedPayloadHandle.DangerousAddRef(ref handleAcquired);
                    return new Span<byte>((byte*)unencryptedPayloadHandle.DangerousGetHandle(), checked((int)cbUnencryptedPayload)).ToArray();
                }
                finally
                {
                    if (handleAcquired)
                    {
                        UnsafeBufferUtil.SecureZeroMemory((byte*)unencryptedPayloadHandle.DangerousGetHandle(), cbUnencryptedPayload);
                        unencryptedPayloadHandle.DangerousRelease();
                    }
                }
            }
        }

        public static byte[] ProtectWithDpapiNG(byte[] bData)
        {
            fixed (byte* pbData = bData)
            {
                return ProtectWithDpapiNGCore(pbData, (uint)bData.Length);
            }
        }

        public static byte[] UnprotectWithDpapiNG(byte[] bData)
        {
            fixed(byte* pbData = bData)
            {
                return UnprotectWithDpapiNGCore(pbData, (uint)bData.Length);
            }
        }
    }
}

// https://learn.microsoft.com/en-us/windows/win32/seccng/protection-descriptors
// https://learn.microsoft.com/en-us/windows/win32/seccng/protection-providers

namespace AmnesicDPAPI
{
    // ProtectedData is a shallow wrapper around the classic DPAPI, so no point in jumping through P/Invoke hoops for this case
    [SupportedOSPlatform("windows")]
    static class NET
    {
        private const DataProtectionScope ProtectionScope = DataProtectionScope.CurrentUser;

        public static byte[] Encrypt(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return Array.Empty<byte>();
            }
            byte[] buffer = ProtectedData.Protect(Encoding.UTF8.GetBytes(value), null, ProtectionScope);
            return buffer;
        }

        public static string Decrypt(byte[] value)
        {
            if (value == null || value.Length == 0)
            {
                return string.Empty;
            }
            byte[] buffer = ProtectedData.Unprotect(value, null, ProtectionScope);
            return Encoding.UTF8.GetString(buffer);
        }
    }

    [SupportedOSPlatform("windows")]
    static class DPAPING // DPAPI-NG aka CNG DPAPI (based on CNG instead of CryptoAPI)
    {
        public static byte[] Encrypt(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return Array.Empty<byte>();
            }
            byte[] buffer = NCrypt.ProtectWithDpapiNG(Encoding.UTF8.GetBytes(value));
            return buffer;
        }

        public static string Decrypt(byte[] value)
        {
            if (value == null || value.Length == 0)
            {
                return string.Empty;
            }
            byte[] buffer = NCrypt.UnprotectWithDpapiNG(value);
            return Encoding.UTF8.GetString(buffer);
        }
    }

    [SupportedOSPlatform("windows")]
    internal class Program
    {
        static void EnableDisableProviders(TraceEventSession session, bool bEnable = true)
        {
            var always_providers = new (string guid, string name)[] {
                // ("{5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB}", "Microsoft-Windows-CAPI2"),
                // ("{C7E089AC-BA2A-11E0-9AF7-68384824019B}", "Microsoft-Windows-Crypto-BCrypt"),
                ("{E3E0E2F0-C9C5-11E0-8AB9-9EBC4824019B}", "Microsoft-Windows-Crypto-CNG"),
                ("{89FE8F40-CDCE-464E-8217-15EF97D4C7C3}", "Microsoft-Windows-Crypto-DPAPI"),
                // ("{43DAD447-735F-4829-A6FF-9829A87419FF}", "Microsoft-Windows-Crypto-DSSEnh"),
                ("{E8ED09DC-100C-45E2-9FC8-B53399EC1F70}", "Microsoft-Windows-Crypto-NCrypt"),
                // ("{54D5AC20-E14F-4FDA-92DA-EBF7556FF176}", "Microsoft-Windows-Crypto-RNG"),
                // ("{152FDB2B-6E9D-4B60-B317-815D5F174C4A}", "Microsoft-Windows-Crypto-RSAEnh"),
                ("{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}", "Microsoft-Windows-TaskScheduler"),
                ("{5D896912-022D-40AA-A3A8-4FA5515C76D7}", "Microsoft-Windows-TerminalServices-LocalSessionManager"),
                ("{DB00DFB6-29F9-4A9C-9B3B-1F4F9E7D9770}", "Microsoft-Windows-User Profiles General"),
                ("{89B1E9F0-5AFF-44A6-9B44-0A07A7CE5845}", "Microsoft-Windows-User Profiles Service"),
            };

            foreach (var (guid, name) in always_providers)
            {
                var pguid = Guid.Parse(guid);
                if (bEnable)
                {
                    if (!session.EnableProvider(
                                providerGuid: pguid,
                                providerLevel: TraceEventLevel.Always
                                ))
                    {
                        Trace.WriteLine($"Failed to enable provider {name} ({guid}) [EnableProvider() returned false]");
                    }
                }
                else
                {
                    try
                    {
                        Trace.WriteLine($"Disabling {name} ({guid}");
                        session.DisableProvider(pguid);
                    }
                    catch (COMException)
                    {
                    }
                }
            }

            var elevated_providers = new (string guid, string name)[] {
                ("{DBE9B383-7CF3-4331-91CC-A3CB16A3B538}", "Microsoft-Windows-Winlogon"),
                ("{206F6DEA-D3C5-4D10-BC72-989F03C8B84B}", "Microsoft-Windows-Wininit"),
                ("{C2BA06E2-F7CE-44AA-9E7E-62652CDEFE97}", "Windows Wininit Trace"),
                ("{D451642C-63A6-11D7-9720-00B0D03E0347}", "Windows Winlogon Trace"),
            };

            foreach (var (guid, name) in elevated_providers)
            {
                var pguid = Guid.Parse(guid);
                if (bEnable)
                {
                    try
                    {
                        if (!session.EnableProvider(
                                providerGuid: pguid,
                                providerLevel: TraceEventLevel.Always
                                ))
                        {
                            Trace.WriteLine($"Failed to enable provider {name} ({guid}) [EnableProvider() returned false]");
                        }
                    }
                    catch (System.UnauthorizedAccessException)
                    {
                        Trace.WriteLine($"ERROR: access denied when attempting to enable {name} ({guid}");
                    }
                }
                else
                {
                    Trace.WriteLine($"Disabling {name} ({guid}");
                    session.DisableProvider(pguid);
                }
            }
        }
        static void EnableProviders(TraceEventSession session)
        {
            EnableDisableProviders(session, true);
        }

        static void DisableProviders(TraceEventSession session)
        {
            // EnableDisableProviders(session, false);
        }

        private static readonly CancellationTokenSource cts = new CancellationTokenSource();

        static async Task Main(string[] args)
        {
            var stderr = new Util.OllisConsoleTraceListener();
            Trace.Listeners.Add(stderr); // trace also to stderr
            Trace.AutoFlush = true;

            Console.CancelKeyPress += (sender, eventArgs) =>
            {
                Trace.WriteLine("Ctrl+C pressed");
                cts.Cancel();
                eventArgs.Cancel = true;
            };

            // xref: https://github.com/microsoft/perfview/blob/main/documentation/TraceEvent/TraceEventProgrammersGuide.md#real-time-processing-of-events
            using (var session = new TraceEventSession("DPAPI"))
            {
                // Set up Ctrl-C to stop the session
                Console.CancelKeyPress += (sender, eventArgs) =>
                {
                    session.Stop();
                    eventArgs.Cancel = true;
                };

                session.StopOnDispose = true;
                session.EnableProviderTimeoutMSec = 5000;
                using (var source = new ETWTraceEventSource(session.SessionName, TraceEventSourceType.Session))
                {
                    EnableProviders(session);

                    session.Source.Dynamic.AddCallbackForProviderEvents(null, delegate (TraceEvent data)
                    {
                        if (data.ProviderName == "MSNT_SystemTrace")
                        {
                            return;
                        }
                        var formattedMessage = data.FormattedMessage ?? "null";
                        if (formattedMessage.Contains("ChromeMetricsTestKey"))
                        {
                            return;
                        }
                        // data.ActivityID == "69768d97-2c3f-0002-288e-76693f2cdb01"
                        /*
                                                if ("DPAPIDefInformationTaskMessage" == data.EventName)
                                                {
                                                    Trace.WriteLine(data.Dump(includePrettyPrint: true, truncateDump: true));
                                                    return;
                                                }
                        */
                        // (uint)data.ID == 16385
                        // data.TaskName == "DPAPIDefInformationTaskMessage"
                        // data.KernelTime
                        if (data.ActivityID.ToString() == "69768d97-2c3f-0002-288e-76693f2cdb01") // DPAPIDefInformationEvent
                        {
                            Trace.WriteLine($"{(uint)data.ID} / {data.TaskName} / {data.Keywords}");
                            foreach(var payload in data.PayloadNames)
                            {
                                Trace.WriteLine($"{payload}: {data.PayloadByName(payload)}");
                                /*
[20316:12] 2024-11-01T12:31:36.5750905Z: 16385 / DPAPIDefInformationTaskMessage / 2305843009213694016
[20316:12] 2024-11-01T12:31:36.5771271Z: OperationType: SPCryptProtect
[20316:12] 2024-11-01T12:31:36.5785002Z: DataDescription:
[20316:12] 2024-11-01T12:31:36.5794670Z: MasterKeyGUID: 1a4b07ea-92c2-4a30-97ad-518a684df6f2
[20316:12] 2024-11-01T12:31:36.5843962Z: Flags: 1
[20316:12] 2024-11-01T12:31:36.5852405Z: ProtectionFlags: 0
[20316:12] 2024-11-01T12:31:36.5860711Z: ReturnValue: 0
[20316:12] 2024-11-01T12:31:36.5870443Z: CallerProcessStartKey: 302867074940668541
[20316:12] 2024-11-01T12:31:36.5879125Z: CallerProcessID: 20316
[20316:12] 2024-11-01T12:31:36.5887634Z: CallerProcessCreationTime: 133749378939327068
[20316:12] 2024-11-01T12:31:36.5896001Z: PlainTextDataSize: 67
                                 */
                            }
                            return;
                        }
                        formattedMessage = formattedMessage.Replace("\r\n\r\n", "\r\n").Replace("\r\n", "; ").Replace("\n", " ").Trim();
                        formattedMessage = Regex.Replace(formattedMessage, @"\s+", " ");
                        var providerName = Regex.Replace(data.ProviderName, @"^Microsoft-(?:Windows-(?:Crypto-)?)?", "");
                        Trace.WriteLine($"[{providerName}] {data.EventName}: {formattedMessage}");
                    });
                }

                await RealMain(cts.Token, session);
            }
        }

        async static Task RealMain(CancellationToken ct, TraceEventSession session)
        {
            // The same across all DPAPI implementations we'll call
            string dataToEncrypt = $"{DateTime.UtcNow:o} {{CCC6413B-6987-47CA-A4F5-2C0D738FBCFA}}"; // our "credentials" to protect

            Trace.WriteLine($"Encrypting: {dataToEncrypt}");
            byte[] encryptedBytesDotNet = NET.Encrypt(dataToEncrypt);
            byte[] encryptedByestDPAPICNG = DPAPING.Encrypt(dataToEncrypt);

            Thread eventThread = new Thread(delegate ()
            {
                session.Source.Process();
                Trace.WriteLine("Leaving TraceEventSession.Source.Process() thread");
            });
            eventThread.Start();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var decryptedStringDotNet = NET.Decrypt(encryptedBytesDotNet);
                    if (decryptedStringDotNet is not null)
                    {
                        Trace.WriteLine("Failed decryption via System.Security.Cryptography.ProtectedData (classic DPAPI)");
                    }
                }
                catch (CryptographicException ex)
                {
                    Trace.WriteLine(ex);
                }
                try
                {
                    var decryptedStringDPAPICNG = DPAPING.Decrypt(encryptedByestDPAPICNG);
                    if (decryptedStringDPAPICNG is not null)
                    {
                        Trace.WriteLine("Failed decryption via DPAPI NG (CNG DPAPI)");
                    }
                }
                catch (Exception ex)
                {
                    Trace.WriteLine(ex);
                }
                await Task.Delay(200);
            }
            DisableProviders(session);
            session.Stop(true);
            eventThread.Join(2000);
        }
    }
}