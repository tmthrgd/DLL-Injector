using System;
using System.Runtime.InteropServices;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		private sealed class CLR
		{
			[RemoteImport("MSCorEE.dll", "CorBindToRuntimeEx", CallingConvention = CallingConvention.StdCall)]
			public delegate uint CorBindToRuntimeExPrototype([MarshalAs(UnmanagedType.LPWStr)] string pwszVersion, [MarshalAs(UnmanagedType.LPWStr)] string pwszBuildFlavor, uint startupFlags, [MarshalAs(UnmanagedType.LPStruct)] Guid rclsid, [MarshalAs(UnmanagedType.LPStruct)] Guid riid, out IntPtr ppv);

			[RemoteImport(CallingConvention = CallingConvention.StdCall)]
			public delegate uint ICLRRuntimeHostStartPrototype(IntPtr This);

			[RemoteImport(CallingConvention = CallingConvention.StdCall)]
			public delegate uint ICLRRuntimeHostReleasePrototype(IntPtr This);

			[RemoteImport(CallingConvention = CallingConvention.StdCall)]
			public delegate uint ICLRRuntimeHostStopPrototype(IntPtr This);

			[RemoteImport(CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
			public delegate uint ICLRRuntimeHostExecuteInDefaultAppDomainPrototype(IntPtr This, [MarshalAs(UnmanagedType.LPWStr)] string pwzAssemblyPath, [MarshalAs(UnmanagedType.LPWStr)] string pwzTypeName, [MarshalAs(UnmanagedType.LPWStr)] string pwzMethodName, [MarshalAs(UnmanagedType.LPWStr)] string pwzArgument, out int ReturnValue);

			public static readonly Guid CLSID_CLRRuntimeHost = new Guid(0x90F1A06E, 0x7712, 0x4762, 0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02);
			public static readonly Guid IID_ICLRRuntimeHost = new Guid(0x90F1A06C, 0x7712, 0x4762, 0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02);

			[StructLayout(LayoutKind.Sequential)]
			public struct ICLRRuntimeHostVtblx86
			{
				public int QueryInterface;
				public int AddRef;
				public int Release;
				public int Start;
				public int Stop;
				public int SetHostControl;
				public int GetCLRControl;
				public int UnloadAppDomain;
				public int ExecuteInAppDomain;
				public int GetCurrentAppDomainId;
				public int ExecuteApplication;
				public int ExecuteInDefaultAppDomain;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct ICLRRuntimeHostVtblx64
			{
				public long QueryInterface;
				public long AddRef;
				public long Release;
				public long Start;
				public long Stop;
				public long SetHostControl;
				public long GetCLRControl;
				public long UnloadAppDomain;
				public long ExecuteInAppDomain;
				public long GetCurrentAppDomainId;
				public long ExecuteApplication;
				public long ExecuteInDefaultAppDomain;
			}

			public ModuleHandle pMSCorEE;

			public IntPtr pCorBindToRuntimeEx;
			public CorBindToRuntimeExPrototype CorBindToRuntimeEx;

			public IntPtr ppClrHost;
			public IntPtr pClrHost;

			public IntPtr pExecuteInDefaultAppDomain;
			public ICLRRuntimeHostExecuteInDefaultAppDomainPrototype ExecuteInDefaultAppDomain;
			public IntPtr pRelease;
			public ICLRRuntimeHostReleasePrototype Release;
			public IntPtr pStart;
			public ICLRRuntimeHostStartPrototype Start;
			public IntPtr pStop;
			public ICLRRuntimeHostStopPrototype Stop;
		}
	}
}