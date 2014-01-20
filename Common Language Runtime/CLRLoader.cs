using System;
using System.ComponentModel;
using System.Reflection;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		private CLR Clr;

		public void LoadCommonLanguageRuntime()
		{
			this.LoadCommonLanguageRuntime(Assembly.GetCallingAssembly().ImageRuntimeVersion);
		}

		public void LoadCommonLanguageRuntime(string RuntimeVersion)
		{
			if (string.IsNullOrEmpty(RuntimeVersion))
				throw new ArgumentNullException("RuntimeVersion");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			if (this.Clr != null)
				return;

			this.Clr = new CLR();

			this.Clr.pMSCorEE = this.LoadLibrary("MSCorEE.dll");
			this.Clr.pCorBindToRuntimeEx = this.GetProcAddress(this.Clr.pMSCorEE, "CorBindToRuntimeEx");
			this.Clr.CorBindToRuntimeEx = this.GetFunction<CLR.CorBindToRuntimeExPrototype>(this.Clr.pCorBindToRuntimeEx);

			uint status = this.Clr.CorBindToRuntimeEx(RuntimeVersion, "wks", 0, CLR.CLSID_CLRRuntimeHost, CLR.IID_ICLRRuntimeHost, out this.Clr.ppClrHost);

			if (status != Win32.ERROR_SUCCESS)
				throw new Win32Exception((int)status);

			this.Clr.pClrHost = this.ReadIntPtr(this.Clr.ppClrHost);

			if (this.Clr.pClrHost == IntPtr.Zero)
				throw new Exception();

			if (this.Is64BitProcess)
			{
				CLR.ICLRRuntimeHostVtblx64 ClrHost = this.ReadStruct<CLR.ICLRRuntimeHostVtblx64>(this.Clr.pClrHost);

				this.Clr.pRelease = new IntPtr(ClrHost.Release);
				this.Clr.pStart = new IntPtr(ClrHost.Start);
				this.Clr.pStop = new IntPtr(ClrHost.Stop);
				this.Clr.pExecuteInDefaultAppDomain = new IntPtr(ClrHost.ExecuteInDefaultAppDomain);
			}
			else
			{
				CLR.ICLRRuntimeHostVtblx86 ClrHost = this.ReadStruct<CLR.ICLRRuntimeHostVtblx86>(this.Clr.pClrHost);

				this.Clr.pRelease = new IntPtr(ClrHost.Release);
				this.Clr.pStart = new IntPtr(ClrHost.Start);
				this.Clr.pStop = new IntPtr(ClrHost.Stop);
				this.Clr.pExecuteInDefaultAppDomain = new IntPtr(ClrHost.ExecuteInDefaultAppDomain);
			}

			//this.Clr.Release = this.GetFunction<CLR.ICLRRuntimeHostReleasePrototype>(this.Clr.pRelease);
			this.Clr.Release = (This) => this.CallFunctionThreadProc(this.Clr.pRelease, This);
			//this.Clr.Start = this.GetFunction<CLR.ICLRRuntimeHostStartPrototype>(this.Clr.pStart);
			this.Clr.Start = (This) => this.CallFunctionThreadProc(this.Clr.pStart, This);
			//this.Clr.Stop = this.GetFunction<CLR.ICLRRuntimeHostStopPrototype>(this.Clr.pStop);
			this.Clr.Stop = (This) => this.CallFunctionThreadProc(this.Clr.pStop, This);
			this.Clr.ExecuteInDefaultAppDomain = this.GetFunction<CLR.ICLRRuntimeHostExecuteInDefaultAppDomainPrototype>(this.Clr.pExecuteInDefaultAppDomain);

			status = this.Clr.Start(this.Clr.ppClrHost);

			if (status != Win32.ERROR_SUCCESS)
				throw new Win32Exception((int)status);
		}

		public void FreeCommonLanguageRuntime()
		{
			this.ThrowIfDisposed();

			if (this.Clr == null)
				return;

			if (this.Clr.ppClrHost != IntPtr.Zero
				&& this.Clr.Stop != null
				&& this.Clr.Release != null)
			{
				try
				{
					uint status = this.Clr.Stop(this.Clr.ppClrHost);

					if (status != Win32.ERROR_SUCCESS)
						throw new Win32Exception((int)status);
				}
				finally
				{
					this.Clr.Release(this.Clr.ppClrHost);
				}
			}

			if (this.Clr.pMSCorEE != null)
				this.Clr.pMSCorEE.Dispose();

			this.Clr = null;
		}
	}
}