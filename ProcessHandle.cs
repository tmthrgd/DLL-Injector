using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		private IntPtr hProc = IntPtr.Zero;

		public void AcquireProcessHandle()
		{
			if (this.hProc != IntPtr.Zero)
				return;

			this.ThrowIfDisposed();
			this.ThrowIfNoProcess();

			try
			{
				Process.EnterDebugMode();
			}
			catch (Exception e)
			{
				Utilities.Log("DllInjector may fail if injecting into system process'.", e);
			}

			this.hProc = Win32.OpenProcess(Win32.ProcessAccess.PROCESS_CREATE_THREAD | Win32.ProcessAccess.PROCESS_VM_OPERATION | Win32.ProcessAccess.PROCESS_VM_WRITE | Win32.ProcessAccess.PROCESS_VM_READ | Win32.ProcessAccess.PROCESS_QUERY_INFORMATION, false, (uint)this.Process.Id);

			if (this.hProc == IntPtr.Zero)
				throw new Win32Exception();
		}

		public void ReleaseProcessHandle()
		{
			this.ThrowIfDisposed();

			if (this.hProc != IntPtr.Zero && !Win32.CloseHandle(this.hProc))
				throw new Win32Exception();

			this.hProc = IntPtr.Zero;
		}
	}
}