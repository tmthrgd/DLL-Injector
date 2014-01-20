using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		public void ResumeProcess()
		{
			this.ThrowIfDisposed();
			this.ThrowIfNoProcess();

			this.Process.Refresh();

			foreach (ProcessThread Thread in this.Process.Threads)
				this.ResumeThread(Thread);
		}

		public void SuspendProcess()
		{
			this.ThrowIfDisposed();
			this.ThrowIfNoProcess();

			this.Process.Refresh();

			foreach (ProcessThread Thread in this.Process.Threads)
				this.SuspendThread(Thread);
		}

		public void ResumeThread(ProcessThread Thread)
		{
			this.ThrowIfDisposed();

			IntPtr hThread = Win32.OpenThread(Win32.ThreadAccess.THREAD_SUSPEND_RESUME, false, (uint)Thread.Id);

			if (hThread == IntPtr.Zero)
				throw new Win32Exception();

			try
			{
				if ((int)Win32.ResumeThread(hThread) == -1)
					throw new Win32Exception();
			}
			finally
			{
				if (!Win32.CloseHandle(hThread))
					throw new Win32Exception();
			}
		}

		public void SuspendThread(ProcessThread Thread)
		{
			this.ThrowIfDisposed();

			IntPtr hThread = Win32.OpenThread(Win32.ThreadAccess.THREAD_SUSPEND_RESUME, false, (uint)Thread.Id);

			if (hThread == IntPtr.Zero)
				throw new Win32Exception();

			try
			{
				if ((this.IsWow64Process && (int)Win32.Wow64SuspendThread(hThread) == -1)
					|| (!this.IsWow64Process && (int)Win32.SuspendThread(hThread) == -1))
					throw new Win32Exception();
			}
			finally
			{
				if (!Win32.CloseHandle(hThread))
					throw new Win32Exception();
			}
		}

		public void KillProcess()
		{
			this.ThrowIfDisposed();

			this.Dispose();

			if (this._Process != null && !this._Process.HasExited)
				this._Process.Kill();
		}
	}
}