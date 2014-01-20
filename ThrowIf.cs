using System;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		private void ThrowIfDisposed()
		{
			if (this.Disposed)
				throw new ObjectDisposedException(this.GetType().Name);
		}

		private void ThrowIfNoProcess()
		{
			if (this._Process == null || this._Process.HasExited)
				throw new NullReferenceException("Process does not exist or has exited.");
		}

		private void ThrowIfNoHandle()
		{
			if (!this.HasProcessHandle)
				throw new Exception("AcquireProcessHandle must be called prior to calling this function.");
		}

		private void ThrowIfNoCLR()
		{
			if (!this.HasCommonLanguageRuntime)
				throw new Exception("LoadCommonLanguageRuntime must be called prior to calling this function.");
		}

		private void ThrowIfx86()
		{
			if (!this.Is64BitProcess)
				throw new Exception("Requires x64");
		}

		private void ThrowIfx64()
		{
			if (this.Is64BitProcess)
				throw new Exception("Requires x86");
		}
	}
}