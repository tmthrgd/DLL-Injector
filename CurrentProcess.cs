using System;
using System.Diagnostics;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		private static DllInjector CurrentProcess;

		public static DllInjector GetCurrentProcess()
		{
			if (CurrentProcess == null || CurrentProcess.Disposed)
				CurrentProcess = new DllInjector(Process.GetCurrentProcess());

			return CurrentProcess;
		}
	}
}