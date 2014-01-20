using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		public DllInjector(string ProcessName, bool FreeOnDispose = false)
		{
			if (string.IsNullOrEmpty(ProcessName))
				throw new ArgumentNullException("ProcessName");

			this.FreeOnDispose = FreeOnDispose;
			this.Process = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(ProcessName)).FirstOrDefault();
			
			if (this.Process == null)
				throw new ArgumentException("Process does not exist", "ProcessName");

			if (IntPtr.Size < this.PointerSize)
				throw new ArgumentException("Process' architecture is incompatible with DllInjector's");
		}

		public DllInjector(int ProcessId, bool FreeOnDispose = false)
		{
			this.FreeOnDispose = FreeOnDispose;
			this.Process = Process.GetProcessById(ProcessId);

			if (this.Process == null)
				throw new ArgumentException("Process does not exist", "ProcessId");

			if (IntPtr.Size < this.PointerSize)
				throw new ArgumentException("Process' architecture is incompatible with DllInjector's");
		}

		public DllInjector(Process Process, bool FreeOnDispose = false)
		{
			if (Process == null)
				throw new ArgumentNullException("Processs");

			this.FreeOnDispose = FreeOnDispose;
			this.Process = Process;

			if (IntPtr.Size < this.PointerSize)
				throw new ArgumentException("Process' architecture is incompatible with DllInjector's");
		}
	}
}