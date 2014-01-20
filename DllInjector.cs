using System;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		/*
		 * DllInjector(string/int/Process Process[, bool FreeOnDispose]);
		 * 
		 * bool FreeOnDispose { get; }
		 * Process TargetProcess { get; }
		 * bool Is64BitProcess { get; }
		 * int PointerSize { get; }
		 * 
		 * void AcquireProcessHandle();
		 * void ReleaseProcessHandle();
		 * 
		 * IntPtr LoadLibrary(string FileName);
		 * void FreeLibrary(IntPtr hModule);
		 * void FreeLoadedLibraries();
		 * 
		 * IntPtr GetModuleHandle(string ModuleName);
		 * 
		 * IntPtr GetProcAddress(string/IntPtr Module, string ProcName);
		 * IntPtr GetProcAddress(string/IntPtr Module, short Ordinal);
		 * 
		 * FunctionReturn CallFunction(IntPtr Function[, params object[] Paramaters]);
		 * FunctionReturn CallFunction(IntPtr Function, CallingConvention callingConvention[, params object[] Paramaters]);
		 * uint CallFunctionThreadProc<T>(IntPtr Function, ref T Paramater) where T : struct;
		 * uint CallFunctionThreadProc(IntPtr Function[, IntPtr Paramater]);
		 * 
		 * ReadMemory
		 * 
		 * WriteMemory
		 * 
		 * FreeMemory
		 * 
		 * void Dispose();
		 */

		public void Dispose()
		{
			if (this.Disposed)
				return;

			if (this.FreeOnDispose)
			{
				this.FreeCommonLanguageRuntime();
				this.FreeLoadedLibraries();
			}
			
			this.FreeNativeCallFunction();
			this.ReleaseProcessHandle();
			this.Disposed = true;
		}
	}
}