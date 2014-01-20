using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		private List<ModuleHandle> LoadedLibraries = new List<ModuleHandle>();

		public ModuleHandle GetModuleHandle(string ModuleName)
		{
			if (string.IsNullOrEmpty(ModuleName))
				throw new ArgumentNullException("ModuleName");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			IntPtr hModule = this.Kernel32.GetModuleHandleW(ModuleName);

			if (hModule == IntPtr.Zero)
				throw new Exception("GetModuleHandle failed", new Win32Exception(this.GetLastError()));

			return new ModuleHandle(this, hModule);
		}

		public ModuleHandle LoadLibrary(string FileNamex86, string FileNamex64)
		{
			return this.LoadLibrary(this.Is64BitProcess ? FileNamex64 : FileNamex86);
		}

		public ModuleHandle LoadLibrary(string FileName)
		{
			if (string.IsNullOrEmpty(FileName))
				throw new ArgumentNullException("FileName");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			IntPtr hModule = this.Kernel32.LoadLibraryW(FileName);

			if (hModule == IntPtr.Zero)
				throw new Exception("LoadLibrary failed", new Win32Exception(this.GetLastError()));

			ModuleHandle Module = new ModuleHandle(this, hModule);
			this.LoadedLibraries.Add(Module);
			return Module;
		}

		public void FreeLibrary(ModuleHandle hModule)
		{
			if (hModule == null)
				throw new ArgumentNullException("hModule");

			hModule.Dispose();
		}

		public void FreeLibrary(IntPtr hModule)
		{
			if (hModule == IntPtr.Zero)
				throw new ArgumentNullException("hModule");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			if (this.Kernel32.FreeLibrary(hModule) == 0)
				throw new Exception("FreeLibrary failed", new Win32Exception(this.GetLastError()));
		}

		public void FreeLoadedLibraries()
		{
			this.ThrowIfDisposed();

			foreach (ModuleHandle Dll in this.LoadedLibraries.ToArray())
				Dll.Dispose();
		}

		#region GetProcAddress
		public IntPtr GetProcAddress(string ModuleName, string ProcName, bool LoadLibrary = false)
		{
			if (string.IsNullOrEmpty(ModuleName))
				throw new ArgumentNullException("ModuleName");

			if (string.IsNullOrEmpty(ProcName))
				throw new ArgumentNullException("ProcName");

			IntPtr hModule;

			if (LoadLibrary)
				hModule = this.LoadLibrary(ModuleName);
			else
				hModule = this.GetModuleHandle(ModuleName);

			return this.GetProcAddress(hModule, ProcName);
		}

		public IntPtr GetProcAddress(IntPtr hModule, string ProcName)
		{
			if (hModule == IntPtr.Zero)
				throw new ArgumentNullException("hModule");

			if (string.IsNullOrEmpty(ProcName))
				throw new ArgumentNullException("ProcName");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			IntPtr ptr = this.Kernel32.GetProcAddress(hModule, ProcName);

			if (ptr == IntPtr.Zero)
				throw new Win32Exception(this.GetLastError());

			return ptr;
		}

		public IntPtr GetProcAddress(string ModuleName, short Ordinal, bool LoadLibrary = false)
		{
			if (string.IsNullOrEmpty(ModuleName))
				throw new ArgumentNullException("ModuleName");

			IntPtr hModule;

			if (LoadLibrary)
				hModule = this.LoadLibrary(ModuleName);
			else
				hModule = this.GetModuleHandle(ModuleName);

			return this.GetProcAddress(hModule, Ordinal);
		}

		public IntPtr GetProcAddress(IntPtr hModule, short Ordinal)
		{
			if (hModule == IntPtr.Zero)
				throw new ArgumentNullException("hModule");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			IntPtr ptr = this.Kernel32.GetProcAddressOrdinal(hModule, Ordinal);

			if (ptr == IntPtr.Zero)
				throw new Win32Exception(this.GetLastError());

			return ptr;
		}
		#endregion
	}

	public class ModuleHandle : SafeHandle
	{
		internal protected ModuleHandle(DllInjector Injector, IntPtr hModule)
		{
			this.Injector = Injector;
			this.hModule = hModule;
		}

		private DllInjector Injector;
		internal protected bool Disposed;

		private IntPtr hModule;

		public override IntPtr Value
		{
			get
			{
				if (this.Disposed)
					throw new ObjectDisposedException(this.GetType().Name);

				return this.hModule;
			}
		}

		public override void Dispose()
		{
			if (this.Disposed)
				return;

			if (this.hModule != IntPtr.Zero)
				this.Injector.FreeLibrary(this.hModule);

			this.hModule = IntPtr.Zero;
			this.Disposed = true;
		}
	}
}