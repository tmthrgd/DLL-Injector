using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		private sealed class Kernel32Procedures
		{
			[RemoteImport(CallingConvention = CallingConvention.StdCall)]
			public delegate int GetLastErrorPrototype();

			[RemoteImport(CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
			public delegate IntPtr GetModuleHandleWPrototype([MarshalAs(UnmanagedType.LPTStr)] string ModuleName);

			[RemoteImport(CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
			public delegate IntPtr LoadLibraryWPrototype([MarshalAs(UnmanagedType.LPTStr)] string FileName);
			[RemoteImport(CallingConvention = CallingConvention.StdCall)]
			public delegate uint FreeLibraryPrototype(IntPtr hModule);

			[RemoteImport(CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
			public delegate IntPtr GetProcAddressPrototype(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)] string ProcName);
			[RemoteImport(CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
			public delegate IntPtr GetProcAddressPrototypeOrdinal(IntPtr hModule, [MarshalAs(UnmanagedType.SysInt)] short Ordinal); 
			
			public IntPtr Kernel32 = IntPtr.Zero;

			public IntPtr _GetLastError = IntPtr.Zero;
			public GetLastErrorPrototype GetLastError;

			public IntPtr _GetModuleHandleW = IntPtr.Zero;
			public GetModuleHandleWPrototype GetModuleHandleW;

			public IntPtr _LoadLibraryW = IntPtr.Zero;
			public LoadLibraryWPrototype LoadLibraryW;
			public IntPtr _FreeLibrary = IntPtr.Zero;
			public FreeLibraryPrototype FreeLibrary;

			public IntPtr _GetProcAddress = IntPtr.Zero;
			public GetProcAddressPrototype GetProcAddress;
			public GetProcAddressPrototypeOrdinal GetProcAddressOrdinal;
		}

		private Kernel32Procedures _Kernel32 = null;

		private Kernel32Procedures Kernel32
		{
			get
			{
				this.ThrowIfDisposed();

				if (this._Kernel32 == null)
					this._Kernel32 = this.GetKernel32Procedures();

				return this._Kernel32;
			}
		}

		private Kernel32Procedures GetKernel32Procedures()
		{
			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			Kernel32Procedures Kernel32 = new Kernel32Procedures();

			// Kernel32 is usually (always?) the 3rd module loaded so we enum first 10 to be safe.
			IntPtr[] hModules = new IntPtr[10];
			uint cbNeeded;

			// Modules are not loaded until at least one thread has been executed.
			using (MemoryHandle DummyFunction = this.WriteMachineCode(
				/* x86: ret 4 */ new byte[] { 0xC2, 0x04, 0x00 },
				/* x64: ret 0 */ new byte[] { 0xC3 }))
				this.CallFunctionThreadProc(DummyFunction);

			if (!Win32.EnumProcessModulesEx(this.hProc,
				hModules,
				(uint)Buffer.ByteLength(hModules),
				out cbNeeded,
				this.Is64BitProcess
					? Win32.EnumProcessModulesExFilterFlags.LIST_MODULES_64BIT
					: Win32.EnumProcessModulesExFilterFlags.LIST_MODULES_32BIT))
				throw new Win32Exception();

			StringBuilder BaseName = new StringBuilder(64);

			for (int i = 0; i < hModules.Length; i++)
			{
				if (Win32.GetModuleBaseName(this.hProc, hModules[i], BaseName, (uint)BaseName.Capacity) == 0)
					throw new Win32Exception();

				if (string.Compare(BaseName.ToString(), "kernel32.dll", true) != 0)
					continue;

				Kernel32.Kernel32 = hModules[i];
				break;
			}

			if (Kernel32.Kernel32 == IntPtr.Zero)
				throw new Exception("Cannot find Kernel32.dll in remote process.");

			Win32.IMAGE_DOS_HEADER DosHeader = this.ReadStruct<Win32.IMAGE_DOS_HEADER>(Kernel32.Kernel32);
			Win32.IMAGE_DATA_DIRECTORY DataDirectory;

			if (this.Is64BitProcess)
			{
				Win32.IMAGE_NT_HEADERS64 NtHeaders = this.ReadStruct<Win32.IMAGE_NT_HEADERS64>(Kernel32.Kernel32 + (int)DosHeader.e_lfanew);
				DataDirectory = NtHeaders.OptionalHeader.DataDirectory[Win32.IMAGE_DIRECTORY_ENTRY_EXPORT];
			}
			else
			{
				Win32.IMAGE_NT_HEADERS32 NtHeaders = this.ReadStruct<Win32.IMAGE_NT_HEADERS32>(Kernel32.Kernel32 + (int)DosHeader.e_lfanew);
				DataDirectory = NtHeaders.OptionalHeader.DataDirectory[Win32.IMAGE_DIRECTORY_ENTRY_EXPORT];
			}

			Win32.IMAGE_EXPORT_DIRECTORY ExportDirectory = this.ReadStruct<Win32.IMAGE_EXPORT_DIRECTORY>(Kernel32.Kernel32 + (int)DataDirectory.VirtualAddress);

			IntPtr AddressArray = Kernel32.Kernel32 + (int)ExportDirectory.AddressOfFunctions;
			IntPtr NameArray = Kernel32.Kernel32 + (int)ExportDirectory.AddressOfNames;
			IntPtr NameOrdinals = Kernel32.Kernel32 + (int)ExportDirectory.AddressOfNameOrdinals;

			for (uint dwCounter = 0; dwCounter < ExportDirectory.NumberOfNames; dwCounter++)
			{
				string ExportedFunctionName = this.ReadStringAnsi(Kernel32.Kernel32 + this.ReadInt32(NameArray));
				bool CheckIfComplete = true;

				switch (ExportedFunctionName)
				{
					case "FreeLibrary":
						Kernel32._FreeLibrary
							= Kernel32.Kernel32
							+ this.ReadInt32(AddressArray
								+ (this.ReadInt16(NameOrdinals) * sizeof(uint)));
						break;
					case "GetLastError":
						Kernel32._GetLastError
							= Kernel32.Kernel32
							+ this.ReadInt32(AddressArray
								+ (this.ReadInt16(NameOrdinals) * sizeof(uint)));
						break;
					case "GetModuleHandleW":
						Kernel32._GetModuleHandleW
							= Kernel32.Kernel32
							+ this.ReadInt32(AddressArray
								+ (this.ReadInt16(NameOrdinals) * sizeof(uint)));
						break;
					case "GetProcAddress":
						Kernel32._GetProcAddress
							= Kernel32.Kernel32
							+ this.ReadInt32(AddressArray
								+ (this.ReadInt16(NameOrdinals) * sizeof(uint)));
						break;
					case "LoadLibraryW":
						Kernel32._LoadLibraryW
							= Kernel32.Kernel32
							+ this.ReadInt32(AddressArray
								+ (this.ReadInt16(NameOrdinals) * sizeof(uint)));
						break;
					default:
						CheckIfComplete = false;
						break;
				}

				if (CheckIfComplete
					&& Kernel32._LoadLibraryW != IntPtr.Zero
					&& Kernel32._GetProcAddress != IntPtr.Zero
					&& Kernel32._GetModuleHandleW != IntPtr.Zero
					&& Kernel32._GetLastError != IntPtr.Zero
					&& Kernel32._FreeLibrary != IntPtr.Zero)
					break;

				NameArray += sizeof(uint);
				NameOrdinals += sizeof(ushort);
			}

			if (Kernel32._FreeLibrary == IntPtr.Zero)
				throw new Exception("Cannot find FreeLibrary in Kernel32.dll.");

			if (Kernel32._GetLastError == IntPtr.Zero)
				throw new Exception("Cannot find GetLastError in Kernel32.dll.");

			if (Kernel32._GetModuleHandleW == IntPtr.Zero)
				throw new Exception("Cannot find GetModuleHandleW in Kernel32.dll.");

			if (Kernel32._GetProcAddress == IntPtr.Zero)
				throw new Exception("Cannot find GetProcAddress in Kernel32.dll.");

			if (Kernel32._LoadLibraryW == IntPtr.Zero)
				throw new Exception("Cannot find LoadLibraryW in Kernel32.dll.");

			//Kernel32.FreeLibrary = this.GetFunction<Kernel32Procedures.FreeLibraryPrototype>(Kernel32._FreeLibrary);
			Kernel32.FreeLibrary = (hModule) => this.CallFunctionThreadProc(Kernel32._FreeLibrary, hModule);
			Kernel32.GetLastError = this.GetFunction<Kernel32Procedures.GetLastErrorPrototype>(Kernel32._GetLastError);
			Kernel32.GetModuleHandleW = this.GetFunction<Kernel32Procedures.GetModuleHandleWPrototype>(Kernel32._GetModuleHandleW);
			Kernel32.GetProcAddress = this.GetFunction<Kernel32Procedures.GetProcAddressPrototype>(Kernel32._GetProcAddress);
			Kernel32.GetProcAddressOrdinal = this.GetFunction<Kernel32Procedures.GetProcAddressPrototypeOrdinal>(Kernel32._GetProcAddress);
			Kernel32.LoadLibraryW = this.GetFunction<Kernel32Procedures.LoadLibraryWPrototype>(Kernel32._LoadLibraryW);

			return Kernel32;
		}
	}
}