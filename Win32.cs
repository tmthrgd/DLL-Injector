using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		private static class Win32
		{
			[DllImport("Kernel32.dll", EntryPoint = "LoadLibraryW", SetLastError = true, CharSet = CharSet.Unicode)]
			public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPWStr)] string FileName);

			[DllImport("Kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool FreeLibrary(IntPtr hModule);

			[DllImport("Kernel32.dll", EntryPoint = "GetModuleHandleW", SetLastError = true, CharSet = CharSet.Unicode)]
			public static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string ModuleName);

			[DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
			public static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)] string ProcName);

			[DllImport("Kernel32.dll", SetLastError = true)]
			public static extern IntPtr OpenProcess(ProcessAccess dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

			[DllImport("Kernel32.dll", SetLastError = true)]
			public static extern WaitForSingleObjectReturn WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

			[DllImport("Kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool GetExitCodeThread(IntPtr hThread, out uint ExitCode);

			[DllImport("Kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool CloseHandle(IntPtr hObject);

			[DllImport("Kernel32.dll", SetLastError = true)]
			public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, VirtualAllocExAllocationType flAllocationType, MemoryProtection flProtect);

			[DllImport("Kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, VirtualFreeExFreeType dwFreeType);

			[DllImport("Kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, MemoryProtection flNewProtect, out MemoryProtection flOldProtect);

			[DllImport("Kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.LPArray), In, Out] byte[] Buffer, uint nSize, out uint NumberOfBytesRead);

			[DllImport("Kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, out uint NumberOfBytesRead);

			[DllImport("Kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.LPArray)] byte[] Buffer, uint nSize, out uint NumberOfBytesWritten);

			[DllImport("Kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, out uint NumberOfBytesWritten);

			[DllImport("Kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, uint dwSize);

			[DllImport("Kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool IsWow64Process(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] out bool Wow64Process);

			[DllImport("Kernel32.dll", SetLastError = true)]
			public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, CreateRemoteThreadCreationFlags dwCreationFlags, IntPtr lpThreadId);

			[DllImport("Ntdll.dll")]
			public static extern uint NtCreateThreadEx(out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, [MarshalAs(UnmanagedType.Bool)] bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer);

			[DllImport("Psapi.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool EnumProcessModulesEx(IntPtr hProcess, [MarshalAs(UnmanagedType.LPArray)] IntPtr[] hModule, uint cb, out uint cbNeeded, EnumProcessModulesExFilterFlags dwFilterFlag);

			[DllImport("Psapi.dll", EntryPoint = "GetModuleBaseNameW", SetLastError = true, CharSet = CharSet.Unicode)]
			public static extern uint GetModuleBaseName(IntPtr hProcess, IntPtr hModule, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder BaseName, uint nSize);

			[DllImport("Kernel32.dll", SetLastError = true)]
			public static extern uint SuspendThread(IntPtr hThread);

			[DllImport("Kernel32.dll", SetLastError = true)]
			public static extern uint Wow64SuspendThread(IntPtr hThread);

			[DllImport("Kernel32.dll", SetLastError = true)]
			public static extern uint ResumeThread(IntPtr hThread);

			[DllImport("Kernel32.dll", SetLastError = true)]
			public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwThreadId);

			[DllImport("Kernel32.dll", EntryPoint = "CreateProcessW", SetLastError = true, CharSet = CharSet.Unicode)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool CreateProcess([MarshalAs(UnmanagedType.LPWStr)] string lpApplicationName, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, [MarshalAs(UnmanagedType.LPWStr)] string lpCurrentDirectory, [MarshalAs(UnmanagedType.Struct)] ref STARTUPINFO lpStartupInfo, [MarshalAs(UnmanagedType.Struct)] out PROCESS_INFORMATION lpProcessInformation);

			[DllImport("Advapi32.dll", EntryPoint = "CreateProcessWithLogonW", SetLastError = true, CharSet = CharSet.Unicode)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool CreateProcessWithLogon([MarshalAs(UnmanagedType.LPWStr)] string lpUsername, [MarshalAs(UnmanagedType.LPWStr)] string lpDomain, IntPtr lpPassword, LogonFlags dwLogonFlags, [MarshalAs(UnmanagedType.LPWStr)] string lpApplicationName, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpCommandLine, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, [MarshalAs(UnmanagedType.LPWStr)] string lpCurrentDirectory, [MarshalAs(UnmanagedType.Struct)] ref STARTUPINFO lpStartupInfo, [MarshalAs(UnmanagedType.Struct)] out PROCESS_INFORMATION lpProcessInfo);

			[DllImport("Kernel32.dll", SetLastError = true)]
			public static extern IntPtr GetStdHandle(StdHandles nStdHandle);

			[DllImport("Kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool CreatePipe(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe, [MarshalAs(UnmanagedType.Struct)] ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

			[DllImport("Kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, SafeFileHandle hSourceHandle, IntPtr hTargetProcessHandle, out SafeFileHandle lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

			[DllImport("Kernel32.dll", SetLastError = true)]
			public static extern uint VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

			public const uint INFINITE = 0xFFFFFFFF;

			public const uint ERROR_SUCCESS = 0;
			public const uint ERROR_INVALID_HANDLE = 6;
			public const uint ERROR_NOT_ENOUGH_MEMORY = 8;
			public const uint ERROR_INVALID_BLOCK = 9;

			public const uint NO_ERROR = 0;

			public const uint MEM_FREE = 0x10000;

			public const uint IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
			public const uint IMAGE_DIRECTORY_ENTRY_IAT = 12;

			public const int IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
			public const int IMAGE_SIZEOF_SHORT_NAME = 8;

			public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

			[Flags]
			public enum CreateRemoteThreadCreationFlags : uint
			{
				None = 0,
				CREATE_SUSPENDED = 0x00000004,
				STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
			}

			public enum WaitForSingleObjectReturn : uint
			{
				WAIT_ABANDONED = 0x80,
				WAIT_OBJECT_0 = 0x0,
				WAIT_TIMEOUT = 0x102,
				WAIT_FAILED = (uint)0xFFFFFFFF
			}

			[Flags]
			public enum ProcessAccess : uint
			{
				DELETE = 0x10000,
				READ_CONTROL = 0x20000,
				SYNCHRONIZE = 0x100000,
				WRITE_DAC = 0x40000,
				WRITE_OWNER = 0x80000,
				PROCESS_CREATE_PROCESS = 0x80,
				PROCESS_CREATE_THREAD = 0x2,
				PROCESS_DUP_HANDLE = 0x40,
				PROCESS_QUERY_INFORMATION = 0x400,
				PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
				PROCESS_SET_INFORMATION = 0x200,
				PROCESS_SET_QUOTA = 0x100,
				PROCESS_SUSPEND_RESUME = 0x800,
				PROCESS_TERMINATE = 0x1,
				PROCESS_VM_OPERATION = 0x8,
				PROCESS_VM_READ = 0x10,
				PROCESS_VM_WRITE = 0x20,
				PROCESS_ALL_ACCESS = 0xF0000 | SYNCHRONIZE | 0xFFFF
			}

			[Flags]
			public enum ThreadAccess : uint
			{
				DELETE = 0x10000,
				READ_CONTROL = 0x20000,
				SYNCHRONIZE = 0x100000,
				WRITE_DAC = 0x40000,
				WRITE_OWNER = 0x80000,
				THREAD_DIRECT_IMPERSONATION = 0x0200,
				THREAD_GET_CONTEXT = 0x0008,
				THREAD_IMPERSONATE = 0x0100,
				THREAD_QUERY_INFORMATION = 0x0040,
				THREAD_QUERY_LIMITED_INFORMATION = 0x0800,
				THREAD_SET_CONTEXT = 0x0010,
				THREAD_SET_INFORMATION = 0x0020,
				THREAD_SET_LIMITED_INFORMATION = 0x0400,
				THREAD_SET_THREAD_TOKEN = 0x0080,
				THREAD_SUSPEND_RESUME = 0x0002,
				THREAD_TERMINATE = 0x0001,
				THREAD_ALL_ACCESS = 0xF0000 | SYNCHRONIZE | 0xFFFF
			}

			[Flags]
			public enum ProcessCreationFlags : uint
			{
				CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
				CREATE_DEFAULT_ERROR_MODE = 0x04000000,
				CREATE_NEW_CONSOLE = 0x00000010,
				CREATE_NEW_PROCESS_GROUP = 0x00000200,
				CREATE_NO_WINDOW = 0x08000000,
				CREATE_PROTECTED_PROCESS = 0x00040000,
				CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
				CREATE_SEPARATE_WOW_VDM = 0x00000800,
				CREATE_SHARED_WOW_VDM = 0x00001000,
				CREATE_SUSPENDED = 0x00000004,
				CREATE_UNICODE_ENVIRONMENT = 0x00000400,
				DEBUG_ONLY_THIS_PROCESS = 0x00000002,
				DEBUG_PROCESS = 0x00000001,
				DETACHED_PROCESS = 0x00000008,
				EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
				INHERIT_PARENT_AFFINITY = 0x00010000
			}

			[Flags]
			public enum LogonFlags
			{
				LOGON_NETCREDENTIALS_ONLY = 2,
				LOGON_WITH_PROFILE = 1
			}

			public enum StdHandles : uint
			{
				STD_INPUT_HANDLE = unchecked((uint)-10),
				STD_OUTPUT_HANDLE = unchecked((uint)-11),
				STD_ERROR_HANDLE = unchecked((uint)-12)
			}

			[Flags]
			public enum VirtualAllocExAllocationType : uint
			{
				MEM_COMMIT = 0x1000,
				MEM_RESERVE = 0x2000,
				MEM_RESET = 0x80000,
				MEM_LARGE_PAGES = 0x20000000,
				MEM_PHYSICAL = 0x400000,
				MEM_TOP_DOWN = 0x100000
			}

			[Flags]
			public enum VirtualFreeExFreeType : uint
			{
				MEM_DECOMMIT = 0x4000,
				MEM_RELEASE = 0x8000
			}

			public enum EnumProcessModulesExFilterFlags : uint
			{
				LIST_MODULES_32BIT = 0x01,
				LIST_MODULES_64BIT = 0x02,
				LIST_MODULES_ALL = 0x03,
				LIST_MODULES_DEFAULT = 0x00
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct IMAGE_DOS_HEADER
			{
				[MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
				public char[] e_magic;       // Magic number
				public ushort e_cblp;    // Bytes on last page of file
				public ushort e_cp;      // Pages in file
				public ushort e_crlc;    // Relocations
				public ushort e_cparhdr;     // Size of header in paragraphs
				public ushort e_minalloc;    // Minimum extra paragraphs needed
				public ushort e_maxalloc;    // Maximum extra paragraphs needed
				public ushort e_ss;      // Initial (relative) SS value
				public ushort e_sp;      // Initial SP value
				public ushort e_csum;    // Checksum
				public ushort e_ip;      // Initial IP value
				public ushort e_cs;      // Initial (relative) CS value
				public ushort e_lfarlc;      // File address of relocation table
				public ushort e_ovno;    // Overlay number
				[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
				public ushort[] e_res1;    // Reserved words
				public ushort e_oemid;       // OEM identifier (for e_oeminfo)
				public ushort e_oeminfo;     // OEM information; e_oemid specific
				[MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
				public ushort[] e_res2;    // Reserved words
				public uint e_lfanew;      // File address of new exe header

				public string _e_magic
				{
					get
					{
						return new string(this.e_magic);
					}
				}
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct IMAGE_NT_HEADERS32
			{
				[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
				public char[] Signature;
				public IMAGE_FILE_HEADER FileHeader;
				public IMAGE_OPTIONAL_HEADER32 OptionalHeader;

				public string _Signature
				{
					get
					{
						return new string(this.Signature);
					}
				}
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct IMAGE_NT_HEADERS64
			{
				[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
				public char[] Signature;
				public IMAGE_FILE_HEADER FileHeader;
				public IMAGE_OPTIONAL_HEADER64 OptionalHeader;

				public string _Signature
				{
					get
					{
						return new string(this.Signature);
					}
				}
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct IMAGE_OPTIONAL_HEADER32
			{
				public IMAGE_OPTIONAL_HEADER_Magic Magic;
				public byte MajorLinkerVersion;
				public byte MinorLinkerVersion;
				public uint SizeOfCode;
				public uint SizeOfInitializedData;
				public uint SizeOfUninitializedData;
				public uint AddressOfEntryPoint;
				public uint BaseOfCode;
				public uint BaseOfData;
				public uint ImageBase;
				public uint SectionAlignment;
				public uint FileAlignment;
				public ushort MajorOperatingSystemVersion;
				public ushort MinorOperatingSystemVersion;
				public ushort MajorImageVersion;
				public ushort MinorImageVersion;
				public ushort MajorSubsystemVersion;
				public ushort MinorSubsystemVersion;
				public uint Win32VersionValue;
				public uint SizeOfImage;
				public uint SizeOfHeaders;
				public uint CheckSum;
				public IMAGE_OPTIONAL_HEADER_Subsystem Subsystem;
				public IMAGE_OPTIONAL_HEADER_DllCharacteristics DllCharacteristics;
				public uint SizeOfStackReserve;
				public uint SizeOfStackCommit;
				public uint SizeOfHeapReserve;
				public uint SizeOfHeapCommit;
				public uint LoaderFlags;
				public uint NumberOfRvaAndSizes;

				[MarshalAs(UnmanagedType.ByValArray, SizeConst = Win32.IMAGE_NUMBEROF_DIRECTORY_ENTRIES)]
				public IMAGE_DATA_DIRECTORY[] DataDirectory;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct IMAGE_OPTIONAL_HEADER64
			{
				public IMAGE_OPTIONAL_HEADER_Magic Magic;
				public byte MajorLinkerVersion;
				public byte MinorLinkerVersion;
				public uint SizeOfCode;
				public uint SizeOfInitializedData;
				public uint SizeOfUninitializedData;
				public uint AddressOfEntryPoint;
				public uint BaseOfCode;
				public ulong ImageBase;
				public uint SectionAlignment;
				public uint FileAlignment;
				public ushort MajorOperatingSystemVersion;
				public ushort MinorOperatingSystemVersion;
				public ushort MajorImageVersion;
				public ushort MinorImageVersion;
				public ushort MajorSubsystemVersion;
				public ushort MinorSubsystemVersion;
				public uint Win32VersionValue;
				public uint SizeOfImage;
				public uint SizeOfHeaders;
				public uint CheckSum;
				public IMAGE_OPTIONAL_HEADER_Subsystem Subsystem;
				public IMAGE_OPTIONAL_HEADER_DllCharacteristics DllCharacteristics;
				public ulong SizeOfStackReserve;
				public ulong SizeOfStackCommit;
				public ulong SizeOfHeapReserve;
				public ulong SizeOfHeapCommit;
				public uint LoaderFlags;
				public uint NumberOfRvaAndSizes;

				[MarshalAs(UnmanagedType.ByValArray, SizeConst = Win32.IMAGE_NUMBEROF_DIRECTORY_ENTRIES)]
				public IMAGE_DATA_DIRECTORY[] DataDirectory;
			}

			public enum IMAGE_OPTIONAL_HEADER_Magic : ushort
			{
/*#if WIN_64
				IMAGE_NT_OPTIONAL_HDR_MAGIC = IMAGE_NT_OPTIONAL_HDR64_MAGIC,
#else
				IMAGE_NT_OPTIONAL_HDR_MAGIC = IMAGE_NT_OPTIONAL_HDR32_MAGIC,
#endif*/
				IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10,
				IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20,
				IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107
			}

			public enum IMAGE_OPTIONAL_HEADER_Subsystem : ushort
			{
				IMAGE_SUBSYSTEM_UNKNOWN = 0,
				IMAGE_SUBSYSTEM_NATIVE = 1,
				IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
				IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
				IMAGE_SUBSYSTEM_OS2_CUI = 5,
				IMAGE_SUBSYSTEM_POSIX_CUI = 7,
				IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
				IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
				IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
				IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
				IMAGE_SUBSYSTEM_EFI_ROM = 13,
				IMAGE_SUBSYSTEM_XBOX = 14,
				IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
			}

			public enum IMAGE_OPTIONAL_HEADER_DllCharacteristics : ushort
			{
				IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x40,
				IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x80,
				IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x100,
				IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x200,
				IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x400,
				IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x800,
				IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
				IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct IMAGE_DATA_DIRECTORY
			{
				public uint VirtualAddress;
				public uint Size;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct IMAGE_EXPORT_DIRECTORY
			{
				public uint Characteristics;
				public uint TimeDateStamp;
				public ushort MajorVersion;
				public ushort MinorVersion;
				public uint Name;
				public uint Base;
				public uint NumberOfFunctions;
				public uint NumberOfNames;
				public uint AddressOfFunctions;     // RVA from base of image
				public uint AddressOfNames;			// RVA from base of image
				public uint AddressOfNameOrdinals;  // RVA from base of image
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct IMAGE_FILE_HEADER
			{
				public IMAGE_FILE_HEADER_Machine Machine;
				public ushort NumberOfSections;
				public uint TimeDateStamp;
				public uint PointerToSymbolTable;
				public uint NumberOfSymbols;
				public ushort SizeOfOptionalHeader;
				public IMAGE_FILE_HEADER_Characteristics Characteristics;
			}

			public enum IMAGE_FILE_HEADER_Machine : ushort
			{
				IMAGE_FILE_MACHINE_I386 = 0x14c,
				IMAGE_FILE_MACHINE_IA64 = 0x200,
				IMAGE_FILE_MACHINE_AMD64 = 0x8664
			}

			[Flags]
			public enum IMAGE_FILE_HEADER_Characteristics : ushort
			{
				IMAGE_FILE_RELOCS_STRIPPED = 0x1,
				IMAGE_FILE_EXECUTABLE_IMAGE = 0x2,
				IMAGE_FILE_LINE_NUMS_STRIPPED = 0x4,
				IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x8,
				IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x10,
				IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x20,
				IMAGE_FILE_BYTES_REVERSED_LO = 0x80,
				IMAGE_FILE_32BIT_MACHINE = 0x100,
				IMAGE_FILE_DEBUG_STRIPPED = 0x200,
				IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x400,
				IMAGE_FILE_NET_RUN_FROM_SWAP = 0x800,
				IMAGE_FILE_SYSTEM = 0x1000,
				IMAGE_FILE_DLL = 0x2000,
				IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
				IMAGE_FILE_BYTES_REVERSED_HI = 0x8000
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct IMAGE_SECTION_HEADER
			{
				[MarshalAs(UnmanagedType.ByValArray, SizeConst = Win32.IMAGE_SIZEOF_SHORT_NAME)]
				public char[] Name;
				public IMAGE_SECTION_HEADER_Misc Misc;
				public uint VirtualAddress;
				public uint SizeOfRawData;
				public uint PointerToRawData;
				public uint PointerToRelocations;
				public uint PointerToLinenumbers;
				public ushort NumberOfRelocations;
				public ushort NumberOfLinenumbers;
				public uint Characteristics;

				public string _Name
				{
					get
					{
						return new string(this.Name);
					}
				}
			}

			[StructLayout(LayoutKind.Explicit)]
			public struct IMAGE_SECTION_HEADER_Misc
			{
				[FieldOffset(0)]
				public uint PhysicalAddress;
				[FieldOffset(0)]
				public uint VirtualSize;
			}

			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
			public struct STARTUPINFO
			{
				public uint cb;
				public IntPtr lpReserved;
				[MarshalAs(UnmanagedType.LPWStr)]
				public string lpDesktop;
				[MarshalAs(UnmanagedType.LPWStr)]
				public string lpTitle;
				public uint dwX;
				public uint dwY;
				public uint dwXSize;
				public uint dwYSize;
				public uint dwXCountChars;
				public uint dwYCountChars;
				public uint dwFillAttribute;
				public uint dwFlags;
				public ushort wShowWindow;
				public ushort cbReserved2;
				public IntPtr lpReserved2;
				public SafeFileHandle hStdInput;
				public SafeFileHandle hStdOutput;
				public SafeFileHandle hStdError;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct PROCESS_INFORMATION
			{
				public IntPtr hProcess;
				public IntPtr hThread;
				public uint dwProcessId;
				public uint dwThreadId;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct SECURITY_ATTRIBUTES
			{
				public uint nLength;
				public IntPtr lpSecurityDescriptor;
				public bool bInheritHandle;
			}

			[StructLayout(LayoutKind.Sequential)]
			public struct MEMORY_BASIC_INFORMATION
			{
				public IntPtr BaseAddress;
				public IntPtr AllocationBase;
				public uint AllocationProtect;
				public IntPtr RegionSize;
				public uint State;
				public uint Protect;
				public uint Type;
			}
		}
	}
}