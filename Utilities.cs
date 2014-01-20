using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		public int GetLastError()
		{
			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			return this.Kernel32.GetLastError();
		}

		public static T StructToStruct<T>(object data)
		{
			return (T)StructToStruct(data, typeof(T));
		}

		public static object StructToStruct(object data, Type t)
		{
			if (data is SafeHandle)
				data = ((SafeHandle)data).Value;

			IntPtr ptr = Marshal.AllocHGlobal(Math.Max(Marshal.SizeOf(data), Marshal.SizeOf(t)));
			
			try
			{
				Marshal.StructureToPtr(data, ptr, false);
				return Marshal.PtrToStructure(ptr, t);
			}
			finally
			{
				Marshal.FreeHGlobal(ptr);
			}
		}

		private static class Utilities
		{
			// Dodgy
			public static void Log(string msg)
			{
				ConsoleColor ForegroundColor = Console.ForegroundColor;
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine(msg);
				Console.ForegroundColor = ForegroundColor;
			}

			public static void Log(string format, params object[] args)
			{
				Log(string.Format(format, args));
			}

			public static void Log(string msg, Exception ex)
			{
				Log(string.Format("{0}\r\n{1}", msg, ex));
			}

			public static void Log(Exception ex)
			{
				Log(ex.ToString());
			}
			// Dodgy

			public static void PreserveStackTrace(Exception exception)
			{
				typeof(Exception)
					.GetMethod("InternalPreserveStackTrace", BindingFlags.Instance | BindingFlags.NonPublic)
					.Invoke(exception, null);
			}

			public static int Align(int i, int alignment)
			{
				return i + (alignment - (i % alignment)) % alignment;
			}

			public static bool DoesWin32MethodExist(string moduleName, string methodName)
			{
				IntPtr moduleHandle = Win32.GetModuleHandle(moduleName);
				return moduleHandle != IntPtr.Zero
					&& Win32.GetProcAddress(moduleHandle, methodName) != IntPtr.Zero;
			}

			public static bool IsWow64Process(Process process)
			{
				if (process == null)
					throw new ArgumentNullException("process");

				if (!Utilities.DoesWin32MethodExist("Kernel32.dll", "IsWow64Process"))
					return false;

				bool Wow64Process;

				if (!Win32.IsWow64Process(process.Handle, out Wow64Process))
					throw new Win32Exception();

				return Wow64Process;
			}

			public static bool Is64BitProcess(Process process)
			{
				return Utilities.Is64BitOperatingSystem
					&& !Utilities.IsWow64Process(process);
			}

			public static IntPtr OffsetOf<T>(IntPtr p, string s)
				where T : struct
			{
				return Utilities.OffsetOf(p, typeof(T), s);
			}

			public static IntPtr OffsetOf(IntPtr p, Type o, string s)
			{
				return new IntPtr(p.ToInt64() + Marshal.OffsetOf(o, s).ToInt64());
			}

			private static bool? _Is64BitOperatingSystem;
			public static bool Is64BitOperatingSystem
			{
				get
				{
#if DOTNET_40
					return Environment.Is64BitOperatingSystem;
#else
					if (IntPtr.Size == 8)
						return true;
					
					if (!_Is64BitOperatingSystem.HasValue)
						_Is64BitOperatingSystem = Utilities.IsWow64Process(Process.GetCurrentProcess());
					
					return _Is64BitOperatingSystem.Value;
#endif
				}
			}

			public static bool IsNt
			{
				get
				{
					return Environment.OSVersion.Platform == PlatformID.Win32NT;
				}
			}
		}
	}
}