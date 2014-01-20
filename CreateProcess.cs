using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		public static DllInjector CreateProcess(string FileName, bool CreateSuspended = false, bool FreeOnDispose = false)
		{
			return CreateProcess(new ProcessStartInfo(FileName), CreateSuspended, FreeOnDispose);
		}

		public static DllInjector CreateProcess(string FileName, string Arguments, bool CreateSuspended = false, bool FreeOnDispose = false)
		{
			return CreateProcess(new ProcessStartInfo(FileName, Arguments), CreateSuspended, FreeOnDispose);
		}

		public static DllInjector CreateProcess(string FileName, string UserName, System.Security.SecureString Password, string Domain, bool CreateSuspended = false, bool FreeOnDispose = false)
		{
			return CreateProcess(new ProcessStartInfo(FileName)
			{
				UserName = UserName,
				Password = Password,
				Domain = Domain
			}, CreateSuspended, FreeOnDispose);
		}

		public static DllInjector CreateProcess(string FileName, string Arguments, string UserName, System.Security.SecureString Password, string Domain, bool CreateSuspended = false, bool FreeOnDispose = false)
		{
			return CreateProcess(new ProcessStartInfo(FileName, Arguments)
			{
				UserName = UserName,
				Password = Password,
				Domain = Domain
			}, CreateSuspended, FreeOnDispose);
		}

		public static DllInjector CreateProcess(ProcessStartInfo StartInfo, bool CreateSuspended = false, bool FreeOnDispose = false)
		{
			Process process;

			if (CreateSuspended)
			{
				if (StartInfo == null)
					throw new ArgumentNullException("StartInfo");

				if (string.IsNullOrEmpty(StartInfo.FileName))
					throw new ArgumentException("FileNameMissing");

				if (StartInfo.StandardOutputEncoding != null && !StartInfo.RedirectStandardOutput)
					throw new ArgumentException("StandardOutputEncodingNotAllowed");

				if (StartInfo.StandardErrorEncoding != null && !StartInfo.RedirectStandardError)
					throw new ArgumentException("StandardErrorEncodingNotAllowed");

				/*
				 * private static StringBuilder BuildCommandLine(string executableFileName, string arguments);
				 * 
				 * Declaring Type: System.Diagnostics.Process 
				 * Assembly: System, Version=4.0.0.0 
				 */
				StringBuilder cmdLine = new StringBuilder();
				string str = StartInfo.FileName.Trim();
				bool flag = str.StartsWith("\"", StringComparison.Ordinal) && str.EndsWith("\"", StringComparison.Ordinal);

				if (!flag)
					cmdLine.Append("\"");

				cmdLine.Append(str);

				if (!flag)
					cmdLine.Append("\"");

				if (!string.IsNullOrEmpty(StartInfo.Arguments))
				{
					cmdLine.Append(" ");
					cmdLine.Append(StartInfo.Arguments);
				}

				/*
				 * private bool StartWithCreateProcess(ProcessStartInfo startInfo);
				 * 
				 * Declaring Type: System.Diagnostics.Process
				 * Assembly: System, Version=4.0.0.0
				 */
				Win32.STARTUPINFO lpStartupInfo = new Win32.STARTUPINFO()
				{
					hStdError = new SafeFileHandle(IntPtr.Zero, false),
					hStdInput = new SafeFileHandle(IntPtr.Zero, false),
					hStdOutput = new SafeFileHandle(IntPtr.Zero, false)
				};
				Win32.PROCESS_INFORMATION lpProcessInformation = new Win32.PROCESS_INFORMATION();
				IntPtr processHandle = IntPtr.Zero;
				IntPtr handle2 = IntPtr.Zero;
				SafeFileHandle parentHandle = null;
				SafeFileHandle handle4 = null;
				SafeFileHandle handle5 = null;
				int error = 0;
				GCHandle handle6 = new GCHandle();

				try
				{
					if (StartInfo.RedirectStandardInput || StartInfo.RedirectStandardOutput || StartInfo.RedirectStandardError)
					{
						if (StartInfo.RedirectStandardInput)
							CreatePipe(out parentHandle, out lpStartupInfo.hStdInput, true);
						else
							lpStartupInfo.hStdInput = new SafeFileHandle(Win32.GetStdHandle(Win32.StdHandles.STD_INPUT_HANDLE), false);

						if (StartInfo.RedirectStandardOutput)
							CreatePipe(out handle4, out lpStartupInfo.hStdOutput, false);
						else
							lpStartupInfo.hStdOutput = new SafeFileHandle(Win32.GetStdHandle(Win32.StdHandles.STD_OUTPUT_HANDLE), false);

						if (StartInfo.RedirectStandardError)
							CreatePipe(out handle5, out lpStartupInfo.hStdError, false);
						else
							lpStartupInfo.hStdError = new SafeFileHandle(Win32.GetStdHandle(Win32.StdHandles.STD_ERROR_HANDLE), false);

						lpStartupInfo.dwFlags = 0x100;
					}

					Win32.ProcessCreationFlags creationFlags = Win32.ProcessCreationFlags.CREATE_SUSPENDED;

					if (StartInfo.CreateNoWindow)
						creationFlags |= Win32.ProcessCreationFlags.CREATE_NO_WINDOW;

					if (Utilities.IsNt)
					{
						creationFlags |= Win32.ProcessCreationFlags.CREATE_UNICODE_ENVIRONMENT;
						handle6 = GCHandle.Alloc(EnvironmentBlock.ToByteArray(StartInfo.EnvironmentVariables, true), GCHandleType.Pinned);
					}
					else
						handle6 = GCHandle.Alloc(EnvironmentBlock.ToByteArray(StartInfo.EnvironmentVariables, false), GCHandleType.Pinned);

					string workingDirectory = StartInfo.WorkingDirectory;

					if (workingDirectory == string.Empty)
						workingDirectory = Environment.CurrentDirectory;

					if (StartInfo.UserName.Length != 0)
					{
						Win32.LogonFlags logonFlags = 0;

						if (StartInfo.LoadUserProfile)
							logonFlags = Win32.LogonFlags.LOGON_WITH_PROFILE;

						IntPtr password = IntPtr.Zero;

						try
						{
							if (StartInfo.Password == null)
								password = Marshal.StringToCoTaskMemUni(string.Empty);
							else
								password = Marshal.SecureStringToCoTaskMemUnicode(StartInfo.Password);

							RuntimeHelpers.PrepareConstrainedRegions();

							try
							{
							}
							finally
							{
								flag = Win32.CreateProcessWithLogon(StartInfo.UserName, StartInfo.Domain, password, logonFlags, null, cmdLine, creationFlags, handle6.AddrOfPinnedObject(), workingDirectory, ref lpStartupInfo, out lpProcessInformation);

								if (!flag)
									error = Marshal.GetLastWin32Error();

								if (lpProcessInformation.hProcess != IntPtr.Zero && lpProcessInformation.hProcess != Win32.INVALID_HANDLE_VALUE)
									processHandle = lpProcessInformation.hProcess;

								if (lpProcessInformation.hThread != IntPtr.Zero && lpProcessInformation.hThread != Win32.INVALID_HANDLE_VALUE)
									handle2 = lpProcessInformation.hThread;
							}

							if (!flag)
							{
								if ((error != 0xc1) && (error != 0xd8))
									throw new Win32Exception(error);

								throw new Win32Exception(error, "InvalidApplication");
							}
						}
						finally
						{
							if (password != IntPtr.Zero)
								Marshal.ZeroFreeCoTaskMemUnicode(password);
						}
					}
					else
					{
						RuntimeHelpers.PrepareConstrainedRegions();

						try
						{
						}
						finally
						{
							flag = Win32.CreateProcess(null, cmdLine, IntPtr.Zero, IntPtr.Zero, true, creationFlags, handle6.AddrOfPinnedObject(), workingDirectory, ref lpStartupInfo, out lpProcessInformation);

							if (!flag)
								error = Marshal.GetLastWin32Error();

							if (lpProcessInformation.hProcess != IntPtr.Zero && lpProcessInformation.hProcess != Win32.INVALID_HANDLE_VALUE)
								processHandle = lpProcessInformation.hProcess;

							if (lpProcessInformation.hThread != IntPtr.Zero && lpProcessInformation.hThread != Win32.INVALID_HANDLE_VALUE)
								handle2 = lpProcessInformation.hThread;
						}

						if (!flag)
						{
							if ((error != 0xc1) && (error != 0xd8))
								throw new Win32Exception(error);

							throw new Win32Exception(error, "InvalidApplication");
						}
					}
				}
				finally
				{
					if (handle6.IsAllocated)
						handle6.Free();

					if (lpStartupInfo.hStdInput != null && !lpStartupInfo.hStdInput.IsInvalid)
						lpStartupInfo.hStdInput.Close();

					if (lpStartupInfo.hStdOutput != null && !lpStartupInfo.hStdOutput.IsInvalid)
						lpStartupInfo.hStdOutput.Close();

					if (lpStartupInfo.hStdError != null && !lpStartupInfo.hStdError.IsInvalid)
						lpStartupInfo.hStdError.Close();
				}

				if (processHandle != IntPtr.Zero && processHandle != Win32.INVALID_HANDLE_VALUE)
					Win32.CloseHandle(handle2);

				process = Process.GetProcessById((int)lpProcessInformation.dwProcessId);

				if (StartInfo.RedirectStandardInput)
				{
					FieldInfo standardInput = typeof(Process).GetField("standardInput", BindingFlags.Instance | BindingFlags.NonPublic);
					standardInput.SetValue(process, new StreamWriter(new FileStream(parentHandle, FileAccess.Write, 0x1000, false), Console.InputEncoding, 0x1000)
					{
						AutoFlush = true
					});
				}

				if (StartInfo.RedirectStandardOutput)
				{
					FieldInfo standardOutput = typeof(Process).GetField("standardOutput", BindingFlags.Instance | BindingFlags.NonPublic);
					standardOutput.SetValue(process, new StreamReader(new FileStream(handle4, FileAccess.Read, 0x1000, false), (StartInfo.StandardOutputEncoding != null) ? StartInfo.StandardOutputEncoding : Console.OutputEncoding, true, 0x1000));
				}

				if (StartInfo.RedirectStandardError)
				{
					FieldInfo standardError = typeof(Process).GetField("standardError", BindingFlags.Instance | BindingFlags.NonPublic);
					standardError.SetValue(process, new StreamReader(new FileStream(handle5, FileAccess.Read, 0x1000, false), (StartInfo.StandardErrorEncoding != null) ? StartInfo.StandardErrorEncoding : Console.OutputEncoding, true, 0x1000));
				}
			}
			else
				process = Process.Start(StartInfo);

			return new DllInjector(process, FreeOnDispose);
		}
		
		private static void CreatePipe(out SafeFileHandle parentHandle, out SafeFileHandle childHandle, bool parentInputs)
		{
			/*
			 * private void CreatePipe(out SafeFileHandle parentHandle, out SafeFileHandle childHandle, bool parentInputs);
			 * 
			 * Declaring Type: System.Diagnostics.Process
			 * Assembly: System, Version=4.0.0.0
			 */
			parentHandle = childHandle = null;

			Win32.SECURITY_ATTRIBUTES lpPipeAttributes = new Win32.SECURITY_ATTRIBUTES();
			lpPipeAttributes.bInheritHandle = true;
			SafeFileHandle hWritePipe = null;

			try
			{
				if (parentInputs && (!Win32.CreatePipe(out childHandle, out hWritePipe, ref lpPipeAttributes, 0) || childHandle.IsInvalid || hWritePipe.IsInvalid))
					throw new Win32Exception();
				else if (!parentInputs && (!Win32.CreatePipe(out hWritePipe, out childHandle, ref lpPipeAttributes, 0) || hWritePipe.IsInvalid || childHandle.IsInvalid))
					throw new Win32Exception();

				if (!Win32.DuplicateHandle(Process.GetCurrentProcess().Handle, hWritePipe, Process.GetCurrentProcess().Handle, out parentHandle, 0, false, 2))
					throw new Win32Exception();
			}
			finally
			{
				if (hWritePipe != null && !hWritePipe.IsInvalid)
					hWritePipe.Close();
			}
		}

		private static class EnvironmentBlock
		{
			private sealed class OrdinalCaseInsensitiveComparer : System.Collections.IComparer
			{
				/*
				 * private class OrdinalCaseInsensitiveComparer : IComparer
				 * 
				 * Name: System.Diagnostics.OrdinalCaseInsensitiveComparer 
				 * Assembly: System, Version=4.0.0.0
				 */
				public static readonly OrdinalCaseInsensitiveComparer Default = new OrdinalCaseInsensitiveComparer();

				public int Compare(object a, object b)
				{
					string strA = a as string;
					string strB = b as string;

					if (strA != null && strB != null)
						return string.Compare(strA, strB, StringComparison.OrdinalIgnoreCase);

					return System.Collections.Comparer.Default.Compare(a, b);
				}
			}

			public static byte[] ToByteArray(System.Collections.Specialized.StringDictionary sd, bool unicode)
			{
				/*
				 * public static byte[] ToByteArray(StringDictionary sd, bool unicode);
				 * 
				 * Declaring Type: System.Diagnostics.EnvironmentBlock 
				 * Assembly: System, Version=4.0.0.0
				 */
				string[] array = new string[sd.Count];

				byte[] bytes = null;

				sd.Keys.CopyTo(array, 0);

				string[] strArray2 = new string[sd.Count];

				sd.Values.CopyTo(strArray2, 0);

				Array.Sort(array, strArray2, OrdinalCaseInsensitiveComparer.Default);

				StringBuilder builder = new StringBuilder();

				for (int i = 0; i < sd.Count; i++)
				{
					builder.Append(array[i]);
					builder.Append('=');
					builder.Append(strArray2[i]);
					builder.Append('\0');
				}

				builder.Append('\0');

				if (unicode)
					bytes = Encoding.Unicode.GetBytes(builder.ToString());
				else
					bytes = Encoding.Default.GetBytes(builder.ToString());

				if (bytes.Length > 0xffff)
					throw new InvalidOperationException("EnvironmentBlockTooLong");

				return bytes;
			}
		}
	}
}