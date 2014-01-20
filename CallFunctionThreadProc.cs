using System;
using System.ComponentModel;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		public uint CallFunctionThreadProc<T>(IntPtr Function, ref T Paramater)
			where T : struct
		{
			if (Function == IntPtr.Zero)
				throw new ArgumentNullException("Function");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			using (MemoryHandle lpParamater = this.WriteStruct(Paramater))
			{
				uint res = this.CallFunctionThreadProc(Function, lpParamater);

				Paramater = this.ReadStruct<T>(lpParamater);
				
				return res;
			}
		}

		public uint CallFunctionThreadProc(IntPtr Function, IntPtr Paramater = default(IntPtr))
		{
			if (Function == IntPtr.Zero)
				throw new ArgumentNullException("Function");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			IntPtr hRemoteThread = IntPtr.Zero;

			try
			{
				if (Utilities.DoesWin32MethodExist("Ntdll.dll", "NtCreateThreadEx"))
				{
					uint Status = Win32.NtCreateThreadEx(out hRemoteThread, 0x1FFFFF, IntPtr.Zero, this.hProc, Function, Paramater, false, 0, 0, 0, IntPtr.Zero);

					// Win32.ERROR_SUCCESS?

					//if (Status != 0x0)
					if (Status != 0x0 || hRemoteThread == IntPtr.Zero)
					{
						if (hRemoteThread == IntPtr.Zero)
							hRemoteThread = Win32.CreateRemoteThread(this.hProc, IntPtr.Zero, 0, Function, Paramater, Win32.CreateRemoteThreadCreationFlags.None, IntPtr.Zero);

						if (hRemoteThread != IntPtr.Zero)
							Utilities.Log("DllInjector.CallFunctionThreadProc, NtCreateThreadEx failed, 0x{0:X}\r\n(See http://msdn.microsoft.com/en-us/library/cc704588.aspx)", Status);
						else
							throw new Exception(string.Format("DllInjector.CallFunctionThreadProc, NtCreateThreadEx failed, 0x{0:X}\r\n(See http://msdn.microsoft.com/en-us/library/cc704588.aspx)", Status), new Win32Exception());
					}
				}
				else
				{
					hRemoteThread = Win32.CreateRemoteThread(this.hProc, IntPtr.Zero, 0, Function, Paramater, Win32.CreateRemoteThreadCreationFlags.None, IntPtr.Zero);

					if (hRemoteThread == IntPtr.Zero)
						throw new Exception("DllInjector.CallFunctionThreadProc failed, CreateRemoteThread failed", new Win32Exception());
				}

				if (Win32.WaitForSingleObject(hRemoteThread, Win32.INFINITE) == Win32.WaitForSingleObjectReturn.WAIT_TIMEOUT)
					throw new TimeoutException("DllInjector.CallFunctionThreadProc failed, thread timed out", new Win32Exception());

				uint ExitCode;

				if (Win32.GetExitCodeThread(hRemoteThread, out ExitCode))
					return ExitCode;
				else
					throw new Exception("DllInjector.CallFunctionThreadProc failed, GetExitCodeThread failed", new Win32Exception());
			}
			finally
			{
				if (hRemoteThread != IntPtr.Zero)
					Win32.CloseHandle(hRemoteThread);
			}
		}
	}
}