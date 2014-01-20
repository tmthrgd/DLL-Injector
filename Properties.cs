using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		#region Members
		private bool Disposed = false;

		private bool _FreeOnDispose;
		private Process _Process;
		private bool? _Is64BitProcess;
		private bool? _IsWow64Process;
		#endregion

		#region Properties
		public bool FreeOnDispose
		{
			get
			{
				this.ThrowIfDisposed();
				return this._FreeOnDispose;
			}
			private set
			{
				this._FreeOnDispose = value;
			}
		}

		public Process Process
		{
			get
			{
				this.ThrowIfDisposed();
				return this._Process;
			}
			private set
			{
				this._Process = value;
			}
		}

		public bool Is64BitProcess
		{
			get
			{
				this.ThrowIfDisposed();

				if (!this._Is64BitProcess.HasValue)
					this._Is64BitProcess = Utilities.Is64BitProcess(this.Process);

				return this._Is64BitProcess.Value;
			}
		}

		public bool IsWow64Process
		{
			get
			{
				this.ThrowIfDisposed();

				if (!this._IsWow64Process.HasValue)
					this._IsWow64Process = Utilities.IsWow64Process(this.Process);

				return this._IsWow64Process.Value;
			}
		}

		public int PointerSize
		{
			get
			{
				this.ThrowIfDisposed();
				return this.Is64BitProcess ? 8 : 4;
			}
		}

		public bool HasProcessHandle
		{
			get
			{
				this.ThrowIfDisposed();
				return this.hProc != IntPtr.Zero;
			}
		}

		public bool HasCommonLanguageRuntime
		{
			get
			{
				this.ThrowIfDisposed();
				return this.Clr != null && this.Clr.ppClrHost != IntPtr.Zero;
			}
		}
		#endregion
	}
}