using System;
using System.Runtime.Remoting.Metadata.W3cXsd2001;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		// ml.exe /c /FoCallFunctionx86.obj /Zf CallFunctionx86.asm --- 8C - C2
		private static readonly byte[] NativeCallFunctionx86 = SoapHexBinary.Parse("55 56 89 65 FC 8B 75 08 8B 46 28 83 F8 00 74 0D 03 46 30 83 E8 08 FF 30 3B 46 28 77 F6 33 C0 8B 4E 08 8B 56 10 FF 16 89 56 3C 89 46 38 8B 65 FC 5E 5D 33 C0 C2 04 00").Value;
		// ml64.exe /c /FoCallFunctionx64.obj /Zf CallFunctionx64.asm --- 8C - DC
		private static readonly byte[] NativeCallFunctionx64 = SoapHexBinary.Parse("41 57 41 56 4C 8B FC 4C 8B F1 48 83 EC 08 49 8B 46 28 48 83 F8 00 74 10 49 03 46 30 48 83 E8 08 FF 30 49 3B 46 28 77 F4 48 83 EC 20 48 33 C0 49 8B 4E 08 49 8B 56 10 4D 8B 46 18 4D 8B 4E 20 41 FF 16 49 89 46 38 49 8B E7 41 5E 41 5F 48 33 C0 C3").Value;

		private MemoryHandle _NativeCallFunction;

		private IntPtr NativeCallFunction
		{
			get
			{
				this.ThrowIfDisposed();

				if (this._NativeCallFunction == null || this._NativeCallFunction.Disposed)
					this._NativeCallFunction = this.WriteMachineCode(NativeCallFunctionx86, NativeCallFunctionx64);

				return this._NativeCallFunction;
			}
		}

		private void FreeNativeCallFunction()
		{
			if (this._NativeCallFunction != null)
				this._NativeCallFunction.Dispose();
		}
	}
}