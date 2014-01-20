using System;
using System.Runtime.InteropServices;

namespace Com.Xenthrax.DllInjector
{
	[AttributeUsage(AttributeTargets.Delegate, AllowMultiple = false, Inherited = false)]
	public sealed class RemoteImportAttribute : Attribute
	{
		public RemoteImportAttribute() { }

		public RemoteImportAttribute(string DllName, string EntryPoint)
		{
			this.DllName = DllName;
			this.EntryPoint = EntryPoint;
		}

		internal string DllName;
		internal string EntryPoint;

		public CallingConvention CallingConvention;
		public CharSet CharSet;
	}
}