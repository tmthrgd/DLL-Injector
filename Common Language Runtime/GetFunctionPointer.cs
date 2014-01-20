using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		[ManagedImport(typeof(DllInjector), "__CLR_GETFUNCTIONPOINTER__")]
		private delegate IntPtr __CLR_GETFUNCTIONPOINTER__Prototype(string AssemblyPath, string DeclaringType, string FunctionName, string DelegateAssemblyPath, string DelegateTypeName);

		private __CLR_GETFUNCTIONPOINTER__Prototype ClrGetFunctionPointer;

		public /*private*/ static IntPtr __CLR_GETFUNCTIONPOINTER__(string AssemblyPath, string DeclaringType, string FunctionName, string DelegateAssemblyPath, string DelegateTypeName)
		{
			var a = LoadAssemblySerializationBinder
					.Default
					.BindToType(DelegateAssemblyPath, DelegateTypeName);
			var b = LoadAssemblySerializationBinder
					.Default
					.BindToType(AssemblyPath, DeclaringType);
			var c = Delegate.CreateDelegate(a, b, FunctionName);
			var d = Marshal.GetFunctionPointerForDelegate(c);
			return d;

			return Marshal.GetFunctionPointerForDelegate(Delegate.CreateDelegate(
				LoadAssemblySerializationBinder
					.Default
					.BindToType(DelegateAssemblyPath, DelegateTypeName),
				LoadAssemblySerializationBinder
					.Default
					.BindToType(AssemblyPath, DeclaringType),
				FunctionName));
		}

		public IntPtr GetFunctionPointer(Delegate Function, Type DelegateType)
		{
			if (Function == null)
				throw new ArgumentNullException("Function");

			if (DelegateType == null)
				throw new ArgumentNullException("DelegateType");

			return this.GetFunctionPointer(Function.Method.DeclaringType, Function.Method.Name, DelegateType);
		}

		public IntPtr GetFunctionPointer(MethodInfo Function, Type DelegateType)
		{
			if (Function == null)
				throw new ArgumentNullException("Function");

			if (DelegateType == null)
				throw new ArgumentNullException("DelegateType");

			return this.GetFunctionPointer(Function.DeclaringType, Function.Name, DelegateType);
		}

		public IntPtr GetFunctionPointer(Type DeclaringType, string FunctionName, Type DelegateType)
		{
			if (DeclaringType == null)
				throw new ArgumentNullException("DeclaringType");

			if (string.IsNullOrEmpty(FunctionName))
				throw new ArgumentNullException("FunctionName");

			if (DelegateType == null)
				throw new ArgumentNullException("DelegateType");
			
			string AssemblyName;
			string TypeName;
			LoadAssemblySerializationBinder.Default.BindToName(DeclaringType, out AssemblyName, out TypeName);

			return this.GetFunctionPointer(
				AssemblyName ?? DeclaringType.Assembly.FullName,
				TypeName ?? DeclaringType.FullName,
				FunctionName,
				DelegateType);
		}

		public IntPtr GetFunctionPointer(string AssemblyPath, string DeclaringType, string FunctionName, Type DelegateType)
		{
			if (string.IsNullOrEmpty(AssemblyPath))
				throw new ArgumentNullException("AssemblyPath");

			if (string.IsNullOrEmpty(DeclaringType))
				throw new ArgumentNullException("DeclaringType");

			if (string.IsNullOrEmpty(FunctionName))
				throw new ArgumentNullException("FunctionName");

			if (DelegateType == null)
				throw new ArgumentNullException("DelegateType");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();
			this.ThrowIfNoCLR();

			if (this.ClrGetFunctionPointer == null)
				this.ClrGetFunctionPointer = this.GetManagedFunction<__CLR_GETFUNCTIONPOINTER__Prototype>();

			string DelegateAssemblyName;
			string DelegateTypeName;
			LoadAssemblySerializationBinder.Default.BindToName(DelegateType, out DelegateAssemblyName, out DelegateTypeName);

			return this.ClrGetFunctionPointer(
				AssemblyPath,
				DeclaringType,
				FunctionName,

				DelegateAssemblyName ?? DelegateType.Assembly.FullName,
				DelegateTypeName ?? DelegateType.FullName);
		}
	}
}