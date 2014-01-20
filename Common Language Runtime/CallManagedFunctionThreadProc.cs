using System;
using System.ComponentModel;
using System.Reflection;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		public int CallManagedFunctionThreadProc(Func<string, int> Function, string Paramater)
		{
			if (Function == null)
				throw new ArgumentNullException("Function");

			return this.CallManagedFunctionThreadProc(Function.Method.DeclaringType, Function.Method.Name, Paramater);
		}

		public int CallManagedFunctionThreadProc(MethodInfo Function, string Paramater)
		{
			if (Function == null)
				throw new ArgumentNullException("Function");

			return this.CallManagedFunctionThreadProc(Function.DeclaringType, Function.Name, Paramater);
		}

		public int CallManagedFunctionThreadProc(Type DeclaringType, string FunctionName, string Paramater)
		{
			if (DeclaringType == null)
				throw new ArgumentNullException("DeclaringType");

			string Assembly;
			string DeclaringTypeName;
			LoadAssemblySerializationBinder.Default.BindToName(DeclaringType, out Assembly, out DeclaringTypeName);

			return this.CallManagedFunctionThreadProc(
				Assembly ?? DeclaringType.Assembly.FullName,
				DeclaringTypeName ?? DeclaringType.FullName,
				FunctionName,
				Paramater);
		}

		public int CallManagedFunctionThreadProc(string AssemblyPath, string TypeName, string FunctionName, string Paramater)
		{
			if (string.IsNullOrEmpty(AssemblyPath))
				throw new ArgumentNullException("AssemblyPath");

			if (string.IsNullOrEmpty(TypeName))
				throw new ArgumentNullException("TypeName");

			if (string.IsNullOrEmpty(FunctionName))
				throw new ArgumentNullException("FunctionName");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();
			this.ThrowIfNoCLR();

			int ReturnValue;
			uint status = this.Clr.ExecuteInDefaultAppDomain(this.Clr.ppClrHost, AssemblyPath, TypeName, FunctionName, Paramater, out ReturnValue);

			if (status != Win32.ERROR_SUCCESS)
				throw new Win32Exception((int)status);

			return ReturnValue;
		}
	}
}