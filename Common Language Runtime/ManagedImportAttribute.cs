using System;
using System.Reflection;

namespace Com.Xenthrax.DllInjector
{
	[AttributeUsage(AttributeTargets.Delegate, AllowMultiple = false, Inherited = false)]
	public sealed class ManagedImportAttribute : Attribute
	{
		public ManagedImportAttribute(Delegate Function) : this(Function.Method.DeclaringType, Function.Method.Name) { }

		public ManagedImportAttribute(MethodInfo Function) : this(Function.DeclaringType, Function.Name) { }

		public ManagedImportAttribute(Type DeclaringType, string FunctionName)
		{
			if (DeclaringType == null)
				throw new ArgumentNullException("DeclaringType");

			if (string.IsNullOrEmpty(FunctionName))
				throw new ArgumentNullException("FunctionName");

			LoadAssemblySerializationBinder.Default.BindToName(DeclaringType, out this.AssemblyPath, out this.DeclaringType);

			this.AssemblyPath = this.AssemblyPath ?? DeclaringType.Assembly.FullName;
			this.DeclaringType = this.DeclaringType ?? DeclaringType.FullName;
			this.FunctionName = FunctionName;
		}

		public ManagedImportAttribute(string AssemblyPath, string DeclaringType, string FunctionName)
		{
			if (string.IsNullOrEmpty(AssemblyPath))
				throw new ArgumentNullException("AssemblyPath");

			if (string.IsNullOrEmpty(DeclaringType))
				throw new ArgumentNullException("DeclaringType");

			if (string.IsNullOrEmpty(FunctionName))
				throw new ArgumentNullException("FunctionName");

			this.AssemblyPath = AssemblyPath;
			this.DeclaringType = DeclaringType;
			this.FunctionName = FunctionName;
		}

		internal string AssemblyPath;
		internal string DeclaringType;
		internal string FunctionName;
	}
}