using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters;
using System.Runtime.Serialization.Formatters.Binary;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		[Serializable]
		private sealed class CLRCallFunctionParam
		{
			public string Assembly;
			public string DeclaringType;
			public string Function;
			public string[] ParamaterAssemblies;
			public string[] ParamaterDeclaringTypes;
			public object[] Paramaters;
			public object ReturnValue;
			public Exception Exception;
		}

		private static readonly BinaryFormatter __CLR_SERIALIZER__ = new BinaryFormatter(null, new StreamingContext(StreamingContextStates.CrossAppDomain | StreamingContextStates.CrossProcess))
		{
			AssemblyFormat = FormatterAssemblyStyle.Full,
			Binder = new LoadAssemblySerializationBinder(),
			FilterLevel = TypeFilterLevel.Full,
			TypeFormat = FormatterTypeStyle.TypesAlways
		};

		private static int __CLR_CALLFUNCTION__(string pwzArgument)
		{
			IntPtr ParamaterPtr = new IntPtr(Convert.ToInt64(pwzArgument, 16));

			using (DllInjector Injector = DllInjector.GetCurrentProcess())
			{
				Injector.AcquireProcessHandle();

				CLRCallFunctionParam P = new CLRCallFunctionParam();

				try
				{
					byte[] Bytes = Injector.ReadPrefixedBytes(Injector.ReadIntPtr(ParamaterPtr));

					using (MemoryStream MS = new MemoryStream(Bytes))
						P = (CLRCallFunctionParam)__CLR_SERIALIZER__.Deserialize(MS);

					Type[] ParamaterTypes = new Type[P.ParamaterAssemblies.Length];

					for (int i = 0; i < ParamaterTypes.Length; i++)
						ParamaterTypes[i] = LoadAssemblySerializationBinder.Default.BindToType(P.ParamaterAssemblies[i], P.ParamaterDeclaringTypes[i]);

					P.ReturnValue = LoadAssemblySerializationBinder
						.Default
						.BindToType(P.Assembly, P.DeclaringType)
						.GetMethod(P.Function,
							BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static,
							null,
							ParamaterTypes,
							null)
						.Invoke(null, P.Paramaters);
				}
				catch (Exception ex)
				{
					P.Exception = ex;
				}

				using (MemoryStream MS = new MemoryStream())
				{
					__CLR_SERIALIZER__.Serialize(MS, P);
					Injector.WriteIntPtr(ParamaterPtr, Injector.WritePrefixedBytes(MS.ToArray()));
				}
			}

			return (int)Win32.ERROR_SUCCESS;
		}

		public object CallManagedFunction(Delegate Function, params object[] Paramaters)
		{
			if (Function == null)
				throw new ArgumentNullException("Function");

			return this.CallManagedFunction(Function.Method, Paramaters);
		}

		public object CallManagedFunction(MethodInfo Function, params object[] Paramaters)
		{
			if (Function == null)
				throw new ArgumentNullException("Function");

			string Assembly;
			string DeclaringTypeName;
			LoadAssemblySerializationBinder.Default.BindToName(Function.DeclaringType, out Assembly, out DeclaringTypeName);

			return this.CallManagedFunction(
				Assembly ?? Function.DeclaringType.Assembly.FullName,
				DeclaringTypeName ?? Function.DeclaringType.FullName,
				Function.Name,
				Paramaters,
				Function.GetParameters().Select(param => param.ParameterType).ToArray());
		}

		public object CallManagedFunction(Type DeclaringType, string FunctionName, params object[] Paramaters)
		{
			if (DeclaringType == null)
				throw new ArgumentNullException("DeclaringType");

			string Assembly;
			string DeclaringTypeName;
			LoadAssemblySerializationBinder.Default.BindToName(DeclaringType, out Assembly, out DeclaringTypeName);

			return this.CallManagedFunction(
				Assembly ?? DeclaringType.Assembly.FullName,
				DeclaringTypeName ?? DeclaringType.FullName,
				FunctionName,
				Paramaters,
				null);
		}

		public object CallManagedFunction(string AssemblyPath, string DeclaringType, string FunctionName, params object[] Paramaters)
		{
			return this.CallManagedFunction(AssemblyPath, DeclaringType, FunctionName, Paramaters, null);
		}

		private object CallManagedFunction(string AssemblyPath, string DeclaringType, string FunctionName, object[] Paramaters, Type[] ParamaterTypes)
		{
			if (string.IsNullOrEmpty(AssemblyPath))
				throw new ArgumentNullException("AssemblyPath");

			if (string.IsNullOrEmpty(DeclaringType))
				throw new ArgumentNullException("DeclaringType");

			if (string.IsNullOrEmpty(FunctionName))
				throw new ArgumentNullException("FunctionName");
			
			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();
			this.ThrowIfNoCLR();

			if (Paramaters == null)
				Paramaters = new object[0];

			if (ParamaterTypes == null)
				ParamaterTypes = Type.GetTypeArray(Paramaters);

			CLRCallFunctionParam P = new CLRCallFunctionParam()
			{
				Assembly = AssemblyPath,
				DeclaringType = DeclaringType,
				Function = FunctionName,
				ParamaterAssemblies = new string[ParamaterTypes.Length],
				ParamaterDeclaringTypes = new string[ParamaterTypes.Length],
				Paramaters = Paramaters
			};

			string ParamaterAssembly;
			string ParamaterDeclaringType;

			for (int i = 0; i < ParamaterTypes.Length; i++)
			{
				LoadAssemblySerializationBinder.Default.BindToName(ParamaterTypes[i], out ParamaterAssembly, out ParamaterDeclaringType);
				P.ParamaterAssemblies[i] = ParamaterAssembly ?? ParamaterTypes[i].Assembly.FullName;
				P.ParamaterDeclaringTypes[i] = ParamaterDeclaringType ?? ParamaterTypes[i].FullName;
			}

			MemoryHandle BytesPtr;

			using (MemoryStream MS = new MemoryStream())
			{
				__CLR_SERIALIZER__.Serialize(MS, P);
				BytesPtr = this.WritePrefixedBytes(MS.ToArray());
			}

			using (BytesPtr)
			using (MemoryHandle ParamaterPtr = this.WriteIntPtr(BytesPtr))
			{
				uint res = (uint)this.CallManagedFunctionThreadProc(__CLR_CALLFUNCTION__, ParamaterPtr.ToString("X16"));

				if (res != Win32.ERROR_SUCCESS)
					throw new Exception(string.Format("__CLR_CALLFUNCTION__ failed, with result {0}", res));
				
				using (MemoryHandle NewBytesPtr = this.ReadMemoryHandle(ParamaterPtr))
				using (MemoryStream MS = new MemoryStream(this.ReadPrefixedBytes(NewBytesPtr)))
					P = (CLRCallFunctionParam)__CLR_SERIALIZER__.Deserialize(MS);
			}

			if (P.Exception != null)
			{
				Utilities.PreserveStackTrace(P.Exception);
				throw P.Exception;
			}

			Array.Copy(P.Paramaters, Paramaters, Paramaters.Length);
			return P.ReturnValue;
		}
	}

	internal sealed class LoadAssemblySerializationBinder : SerializationBinder
	{
		public static readonly LoadAssemblySerializationBinder Default = new LoadAssemblySerializationBinder();

		private static readonly string FrameworkPath = Path.GetDirectoryName(typeof(string).Assembly.Location);

		public override void BindToName(Type serializedType, out string assemblyName, out string typeName)
		{
			if (serializedType.Assembly.Location.StartsWith(FrameworkPath, true, null))
				assemblyName = null;
			else
				assemblyName = serializedType.Assembly.CodeBase;

			typeName = null;
		}

		public override Type BindToType(string assemblyName, string typeName)
		{
			Uri temp;

			if (Uri.TryCreate(assemblyName, UriKind.Absolute, out temp)
				&& temp.Scheme == Uri.UriSchemeFile)
				return Assembly.LoadFrom(assemblyName).GetType(typeName, true, false);
			else
				return Assembly.Load(assemblyName).GetType(typeName, true, false);
		}
	}
}