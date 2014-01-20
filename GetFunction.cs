using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		#region GetFunction<T>
		public T GetFunction<T>(bool LoadLibrary = false)
			where T : class
		{
			return (T)(object)this.GetFunction(typeof(T), LoadLibrary);
		}

		public T GetFunction<T>(IntPtr Function)
			where T : class
		{
			return (T)(object)this.GetFunction(Function, typeof(T));
		}
		#endregion

		#region GetFunction
		public Delegate GetFunction(Type DelegateType, bool LoadLibrary = false)
		{
			RemoteImportAttribute RemoteImport = (RemoteImportAttribute)DelegateType
				.GetCustomAttributes(typeof(RemoteImportAttribute), false)
				.FirstOrDefault();

			if (RemoteImport == null)
				throw new ArgumentException(string.Format("Type `{0}` must have RemoteImportAttribute", DelegateType));

			if (string.IsNullOrEmpty(RemoteImport.DllName))
				throw new ArgumentException("RemoteImportAttribute.DllName must be set to call this method");

			if (string.IsNullOrEmpty(RemoteImport.EntryPoint))
				throw new ArgumentException("RemoteImportAttribute.EntryPoint must be set to call this method");

			IntPtr FunctionPtr = this.GetProcAddress(RemoteImport.DllName, RemoteImport.EntryPoint, LoadLibrary);
			return this.GetFunction(FunctionPtr, DelegateType);
		}

		public Delegate GetFunction(IntPtr Function, Type DelegateType)
		{
			if (!DelegateType.IsSubclassOf(typeof(Delegate)))
				throw new ArgumentException("DelegateType must be typeof Delegate");

			RemoteImportAttribute RemoteImport = (RemoteImportAttribute)DelegateType
				.GetCustomAttributes(typeof(RemoteImportAttribute), false)
				.FirstOrDefault();

			string FunctionName;
			CallingConvention callingConvention;
			CharSet charSet;

			if (RemoteImport == null)
			{
				FunctionName = DelegateType.Name;
				callingConvention = CallingConvention.Winapi;
				charSet = CharSet.Ansi;
			}
			else
			{
				FunctionName = RemoteImport.EntryPoint ?? DelegateType.Name;
				callingConvention = (RemoteImport.CallingConvention == 0)
					? CallingConvention.Winapi
					: RemoteImport.CallingConvention;
				charSet = (RemoteImport.CharSet == 0)
					? CharSet.Ansi
					: RemoteImport.CharSet;
			}

			MethodInfo DelegateInvoke = DelegateType.GetMethod("Invoke");

			ParameterInfo[] Paramaters = DelegateInvoke.GetParameters();

			Type[] ParamaterTypes = Paramaters
				.Select(param => param.ParameterType.IsByRef
					? param.ParameterType.GetElementType()
					: param.ParameterType)
				.ToArray();

			MarshalAsAttribute[] MarshalAsAttributes = Paramaters
				.Select(param => (MarshalAsAttribute)param
					.GetCustomAttributes(typeof(MarshalAsAttribute), false)
					.FirstOrDefault())
				.ToArray();

			MarshalAsAttribute ReturnMarshalAs = (MarshalAsAttribute)DelegateInvoke.ReturnParameter.GetCustomAttributes(typeof(MarshalAsAttribute), false).FirstOrDefault();

			if (ReturnMarshalAs == null)
				ReturnMarshalAs = DefaultMarshalling(DelegateInvoke.ReturnType);

			ParameterExpression[] ExpressionParamaters = Paramaters
				.Select(param => Expression.Parameter(param.ParameterType, param.Name))
				.ToArray();

			bool[] IsByRef = ExpressionParamaters
				.Select(param => param.IsByRef)
				.ToArray();

			bool HasByRef = IsByRef.FirstOrDefault(byref => byref);

			Expression ParamaterArray = Expression.NewArrayInit(
				typeof(object),
				ExpressionParamaters.Select(param => Expression.Convert(param, typeof(object))));

			MethodInfo CallFunction = this.GetType()
				.GetMethod("CallFunction", BindingFlags.Instance | BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Public, null, new Type[]
				{
					typeof(IntPtr),
					typeof(CallingConvention),
					typeof(CharSet),
					typeof(object[]),
					typeof(Type[]),
					typeof(MarshalAsAttribute[]),
					typeof(bool[]),
					typeof(Type),
					typeof(MarshalAsAttribute)
				}, null);

			Expression Body;

			if (HasByRef)
			{
				ParameterExpression ParamsVar = Expression.Variable(typeof(object[]), "params");
				ParameterExpression RetVar = Expression.Variable(typeof(object), "ret");

				List<Expression> BodyBlock = new List<Expression>(3 + ExpressionParamaters.Length);
				BodyBlock.Add(Expression.Assign(ParamsVar, ParamaterArray));
				BodyBlock.Add(
					Expression.Assign(RetVar,
						Expression.Call(
							Expression.Constant(this),
							CallFunction,
							/* Params */
							Expression.Constant(Function),
							Expression.Constant(callingConvention),
							Expression.Constant(charSet),
							ParamsVar,
							Expression.Constant(ParamaterTypes),
							Expression.Constant(MarshalAsAttributes),
							Expression.Constant(IsByRef),
							Expression.Constant(DelegateInvoke.ReturnType),
							Expression.Constant(ReturnMarshalAs, typeof(MarshalAsAttribute)))));

				for (int i = 0; i < ExpressionParamaters.Length; i++)
					if (ExpressionParamaters[i].IsByRef)
						BodyBlock.Add(Expression.Assign(
							ExpressionParamaters[i],
							Expression.Convert(
								Expression.ArrayAccess(ParamsVar, Expression.Constant(i)),
								ExpressionParamaters[i].Type)
							));

				BodyBlock.Add(Expression.Convert(RetVar, DelegateInvoke.ReturnType));
				Body = Expression.Block(new ParameterExpression[] { ParamsVar, RetVar }, BodyBlock);
			}
			else
			{
				Body = Expression.Convert(
					Expression.Call(
						Expression.Constant(this),
						CallFunction,
						/* Params */
						Expression.Constant(Function),
						Expression.Constant(callingConvention),
						Expression.Constant(charSet),
						ParamaterArray,
						Expression.Constant(ParamaterTypes),
						Expression.Constant(MarshalAsAttributes),
						Expression.Constant(IsByRef),
						Expression.Constant(DelegateInvoke.ReturnType),
						Expression.Constant(ReturnMarshalAs, typeof(MarshalAsAttribute))),
					DelegateInvoke.ReturnType);
			}
			
			LambdaExpression Lambda = Expression.Lambda(
				DelegateType,
				Body,
				FunctionName,
				ExpressionParamaters);

			return Lambda.Compile();
		}
		#endregion
	}
}