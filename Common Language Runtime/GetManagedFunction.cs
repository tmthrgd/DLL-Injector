using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		#region GetManagedFunction<T>
		public T GetManagedFunction<T>()
			where T : class
		{
			return (T)(object)this.GetManagedFunction(typeof(T));
		}

		public T GetManagedFunction<T>(Delegate Function)
			where T : class
		{
			if (Function == null)
				throw new ArgumentNullException("Function");

			return this.GetManagedFunction<T>(Function.Method.DeclaringType, Function.Method.Name);
		}

		public T GetManagedFunction<T>(MethodInfo Function)
			where T : class
		{
			if (Function == null)
				throw new ArgumentNullException("Function");

			return this.GetManagedFunction<T>(Function.DeclaringType, Function.Name);
		}

		public T GetManagedFunction<T>(Type DeclaringType, string FunctionName)
			where T : class
		{
			return (T)(object)this.GetManagedFunction(DeclaringType, FunctionName, typeof(T));
		}

		public T GetManagedFunction<T>(string AssemblyPath, string DeclaringType, string FunctionName)
			where T : class
		{
			return (T)(object)this.GetManagedFunction(AssemblyPath, DeclaringType, FunctionName, typeof(T));
		}
		#endregion

		#region GetManagedFunction
		public Delegate GetManagedFunction(Type DelegateType)
		{
			ManagedImportAttribute ManagedImport = (ManagedImportAttribute)DelegateType
				.GetCustomAttributes(typeof(ManagedImportAttribute), false)
				.FirstOrDefault();

			if (ManagedImport == null)
				throw new ArgumentException(string.Format("Type `{0}` must have ManagedImportAttribute", DelegateType));

			return this.GetManagedFunction(ManagedImport.AssemblyPath, ManagedImport.DeclaringType, ManagedImport.FunctionName, DelegateType);
		}

		public Delegate GetManagedFunction(Delegate Function, Type DelegateType)
		{
			if (Function == null)
				throw new ArgumentNullException("Function");

			return this.GetManagedFunction(Function.Method.DeclaringType, Function.Method.Name, DelegateType);
		}

		public Delegate GetManagedFunction(MethodInfo Function, Type DelegateType)
		{
			if (Function == null)
				throw new ArgumentNullException("Function");

			return this.GetManagedFunction(Function.DeclaringType, Function.Name, DelegateType);
		}

		public Delegate GetManagedFunction(Type DeclaringType, string FunctionName, Type DelegateType)
		{
			if (DeclaringType == null)
				throw new ArgumentNullException("DeclaringType");

			if (string.IsNullOrEmpty(FunctionName))
				throw new ArgumentNullException("FunctionName");

			string Assembly;
			string DeclaringTypeName;
			LoadAssemblySerializationBinder.Default.BindToName(DeclaringType, out Assembly, out DeclaringTypeName);

			return this.GetManagedFunction(
				Assembly ?? DeclaringType.Assembly.FullName,
				DeclaringTypeName ?? DeclaringType.FullName,
				FunctionName,
				DelegateType);
		}

		public Delegate GetManagedFunction(string AssemblyPath, string DeclaringType, string FunctionName, Type DelegateType)
		{
			if (string.IsNullOrEmpty(AssemblyPath))
				throw new ArgumentNullException("AssemblyPath");

			if (string.IsNullOrEmpty(DeclaringType))
				throw new ArgumentNullException("DeclaringType");

			if (string.IsNullOrEmpty(FunctionName))
				throw new ArgumentNullException("FunctionName");

			if (!DelegateType.IsSubclassOf(typeof(Delegate)))
				throw new ArgumentException("DelegateType must be typeof Delegate");

			MethodInfo DelegateInvoke = DelegateType.GetMethod("Invoke");

			ParameterInfo[] Paramaters = DelegateInvoke.GetParameters();

			Type[] ParamaterTypes = Paramaters
				.Select(param => param.ParameterType.IsByRef
					? param.ParameterType.GetElementType()
					: param.ParameterType)
				.ToArray();

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
				.GetMethod("CallManagedFunction", BindingFlags.Instance | BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Public, null, new Type[]
				{
					typeof(string),
					typeof(string),
					typeof(string),
					typeof(object[]),
					typeof(Type[])
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
							Expression.Constant(AssemblyPath),
							Expression.Constant(DeclaringType),
							Expression.Constant(FunctionName),
							ParamaterArray,
							Expression.Constant(ParamaterTypes))));

				for (int i = 0; i < ExpressionParamaters.Length; i++)
					if (ExpressionParamaters[i].IsByRef)
						BodyBlock.Add(Expression.Assign(
							ExpressionParamaters[i],
							Expression.Convert(
								Expression.ArrayAccess(ParamsVar, Expression.Constant(i)),
								ExpressionParamaters[i].Type)
							));

				if (DelegateInvoke.ReturnType != typeof(void))
					BodyBlock.Add(Expression.Convert(RetVar, DelegateInvoke.ReturnType));

				Body = Expression.Block(new ParameterExpression[] { ParamsVar, RetVar }, BodyBlock);
			}
			else
			{
				Body = Expression.Call(
					Expression.Constant(this),
					CallFunction,
					/* Params */
					Expression.Constant(AssemblyPath),
					Expression.Constant(DeclaringType),
					Expression.Constant(FunctionName),
					ParamaterArray,
					Expression.Constant(ParamaterTypes));

				if (DelegateInvoke.ReturnType != typeof(void))
					Body = Expression.Convert(Body, DelegateInvoke.ReturnType);
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