using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		private ICustomMarshaler CreateCustomMarshaller(MarshalAsAttribute Marshalling)
		{
			Type marshalType = Marshalling.MarshalTypeRef ?? Type.GetType(Marshalling.MarshalType);

			if (marshalType.GetInterface(typeof(ICustomMarshaler).FullName, false) == null)
				throw new NotSupportedException(string.Format("Custom marshaler must implement `{0}`", typeof(ICustomMarshaler)));

			MethodInfo GetInstance = marshalType.GetMethod("GetInstance", BindingFlags.Public | BindingFlags.Static, null, new Type[] { typeof(string), typeof(DllInjector) }, null);

			if (GetInstance == null)
				throw new NotSupportedException("Custom marshaler must implement function `public static ICustomMarshaler GetInstance(string cookie, DllInjector injector)`");

			return (ICustomMarshaler)GetInstance.Invoke(null, new object[] { Marshalling.MarshalCookie, this });
		}

		private static MarshalAsAttribute DefaultMarshalling(Type t)
		{
			if (t == typeof(bool))
				return new MarshalAsAttribute(UnmanagedType.Bool);
			else if (t == typeof(string) || t == typeof(StringBuilder))
				return new MarshalAsAttribute(UnmanagedType.LPTStr);
			else if (t.IsArray)
				return new MarshalAsAttribute(UnmanagedType.LPArray);
			else
				return null;
		}

		private int MarshalSizeOf(object o)
		{
			return this.MarshalSizeOf(o.GetType());
		}

		private int MarshalSizeOf(Type t, MarshalAsAttribute Marshalling = null)
		{
			if (Marshalling == null)
				Marshalling = DefaultMarshalling(t);

			if (Marshalling != null)
			{
				switch (Marshalling.Value)
				{
					default:
					case UnmanagedType.AsAny:
					case UnmanagedType.ByValArray:
					case UnmanagedType.ByValTStr:
					case UnmanagedType.Currency:
					case UnmanagedType.Error:
					case UnmanagedType.FunctionPtr:
					case UnmanagedType.IDispatch:
					case UnmanagedType.Interface:
					case UnmanagedType.IUnknown:
					case UnmanagedType.R4:
					case UnmanagedType.R8:
					case UnmanagedType.SafeArray:
					case UnmanagedType.Struct:
					case UnmanagedType.VBByRefStr:
						throw new NotSupportedException(string.Format("MarshalAs type {0} not supported", Marshalling.Value));

					case UnmanagedType.AnsiBStr:
					case UnmanagedType.BStr:
					case UnmanagedType.CustomMarshaler:
					case UnmanagedType.LPArray:
					case UnmanagedType.LPStruct:
					case UnmanagedType.LPStr:
					case UnmanagedType.LPTStr:
					case UnmanagedType.LPWStr:
					case UnmanagedType.TBStr:
						return this.PointerSize;
					case UnmanagedType.I1:
					case UnmanagedType.U1:
						return sizeof(sbyte);
					case UnmanagedType.I2:
					case UnmanagedType.U2:
					case UnmanagedType.VariantBool:
						return sizeof(short);
					case UnmanagedType.Bool:
					case UnmanagedType.I4:
					case UnmanagedType.U4:
						return sizeof(int);
					case UnmanagedType.I8:
					case UnmanagedType.U8:
						return sizeof(long);
					case UnmanagedType.SysInt:
						if (this.Is64BitProcess)
							return sizeof(long);
						else
							return sizeof(int);

					case UnmanagedType.SysUInt:
						if (this.Is64BitProcess)
							return sizeof(ulong);
						else
							return sizeof(uint);
				}
			}
			else
				return Marshal.SizeOf(t);
		}

		private void MarshalToNative(ref object Paramater, MarshalAsAttribute Marshalling, Type ParamaterType, out ICustomMarshaler CustomMarshaler, CharSet charSet)
		{
			CustomMarshaler = null;

			if (ParamaterType == typeof(SafeHandle) || ParamaterType.IsSubclassOf(typeof(SafeHandle)))
				Paramater = ((SafeHandle)Paramater).Value;

			if (Marshalling == null)
				return;

			switch (Marshalling.Value)
			{
				default:
				case UnmanagedType.AsAny:
				case UnmanagedType.ByValArray:
				case UnmanagedType.ByValTStr:
				case UnmanagedType.Currency:
				case UnmanagedType.Error:
				case UnmanagedType.FunctionPtr:
				case UnmanagedType.IDispatch:
				case UnmanagedType.Interface:
				case UnmanagedType.IUnknown:
				case UnmanagedType.R4:
				case UnmanagedType.R8:
				case UnmanagedType.SafeArray:
				case UnmanagedType.Struct:
				case UnmanagedType.VBByRefStr:
					throw new NotSupportedException(string.Format("MarshalAs type {0} not supported", Marshalling.Value));

				case UnmanagedType.AnsiBStr:
					if (Paramater == null)
						Paramater = IntPtr.Zero;
					else if (ParamaterType == typeof(string))
						Paramater = this.WritePrefixedStringAnsi((string)Paramater);
					else if (ParamaterType == typeof(StringBuilder))
						Paramater = this.WritePrefixedStringAnsi((StringBuilder)Paramater);
					else
						throw new NotSupportedException();

					break;
				case UnmanagedType.Bool:
					Paramater = Convert.ToBoolean(Paramater) ? 1U : 0U;
					break;
				case UnmanagedType.BStr:
					if (Paramater == null)
						Paramater = IntPtr.Zero;
					else if (ParamaterType == typeof(string))
						Paramater = this.WritePrefixedStringUni((string)Paramater);
					else if (ParamaterType == typeof(StringBuilder))
						Paramater = this.WritePrefixedStringUni((StringBuilder)Paramater);
					else
						throw new NotSupportedException();

					break;
				case UnmanagedType.CustomMarshaler:
					CustomMarshaler = this.CreateCustomMarshaller(Marshalling);
					Paramater = CustomMarshaler.MarshalManagedToNative(Paramater);
					break;
				case UnmanagedType.I1:
					Paramater = StructToStruct<sbyte>(Paramater);
					break;
				case UnmanagedType.I2:
					Paramater = StructToStruct<short>(Paramater);
					break;
				case UnmanagedType.I4:
					Paramater = StructToStruct<int>(Paramater);
					break;
				case UnmanagedType.I8:
					Paramater = StructToStruct<long>(Paramater);
					break;
				case UnmanagedType.LPArray:
					Array ArrParam = (Array)Paramater;

					if (ArrParam == null)
						Paramater = IntPtr.Zero;
					else
						Paramater = this.WriteArray(ArrParam);

					break;
				case UnmanagedType.LPStruct:
					Paramater = this.WriteStruct(Paramater);
					break;
				case UnmanagedType.LPStr:
					if (Paramater == null)
						Paramater = IntPtr.Zero;
					else if (ParamaterType == typeof(string))
						Paramater = this.WriteStringAnsi((string)Paramater);
					else if (ParamaterType == typeof(StringBuilder))
						Paramater = this.WriteStringAnsi((StringBuilder)Paramater);
					else
						throw new NotSupportedException();

					break;
				case UnmanagedType.LPTStr:
					if (charSet == CharSet.Ansi || charSet == CharSet.None)
						goto case UnmanagedType.LPStr;
					else if (charSet == CharSet.Auto || charSet == CharSet.Unicode)
						goto case UnmanagedType.LPWStr;
					else
						throw new NotSupportedException();
				case UnmanagedType.LPWStr:
					if (Paramater == null)
						Paramater = IntPtr.Zero;
					else if (ParamaterType == typeof(string))
						Paramater = this.WriteStringUni((string)Paramater);
					else if (ParamaterType == typeof(StringBuilder))
						Paramater = this.WriteStringUni((StringBuilder)Paramater);
					else
						throw new NotSupportedException();

					break;
				case UnmanagedType.SysInt:
					if (this.Is64BitProcess)
						Paramater = StructToStruct<long>(Paramater);
					else
						Paramater = StructToStruct<int>(Paramater);

					break;
				case UnmanagedType.SysUInt:
					if (this.Is64BitProcess)
						Paramater = StructToStruct<ulong>(Paramater);
					else
						Paramater = StructToStruct<uint>(Paramater);

					break;
				case UnmanagedType.TBStr:
					if (charSet == CharSet.Ansi || charSet == CharSet.None)
						goto case UnmanagedType.AnsiBStr;
					else if (charSet == CharSet.Auto || charSet == CharSet.Unicode)
						goto case UnmanagedType.BStr;
					else
						throw new NotSupportedException();
				case UnmanagedType.U1:
					Paramater = StructToStruct<byte>(Paramater);
					break;
				case UnmanagedType.U2:
					Paramater = StructToStruct<ushort>(Paramater);
					break;
				case UnmanagedType.U4:
					Paramater = StructToStruct<uint>(Paramater);
					break;
				case UnmanagedType.U8:
					Paramater = StructToStruct<ulong>(Paramater);
					break;
				case UnmanagedType.VariantBool:
					Paramater = (short)(Convert.ToBoolean(Paramater) ? -1 : 0);
					break;
			}

			if (Paramater is SafeHandle)
				Paramater = ((SafeHandle)Paramater).Value;
		}

		private void MarshalToManaged(ref object Paramater, object OrigParmater, IntPtr PtrParamater, MarshalAsAttribute Marshalling, Type ParamaterType, ICustomMarshaler CustomMarshaler, CharSet charSet, bool IsByRef)
		{
			if (Marshalling == null)
				return;

			switch (Marshalling.Value)
			{
				case UnmanagedType.AnsiBStr:
					try
					{
						if (ParamaterType == typeof(StringBuilder))
						{
							StringBuilder StrParam = (StringBuilder)OrigParmater;

							if (IsByRef && StrParam == null)
								Paramater = StrParam = new StringBuilder();

							if (StrParam == null)
								break;

							if (PtrParamater == IntPtr.Zero)
								StrParam.Clear();
							else
								this.ReadPrefixedStringAnsi(PtrParamater, StrParam);
						}
						else if (IsByRef && ParamaterType == typeof(string))
						{
							if (PtrParamater == IntPtr.Zero)
								Paramater = null;
							else
								Paramater = this.ReadPrefixedStringAnsi(PtrParamater);
						}
					}
					finally
					{
						if (PtrParamater != IntPtr.Zero)
							this.FreeMemory(PtrParamater);
					}
					break;
				case UnmanagedType.Bool:
					if (IsByRef)
						Paramater = Convert.ToUInt32(Paramater) != 0U;

					break;
				case UnmanagedType.BStr:
					try
					{
						if (ParamaterType == typeof(StringBuilder))
						{
							StringBuilder StrParam = (StringBuilder)OrigParmater;

							if (IsByRef && StrParam == null)
								Paramater = StrParam = new StringBuilder();

							if (StrParam == null)
								break;

							if (PtrParamater == IntPtr.Zero)
								StrParam.Clear();
							else
								this.ReadPrefixedStringUni(PtrParamater, StrParam);
						}
						else if (IsByRef && ParamaterType == typeof(string))
						{
							if (PtrParamater == IntPtr.Zero)
								Paramater = null;
							else
								Paramater = this.ReadPrefixedStringUni(PtrParamater);
						}
					}
					finally
					{
						if (PtrParamater != IntPtr.Zero)
							this.FreeMemory(PtrParamater);
					}
					break;
				case UnmanagedType.CustomMarshaler:
					if (CustomMarshaler == null)
						CustomMarshaler = this.CreateCustomMarshaller(Marshalling);

					try
					{
						if (IsByRef)
							Paramater = CustomMarshaler.MarshalNativeToManaged(PtrParamater);
					}
					finally
					{
						CustomMarshaler.CleanUpNativeData(PtrParamater);
					}
					break;
				case UnmanagedType.I1:
				case UnmanagedType.I2:
				case UnmanagedType.I4:
				case UnmanagedType.I8:
				case UnmanagedType.SysInt:
				case UnmanagedType.SysUInt:
				case UnmanagedType.U1:
				case UnmanagedType.U2:
				case UnmanagedType.U4:
				case UnmanagedType.U8:
					if (IsByRef)
						Paramater = StructToStruct(Paramater, ParamaterType);

					break;
				case UnmanagedType.LPArray:
					try
					{
						if (PtrParamater == IntPtr.Zero)
							Paramater = null;
						else
						{
							Type ArrElementType = ParamaterType.GetElementType();
							Array ArrParam;
							int ArrLength = 0;

							if (IsByRef)
							{
								ArrLength = Marshalling.SizeConst;
								Paramater = ArrParam = Array.CreateInstance(ArrElementType, ArrLength);
							}
							else
							{
								ArrParam = (Array)OrigParmater;

								if (ArrParam != null)
									ArrLength = ArrParam.Length;
							}

							if (ArrLength > 0)
							{
								int bSize = ArrLength * Marshal.SizeOf(ArrElementType);
								Buffer.BlockCopy(this.ReadBytes(PtrParamater, bSize), 0, ArrParam, 0, bSize);
							}
						}
					}
					finally
					{
						if (PtrParamater != IntPtr.Zero)
							this.FreeMemory(PtrParamater);
					}
					break;
				case UnmanagedType.LPStruct:
					try
					{
						if (IsByRef && PtrParamater != IntPtr.Zero)
							Paramater = this.ReadStruct(PtrParamater, ParamaterType);
					}
					finally
					{
						if (PtrParamater != IntPtr.Zero)
							this.FreeMemory(PtrParamater);
					}
					break;
				case UnmanagedType.LPStr:
					try
					{
						if (ParamaterType == typeof(StringBuilder))
						{
							StringBuilder StrParam = (StringBuilder)OrigParmater;

							if (IsByRef && StrParam == null)
								Paramater = StrParam = new StringBuilder();

							if (StrParam == null)
								break;

							if (PtrParamater == IntPtr.Zero)
								StrParam.Clear();
							else
								this.ReadStringAnsi(PtrParamater, StrParam);
						}
						else if (IsByRef && ParamaterType == typeof(string))
						{
							if (PtrParamater == IntPtr.Zero)
								Paramater = null;
							else
								Paramater = this.ReadStringAnsi(PtrParamater);
						}
					}
					finally
					{
						if (PtrParamater != IntPtr.Zero)
							this.FreeMemory(PtrParamater);
					}
					break;
				case UnmanagedType.LPTStr:
					if (charSet == CharSet.Ansi || charSet == CharSet.None)
						goto case UnmanagedType.LPStr;
					else if (charSet == CharSet.Auto || charSet == CharSet.Unicode)
						goto case UnmanagedType.LPWStr;
					else
						throw new NotSupportedException();
				case UnmanagedType.LPWStr:
					try
					{
						if (ParamaterType == typeof(StringBuilder))
						{
							StringBuilder StrParam = (StringBuilder)OrigParmater;

							if (IsByRef && StrParam == null)
								Paramater = StrParam = new StringBuilder();

							if (StrParam == null)
								break;

							if (PtrParamater == IntPtr.Zero)
								StrParam.Clear();
							else
								this.ReadStringUni(PtrParamater, StrParam);
						}
						else if (IsByRef && ParamaterType == typeof(string))
						{
							if (PtrParamater == IntPtr.Zero)
								Paramater = null;
							else
								Paramater = this.ReadStringUni(PtrParamater);
						}
					}
					finally
					{
						if (PtrParamater != IntPtr.Zero)
							this.FreeMemory(PtrParamater);
					}
					break;
				case UnmanagedType.TBStr:
					if (charSet == CharSet.Ansi || charSet == CharSet.None)
						goto case UnmanagedType.AnsiBStr;
					else if (charSet == CharSet.Auto || charSet == CharSet.Unicode)
						goto case UnmanagedType.BStr;
					else
						throw new NotSupportedException();
				case UnmanagedType.VariantBool:
					if (IsByRef)
						Paramater = Convert.ToInt16(Paramater) == -1;

					break;
			}
		}
	}
}