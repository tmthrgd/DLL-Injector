using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		[StructLayout(LayoutKind.Explicit)]
		private struct FunctionReturnx86 : FunctionReturn
		{
			public const int EAXOffset = 0;
			public const int EDXOffset = 4;

			[FieldOffset(EAXOffset)]
			public uint EAX;
			[FieldOffset(EDXOffset)]
			public uint EDX;

			[FieldOffset(EAXOffset)]
			private sbyte _Int8;
			[FieldOffset(EAXOffset)]
			private byte _UInt8;

			[FieldOffset(EAXOffset)]
			private short _Int16;
			[FieldOffset(EAXOffset)]
			private ushort _UInt16;

			[FieldOffset(EAXOffset)]
			private int _Int32;
			[FieldOffset(EAXOffset)]
			private uint _UInt32;

			[FieldOffset(EAXOffset)]
			private long _Int64;
			[FieldOffset(EAXOffset)]
			private ulong _UInt64;

			public sbyte Int8 { get { return this._Int8; } }
			public byte UInt8 { get { return this._UInt8; } }
			public short Int16 { get { return this._Int16; } }
			public ushort UInt16 { get { return this._UInt16; } }
			public int Int32 { get { return this._Int32; } }
			public uint UInt32 { get { return this._UInt32; } }
			public long Int64 { get { return this._Int64; } }
			public ulong UInt64 { get { return this._UInt64; } }
			public IntPtr IntPtr { get { return (IntPtr)this._Int32; } }
			public UIntPtr UIntPtr { get { return (UIntPtr)this._UInt32; } }
		}

		[StructLayout(LayoutKind.Explicit)]
		private struct FunctionReturnx64 : FunctionReturn
		{
			public const int RAXOffset = 0;

			[FieldOffset(RAXOffset)]
			public ulong RAX;

			[FieldOffset(RAXOffset)]
			private sbyte _Int8;
			[FieldOffset(RAXOffset)]
			private byte _UInt8;

			[FieldOffset(RAXOffset)]
			private short _Int16;
			[FieldOffset(RAXOffset)]
			private ushort _UInt16;

			[FieldOffset(RAXOffset)]
			private int _Int32;
			[FieldOffset(RAXOffset)]
			private uint _UInt32;

			[FieldOffset(RAXOffset)]
			private long _Int64;
			[FieldOffset(RAXOffset)]
			private ulong _UInt64;

			[FieldOffset(RAXOffset)]
			private IntPtr _IntPtr;
			[FieldOffset(RAXOffset)]
			private UIntPtr _UIntPtr;

			public sbyte Int8 { get { return this._Int8; } }
			public byte UInt8 { get { return this._UInt8; } }
			public short Int16 { get { return this._Int16; } }
			public ushort UInt16 { get { return this._UInt16; } }
			public int Int32 { get { return this._Int32; } }
			public uint UInt32 { get { return this._UInt32; } }
			public long Int64 { get { return this._Int64; } }
			public ulong UInt64 { get { return this._UInt64; } }
			public IntPtr IntPtr { get { return this._IntPtr; } }
			public UIntPtr UIntPtr { get { return this._UIntPtr; } }
		}

		[StructLayout(LayoutKind.Explicit)]
		private struct Argumentsx86
		{
			[FieldOffset(0)]
			public uint ECX;

			[FieldOffset(8)]
			public uint EDX;

			[FieldOffset(32)]
			public IntPtr Stack;

			[FieldOffset(40)]
			public int StackLength;
		}

		[StructLayout(LayoutKind.Explicit)]
		private struct Argumentsx64
		{
			[FieldOffset(0)]
			public ulong RCX;

			[FieldOffset(8)]
			public ulong RDX;

			[FieldOffset(16)]
			public ulong R8;

			[FieldOffset(24)]
			public ulong R9;

			[FieldOffset(32)]
			public IntPtr Stack;

			[FieldOffset(40)]
			public int StackLength;
		}

		[StructLayout(LayoutKind.Explicit)]
		private struct CallFunctionParam
		{
			[FieldOffset(0)]
			public IntPtr Function;

			[FieldOffset(8)]
			public Argumentsx86 Argumentsx86;
			[FieldOffset(8)]
			public Argumentsx64 Argumentsx64;

			[FieldOffset(56)]
			public FunctionReturnx86 ReturnValuex86;
			[FieldOffset(56)]
			public FunctionReturnx64 ReturnValuex64;
		}

		private const int StackPointerAlignment = 8;

		public FunctionReturn CallFunction(IntPtr Function, params object[] Paramaters)
		{
			return this.CallFunction(Function, CallingConvention.Winapi, CharSet.Auto, Paramaters);
		}

		public FunctionReturn CallFunction(IntPtr Function, CallingConvention callingConvention, params object[] Paramaters)
		{
			return this.CallFunction(Function, callingConvention, CharSet.Auto, Paramaters);
		}

		public FunctionReturn CallFunction(IntPtr Function, CharSet charSet, params object[] Paramaters)
		{
			return this.CallFunction(Function, CallingConvention.Winapi, charSet, Paramaters);
		}

		public FunctionReturn CallFunction(IntPtr Function, CallingConvention callingConvention, CharSet charSet, params object[] Paramaters)
		{
			return (FunctionReturn)this.CallFunction(Function, callingConvention, charSet, Paramaters, null, null, null, typeof(FunctionReturn), null);
		}

		private object CallFunction(IntPtr Function, CallingConvention callingConvention, CharSet charSet, object[] Paramaters, Type[] ParamaterTypes, MarshalAsAttribute[] Marshalling, bool[] IsByRef, Type ReturnType, MarshalAsAttribute ReturnMarshalling)
		{
			if (Function == IntPtr.Zero)
				throw new ArgumentNullException("Function");

			if (ReturnType == null)
				throw new ArgumentNullException("ReturnType");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			if (callingConvention == 0)
				callingConvention = CallingConvention.Winapi;

			if (charSet == 0)
				charSet = CharSet.Ansi;

			if (Paramaters == null)
				Paramaters = new object[0];

			if (ParamaterTypes == null)
				ParamaterTypes = Type.GetTypeArray(Paramaters);

			if (Marshalling == null)
				Marshalling = new MarshalAsAttribute[Paramaters.Length];

			if (IsByRef == null)
				IsByRef = new bool[Paramaters.Length];

			if (ReturnMarshalling == null)
				ReturnMarshalling = DefaultMarshalling(ReturnType);

			object[] OrigParmaters = new object[Paramaters.Length];
			Type[] AfterMarshalTypes = new Type[Paramaters.Length];
			ICustomMarshaler[] CustomMarshalers = new ICustomMarshaler[Paramaters.Length];
			IntPtr[] PtrParamaters = new IntPtr[Paramaters.Length];

			for (int i = 0; i < Paramaters.Length; i++)
			{
				OrigParmaters[i] = Paramaters[i];

				if (Marshalling[i] == null)
					Marshalling[i] = DefaultMarshalling(ParamaterTypes[i]);

				this.MarshalToNative(ref Paramaters[i], Marshalling[i], ParamaterTypes[i], out CustomMarshalers[i], charSet);

				if (IsByRef[i])
				{
					if (Paramaters[i] == null)
					{
						AfterMarshalTypes[i] = ParamaterTypes[i];
						Paramaters[i] = IntPtr.Zero;
					}
					else
					{
						AfterMarshalTypes[i] = Paramaters[i].GetType();
						Paramaters[i] = this.WriteStruct(Paramaters[i]).Value;
					}
				}

				if (Paramaters[i] is IntPtr)
				{
					PtrParamaters[i] = (IntPtr)Paramaters[i];

					if (this.Is64BitProcess)
						Paramaters[i] = PtrParamaters[i].ToInt64();
					else
						Paramaters[i] = (int)PtrParamaters[i].ToInt64();
				}
			}

			CallFunctionParam Param = new CallFunctionParam()
			{
				Function = Function
			};

			if (this.Is64BitProcess)
			{
				int SkipOnStack = 0;

				if (Paramaters.Length >= 1
					&& Marshal.SizeOf(Paramaters[0]) <= sizeof(ulong))
				{
					Param.Argumentsx64.RCX = StructToStruct<ulong>(Paramaters[0]);
					SkipOnStack = 1;

					if (Paramaters.Length >= 2
						&& Marshal.SizeOf(Paramaters[1]) <= sizeof(ulong))
					{
						Param.Argumentsx64.RDX = StructToStruct<ulong>(Paramaters[1]);
						SkipOnStack = 2;

						if (Paramaters.Length >= 3
							&& Marshal.SizeOf(Paramaters[2]) <= sizeof(ulong))
						{
							Param.Argumentsx64.R8 = StructToStruct<ulong>(Paramaters[2]);
							SkipOnStack = 3;

							if (Paramaters.Length >= 4
								&& Marshal.SizeOf(Paramaters[3]) <= sizeof(ulong))
							{
								Param.Argumentsx64.R9 = StructToStruct<ulong>(Paramaters[3]);
								SkipOnStack = 4;
							}
						}
					}
				}

				for (int i = SkipOnStack; i < Paramaters.Length; i++)
					Param.Argumentsx64.StackLength += Utilities.Align(Marshal.SizeOf(Paramaters[i]), StackPointerAlignment);

				if (Param.Argumentsx64.StackLength != 0)
				{
					IntPtr args = Marshal.AllocHGlobal(Param.Argumentsx64.StackLength);

					try
					{
						IntPtr _args = args;

						for (int i = SkipOnStack; i < Paramaters.Length; i++)
						{
							Marshal.StructureToPtr(Paramaters[i], _args, false);
							_args += Utilities.Align(Marshal.SizeOf(Paramaters[i]), StackPointerAlignment);
						}

						Param.Argumentsx64.Stack = this.WriteMemory(args, Param.Argumentsx64.StackLength);
					}
					finally
					{
						Marshal.FreeHGlobal(args);
					}
				}
			}
			else
			{
				int SkipOnStack = 0;

				switch (callingConvention)
				{
					case CallingConvention.Cdecl:
					case CallingConvention.StdCall:
					case CallingConvention.Winapi:
						for (int i = SkipOnStack; i < Paramaters.Length; i++)
							Param.Argumentsx86.StackLength += Utilities.Align(Marshal.SizeOf(Paramaters[i]), StackPointerAlignment);

						if (Param.Argumentsx86.StackLength != 0)
						{
							IntPtr args = Marshal.AllocHGlobal(Param.Argumentsx86.StackLength);

							try
							{
								IntPtr _args = args;

								for (int i = SkipOnStack; i < Paramaters.Length; i++)
								{
									Marshal.StructureToPtr(Paramaters[i], _args, false);
									_args += Utilities.Align(Marshal.SizeOf(Paramaters[i]), StackPointerAlignment);
								}

								Param.Argumentsx86.Stack = this.WriteMemory(args, Param.Argumentsx86.StackLength);
							}
							finally
							{
								if (args != IntPtr.Zero)
									Marshal.FreeHGlobal(args);
							}
						}
						break;
					case CallingConvention.FastCall:
						if (Paramaters.Length >= 1
							&& Marshal.SizeOf(Paramaters[0]) <= sizeof(uint))
						{
							Param.Argumentsx86.ECX = StructToStruct<uint>(Paramaters[0]);
							SkipOnStack = 1;

							if (Paramaters.Length >= 2
								&& Marshal.SizeOf(Paramaters[1]) <= sizeof(uint))
							{
								Param.Argumentsx86.EDX = StructToStruct<uint>(Paramaters[1]);
								SkipOnStack = 2;
							}
						}

						goto case CallingConvention.StdCall;
					case CallingConvention.ThisCall:
						if (Paramaters.Length < 1)
							throw new ArgumentException("Calling convention requires at least one argument.");

						if (Marshal.SizeOf(Paramaters[0]) > sizeof(uint))
							throw new ArgumentException("Paramater 0 must be this paramater and less than or equal to 32-bits.");

						Param.Argumentsx86.ECX = StructToStruct<uint>(Paramaters[0]);
						SkipOnStack = 1;
						goto case CallingConvention.Cdecl;
					default:
						throw new ArgumentException(null, "callingConvention");
				}
			}

			try
			{
				uint res = this.CallFunctionThreadProc(this.NativeCallFunction, ref Param);

				if (res != Win32.ERROR_SUCCESS)
					throw new Exception("CallFunction failed", new Win32Exception((int)res));
			}
			finally
			{
				if (Param.Argumentsx86.Stack != IntPtr.Zero)
					this.FreeMemory(Param.Argumentsx86.Stack);

				for (int i = 0; i < Paramaters.Length; i++)
				{
					if (IsByRef[i])
					{
						IntPtr PtrParamater = PtrParamaters[i];

						try
						{
							if (AfterMarshalTypes[i] == typeof(IntPtr))
								Paramaters[i] = PtrParamaters[i] = this.ReadIntPtr(PtrParamater);
							else if (PtrParamater == IntPtr.Zero)
								Paramaters[i] = null;
							else
								Paramaters[i] = this.ReadStruct(PtrParamater, AfterMarshalTypes[i]);
						}
						finally
						{
							if (PtrParamater != IntPtr.Zero)
								this.FreeMemory(PtrParamater);
						}
					}

					this.MarshalToManaged(ref Paramaters[i], OrigParmaters[i], PtrParamaters[i], Marshalling[i], ParamaterTypes[i], CustomMarshalers[i], charSet, IsByRef[i]);
				}
			}

			FunctionReturn ReturnValue;

			if (this.Is64BitProcess)
				ReturnValue = Param.ReturnValuex64;
			else
				ReturnValue = Param.ReturnValuex86;

			if (ReturnMarshalling != null)
			{
				object _ReturnValue = ReturnValue.Int64;
				this.MarshalToManaged(ref _ReturnValue, null, ReturnValue.IntPtr, ReturnMarshalling, ReturnType, null, charSet, true);
				return _ReturnValue;
			}
			else if (ReturnType == typeof(FunctionReturn))
				return ReturnValue;
			else if (ReturnType == typeof(sbyte))
				return ReturnValue.Int8;
			else if (ReturnType == typeof(byte))
				return ReturnValue.UInt8;
			else if (ReturnType == typeof(short))
				return ReturnValue.Int16;
			else if (ReturnType == typeof(ushort))
				return ReturnValue.UInt16;
			else if (ReturnType == typeof(int))
				return ReturnValue.Int32;
			else if (ReturnType == typeof(uint))
				return ReturnValue.UInt32;
			else if (ReturnType == typeof(long))
				return ReturnValue.Int64;
			else if (ReturnType == typeof(ulong))
				return ReturnValue.UInt64;
			else if (ReturnType == typeof(IntPtr))
				return ReturnValue.IntPtr;
			else if (ReturnType == typeof(UIntPtr))
				return ReturnValue.UIntPtr;
			else
				throw new NotSupportedException(string.Format("Return type `{0}` is not supported", ReturnType));
		}
	}

	public interface FunctionReturn
	{
		sbyte Int8 { get; }
		byte UInt8 { get; }

		short Int16 { get; }
		ushort UInt16 { get; }

		int Int32 { get; }
		uint UInt32 { get; }

		long Int64 { get; }
		ulong UInt64 { get; }

		IntPtr IntPtr { get; }
		UIntPtr UIntPtr { get; }
	}
}