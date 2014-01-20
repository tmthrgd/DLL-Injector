using System;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;

namespace Com.Xenthrax
{
	public partial class DllInjector : IDisposable
	{
		[StructLayout(LayoutKind.Sequential)]
		public struct RemPtr : ISerializable
		{
			public const RemPtr Zero = new RemPtr(0);
			
			public RemPtr(int value)
			{
				this.Value = value;
			}

			public RemPtr(long value)
			{
				this.Value = value;
			}

			public RemPtr(IntPtr value)
			{
				this.Value = value.ToInt64();
			}

			public unsafe RemPtr(void* value)
			{
				this.Value = (long)value;
			}

			private RemPtr(SerializationInfo info, StreamingContext context)
			{
				long num = info.GetInt64("value");

				//if ((Size == 4) && ((num > 0x7fffffffL) || (num < -2147483648L)))
				//	throw new ArgumentException(Environment.GetResourceString("Serialization_InvalidPtrValue"));

				this.Value = num;
			}

			private long Value;

			private unsafe void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context)
			{
				if (info == null)
					throw new ArgumentNullException("info");

				info.AddValue("value", this.Value);
			}

			public override bool Equals(object obj)
			{
				if (obj is RemPtr)
				{
					RemPtr ptr = (RemPtr)obj;
					return (this.Value == ptr.Value);
				}
				
				return false;
			}

			public override int GetHashCode()
			{
				return (int)this.Value;
			}

			public int ToInt32()
			{
				return (int)this.Value;
			}

			public long ToInt64()
			{
				return this.Value;
			}

			public IntPtr ToIntPtr()
			{
				return (IntPtr)this.Value;
			}

			public unsafe void* ToPointer()
			{
				return (void*)this.Value;
			}

			public override string ToString()
			{
				return this.Value.ToString(CultureInfo.InvariantCulture);
			}

			public string ToString(string format)
			{
				return this.Value.ToString(format, CultureInfo.InvariantCulture);
			}

			public static explicit operator RemPtr(int value)
			{
				return new RemPtr(value);
			}

			public static explicit operator RemPtr(long value)
			{
				return new RemPtr(value);
			}

			public static explicit operator RemPtr(IntPtr value)
			{
				return new RemPtr(value);
			}

			public static unsafe explicit operator RemPtr(void* value)
			{
				return new RemPtr(value);
			}

			public static unsafe explicit operator void*(RemPtr value)
			{
				return value.ToPointer();
			}

			public static explicit operator int(RemPtr value)
			{
				return (int)value.Value;
			}

			public static explicit operator long(RemPtr value)
			{
				return value.Value;
			}

			public static unsafe bool operator ==(RemPtr value1, RemPtr value2)
			{
				return value1.Value == value2.Value;
			}

			public static unsafe bool operator !=(RemPtr value1, RemPtr value2)
			{
				return value1.Value != value2.Value;
			}

			public static RemPtr Add(RemPtr pointer, int offset)
			{
				return pointer + offset;
			}

			public static RemPtr operator +(RemPtr pointer, int offset)
			{
				return new RemPtr(pointer.ToInt64() + offset);
			}

			public static RemPtr Subtract(RemPtr pointer, int offset)
			{
				return pointer - offset;
			}

			public static RemPtr operator -(RemPtr pointer, int offset)
			{
				return new RemPtr(pointer.ToInt64() - offset);
			}
		}
	}
}