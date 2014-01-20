using System;

namespace Com.Xenthrax.DllInjector
{
	public abstract class SafeHandle : IDisposable
	{
		public abstract void Dispose();

		public abstract IntPtr Value { get; }

		public override string ToString()
		{
			return this.Value.ToString();
		}

		public string ToString(string format)
		{
			return this.Value.ToString(format);
		}

		public override int GetHashCode()
		{
			return this.Value.GetHashCode();
		}

		public override bool Equals(object obj)
		{
			return this == obj;
		}

		public static IntPtr operator -(SafeHandle value, int p)
		{
			return value.Value - p;
		}

		public static IntPtr operator -(SafeHandle value, long p)
		{
			return new IntPtr(value.Value.ToInt64() - p);
		}

		public static IntPtr operator -(SafeHandle value, IntPtr p)
		{
			return value - p.ToInt64();
		}

		public static IntPtr operator +(SafeHandle value, int p)
		{
			return value.Value + p;
		}

		public static IntPtr operator +(SafeHandle value, long p)
		{
			return new IntPtr(value.Value.ToInt64() + p);
		}

		public static IntPtr operator +(SafeHandle value, IntPtr p)
		{
			return value + p.ToInt64();
		}

		public static implicit operator IntPtr(SafeHandle value)
		{
			return value.Value;
		}

		public static explicit operator int(SafeHandle value)
		{
			return (int)value.Value;
		}

		public static explicit operator long(SafeHandle value)
		{
			return (long)value.Value;
		}

		public static bool operator ==(SafeHandle value1, IntPtr value2)
		{
			return value1.Value == value2;
		}

		public static bool operator !=(SafeHandle value1, IntPtr value2)
		{
			return value1.Value != value2;
		}
	}
}