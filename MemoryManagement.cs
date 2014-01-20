using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		private static readonly int AnsiNullLength = Encoding.Default.GetMaxByteCount(0);
		private static readonly int UnicodeNullLength = Encoding.Unicode.GetMaxByteCount(0);
		private const string Null = "\0";

		#region ReadMemory
		public byte ReadByte(IntPtr Address)
		{
			return this.ReadStruct<byte>(Address);
		}

		public short ReadInt16(IntPtr Address)
		{
			return this.ReadStruct<short>(Address);
		}

		public int ReadInt32(IntPtr Address)
		{
			return this.ReadStruct<int>(Address);
		}

		public long ReadInt64(IntPtr Address)
		{
			return this.ReadStruct<long>(Address);
		}

		public IntPtr ReadIntPtr(IntPtr Address)
		{
			return this.ReadStruct<IntPtr>(Address);
		}

		internal protected MemoryHandle ReadMemoryHandle(IntPtr Address)
		{
			return new MemoryHandle(this, this.ReadIntPtr(Address));
		}

		#region ReadString
		public string ReadStringAnsi(IntPtr Address)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			List<byte> tempData = new List<byte>();

			for (long i = 0; ; i++)
			{
				byte tempByte = this.ReadByte(new IntPtr(Address.ToInt64() + i));

				if (tempByte == 0)
					break;

				tempData.Add(tempByte);
			}

			return Encoding.Default.GetString(tempData.ToArray());
		}

		public void ReadStringAnsi(IntPtr Address, StringBuilder Value)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			if (Value == null)
				throw new ArgumentNullException("Value");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			lock (Value)
			{
				Value.Clear();
				Value.Append(this.ReadStringAnsi(Address));
			}
		}

		public string ReadStringAnsi(IntPtr Address, int StrLen)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			byte[] Data = this.ReadBytes(Address, Encoding.Default.GetMaxByteCount(StrLen));
			return Encoding.Default.GetString(Data, 0, Data.Length - DllInjector.AnsiNullLength);
		}

		public void ReadStringAnsi(IntPtr Address, int StrLen, StringBuilder Value)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			if (Value == null)
				throw new ArgumentNullException("Value");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			lock (Value)
			{
				Value.Clear();
				Value.Append(this.ReadStringAnsi(Address, StrLen));
			}
		}

		public string ReadPrefixedStringAnsi(IntPtr Address)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			int StrLen = this.ReadInt32(Address);
			return this.ReadStringAnsi(Address + sizeof(int), StrLen);
		}

		public void ReadPrefixedStringAnsi(IntPtr Address, StringBuilder Value)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			if (Value == null)
				throw new ArgumentNullException("Value");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			int StrLen = this.ReadInt32(Address);

			lock (Value)
			{
				Value.Clear();
				Value.Append(this.ReadStringAnsi(Address + sizeof(int), StrLen));
			}
		}

		public string ReadStringUni(IntPtr Address)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			List<byte> tempData = new List<byte>();
			short tempVal;
			
			for (long i = 0; ; i += 2)
			{
				tempVal = this.ReadInt16(new IntPtr(Address.ToInt64() + i));

				if (tempVal == 0)
					break;

				tempData.AddRange(BitConverter.GetBytes(tempVal));
			}

			return Encoding.Unicode.GetString(tempData.ToArray());
		}

		public void ReadStringUni(IntPtr Address, StringBuilder Value)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			if (Value == null)
				throw new ArgumentNullException("Value");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			lock (Value)
			{
				Value.Clear();
				Value.Append(this.ReadStringUni(Address));
			}
		}

		public string ReadStringUni(IntPtr Address, int StrLen)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			byte[] Data = this.ReadBytes(Address, Encoding.Unicode.GetMaxByteCount(StrLen));
			return Encoding.Unicode.GetString(Data, 0, Data.Length - DllInjector.UnicodeNullLength);
		}

		public void ReadStringUni(IntPtr Address, int StrLen, StringBuilder Value)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			if (Value == null)
				throw new ArgumentNullException("Value");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			lock (Value)
			{
				Value.Clear();
				Value.Append(this.ReadStringUni(Address, StrLen));
			}
		}

		public string ReadPrefixedStringUni(IntPtr Address)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			int StrLen = this.ReadInt32(Address);
			return this.ReadStringUni(Address + sizeof(int), StrLen);
		}

		public void ReadPrefixedStringUni(IntPtr Address, StringBuilder Value)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			if (Value == null)
				throw new ArgumentNullException("Value");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			int StrLen = this.ReadInt32(Address);

			lock (Value)
			{
				Value.Clear();
				Value.Append(this.ReadStringUni(Address + sizeof(int), StrLen));
			}
		}
		#endregion

		/* ReadArray */

		public byte[] ReadBytes(IntPtr Address, int Size)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			byte[] ret = new byte[Size];
			this.ReadBytes(Address, ret);
			return ret;
		}

		public void ReadBytes(IntPtr Address, byte[] Buffer)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			if (Buffer == null)
				throw new ArgumentNullException("Buffer");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			uint lpNumberOfBytesRead;

			if (!Win32.ReadProcessMemory(this.hProc, Address, Buffer, (uint)Buffer.Length, out lpNumberOfBytesRead))
				throw new Win32Exception();
		}

		public void ReadBytes(IntPtr Address, byte[] Buffer, int Offset, int Length)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			if (Buffer == null)
				throw new ArgumentNullException("Buffer");

			if (Buffer.Length < Offset)
				throw new ArgumentOutOfRangeException("Offset");

			if (Buffer.Length < Offset + Length)
				throw new ArgumentOutOfRangeException("Length");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			GCHandle lpBuffer = GCHandle.Alloc(Buffer, GCHandleType.Pinned);

			try
			{
				uint lpNumberOfBytesRead;

				if (!Win32.ReadProcessMemory(this.hProc, Address, lpBuffer.AddrOfPinnedObject() + Offset, (uint)Length, out lpNumberOfBytesRead))
					throw new Win32Exception();
			}
			finally
			{
				lpBuffer.Free();
			}
		}

		public byte[] ReadPrefixedBytes(IntPtr Address)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			return this.ReadBytes(Address + sizeof(int), this.ReadInt32(Address));
		}

		public T ReadStruct<T>(IntPtr Address)
			where T : struct
		{
			return (T)this.ReadStruct(Address, typeof(T));
		}

		public object ReadStruct(IntPtr Address, Type t)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			if (t == typeof(IntPtr))
			{
				if (this.Is64BitProcess)
					return new IntPtr(this.ReadInt64(Address));
				else
					return new IntPtr(this.ReadInt32(Address));
			}

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			int ResultSize = Marshal.SizeOf(t);
			IntPtr Result = Marshal.AllocHGlobal(ResultSize);

			try
			{
				uint _lpNumberOfBytesRead;

				if (!Win32.ReadProcessMemory(this.hProc, Address, Result, (uint)ResultSize, out _lpNumberOfBytesRead))
					throw new Win32Exception();

				return Marshal.PtrToStructure(Result, t);
			}
			finally
			{
				Marshal.FreeHGlobal(Result);
			}
		}
	
		public void ReadMemory(IntPtr Address, IntPtr Buffer, int Size)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			if (Buffer == IntPtr.Zero)
				throw new ArgumentNullException("Buffer");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			uint lpNumberOfBytesRead;

			if (!Win32.ReadProcessMemory(this.hProc, Address, Buffer, (uint)Size, out lpNumberOfBytesRead))
				throw new Win32Exception();
		}
		#endregion

		#region WriteMemory
		#region Write Alloc
		public MemoryHandle WriteByte(byte Value)
		{
			return this.WriteStruct(Value);
		}

		public MemoryHandle WriteInt16(short Value)
		{
			return this.WriteStruct(Value);
		}

		public MemoryHandle WriteInt32(int Value)
		{
			return this.WriteStruct(Value);
		}

		public MemoryHandle WriteInt64(long Value)
		{
			return this.WriteStruct(Value);
		}

		public MemoryHandle WriteIntPtr(IntPtr Value)
		{
			return this.WriteStruct(Value);
		}

		#region WriteString
		public MemoryHandle WriteStringAnsi(string Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			return this.WriteBytes(Encoding.Default.GetBytes(Value + DllInjector.Null));
		}

		public MemoryHandle WriteStringAnsi(StringBuilder Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			MemoryHandle hRemoteMem = this.AllocMemory(Encoding.Default.GetMaxByteCount(Value.Capacity));
			this.WriteStringAnsi(hRemoteMem, Value);
			return hRemoteMem;
		}

		public MemoryHandle WritePrefixedStringAnsi(string Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			MemoryHandle hRemoteMem = this.AllocMemory(sizeof(int) + Encoding.Default.GetMaxByteCount(Value.Length));
			this.WriteInt32(hRemoteMem, Value.Length);
			this.WriteStringAnsi(hRemoteMem + sizeof(int), Value);
			return hRemoteMem;
		}

		public MemoryHandle WritePrefixedStringAnsi(StringBuilder Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			MemoryHandle hRemoteMem = this.AllocMemory(sizeof(int) + Encoding.Default.GetMaxByteCount(Value.Capacity));
			this.WriteInt32(hRemoteMem, Value.Length);
			this.WriteStringAnsi(hRemoteMem + sizeof(int), Value);
			return hRemoteMem;
		}

		public MemoryHandle WriteStringUni(string Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			return this.WriteBytes(Encoding.Unicode.GetBytes(Value + DllInjector.Null));
		}

		public MemoryHandle WriteStringUni(StringBuilder Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			MemoryHandle hRemoteMem = this.AllocMemory(Encoding.Unicode.GetMaxByteCount(Value.Capacity));
			this.WriteStringUni(hRemoteMem, Value);
			return hRemoteMem;
		}

		public MemoryHandle WritePrefixedStringUni(string Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			MemoryHandle hRemoteMem = this.AllocMemory(sizeof(int) + Encoding.Default.GetMaxByteCount(Value.Length));
			this.WriteInt32(hRemoteMem, Value.Length);
			this.WriteStringUni(hRemoteMem + sizeof(int), Value);
			return hRemoteMem;
		}

		public MemoryHandle WritePrefixedStringUni(StringBuilder Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			MemoryHandle hRemoteMem = this.AllocMemory(sizeof(int) + Encoding.Default.GetMaxByteCount(Value.Capacity));
			this.WriteInt32(hRemoteMem, Value.Length);
			this.WriteStringUni(hRemoteMem + sizeof(int), Value);
			return hRemoteMem;
		}
		#endregion

		public MemoryHandle WriteArray(Array Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");
			
			return this.WriteMemory(Marshal.UnsafeAddrOfPinnedArrayElement(Value, 0), Buffer.ByteLength(Value));
		}

		public MemoryHandle WriteBytes(byte[] Buffer)
		{
			if (Buffer == null)
				throw new ArgumentNullException("Buffer");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			uint _lpNumBytesWritten;
			MemoryHandle hRemoteMem = this.AllocMemory(Buffer.Length);

			if (!Win32.WriteProcessMemory(this.hProc, hRemoteMem, Buffer, (uint)Buffer.Length, out _lpNumBytesWritten))
				throw new Win32Exception();

			return hRemoteMem;
		}

		public MemoryHandle WriteBytes(byte[] Buffer, int Offset, int Length)
		{
			if (Buffer == null)
				throw new ArgumentNullException("Buffer");

			if (Buffer.Length < Offset)
				throw new ArgumentOutOfRangeException("Offset");

			if (Buffer.Length < Offset + Length)
				throw new ArgumentOutOfRangeException("Length");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			GCHandle lpBuffer = GCHandle.Alloc(Buffer, GCHandleType.Pinned);

			try
			{
				return this.WriteMemory(lpBuffer.AddrOfPinnedObject() + Offset, Length);
			}
			finally
			{
				lpBuffer.Free();
			}
		}

		public MemoryHandle WritePrefixedBytes(byte[] Buffer)
		{
			if (Buffer == null)
				throw new ArgumentNullException("Buffer");

			MemoryHandle hRemoteMem = this.AllocMemory(sizeof(int) + Buffer.Length);
			this.WriteInt32(hRemoteMem, Buffer.Length);
			this.WriteBytes(hRemoteMem + sizeof(int), Buffer);
			return hRemoteMem;
		}

		public MemoryHandle WriteStruct(object Data)
		{
			if (Data == null)
				throw new ArgumentNullException("Data");

			if (Data is IntPtr)
			{
				if (this.Is64BitProcess)
					return this.WriteInt64(((IntPtr)Data).ToInt64());
				else
					return this.WriteInt32((int)((IntPtr)Data).ToInt64());
			}

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			int DataLength = Marshal.SizeOf(Data);
			MemoryHandle hRemoteMem = this.AllocMemory(DataLength);
			IntPtr ptr = Marshal.AllocHGlobal(DataLength);

			try
			{
				uint _lpNumBytesWritten;

				Marshal.StructureToPtr(Data, ptr, false);

				if (!Win32.WriteProcessMemory(this.hProc, hRemoteMem, ptr, (uint)DataLength, out _lpNumBytesWritten))
					throw new Win32Exception();

				return hRemoteMem;
			}
			finally
			{
				Marshal.FreeHGlobal(ptr);
			}
		}

		public MemoryHandle WriteMachineCode(byte[] Buffer)
		{
			if (Buffer == null)
				throw new ArgumentNullException("Buffer");

			MemoryHandle hRemoteMem = this.AllocMemory(Buffer.Length, MemoryProtection.PAGE_EXECUTE_READWRITE);
			this.WriteBytes(hRemoteMem, Buffer);

			if (!Win32.FlushInstructionCache(this.hProc, hRemoteMem, (uint)Buffer.Length))
				throw new Win32Exception();

			return hRemoteMem;
		}

		public MemoryHandle WriteMachineCode(byte[] Bufferx86, byte[] Bufferx64)
		{
			return this.WriteMachineCode(this.Is64BitProcess ? Bufferx64 : Bufferx86);
		}

		public MemoryHandle WriteMemory(IntPtr Buffer, int Size)
		{
			if (Buffer == IntPtr.Zero)
				throw new ArgumentNullException("Buffer");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			uint _lpNumBytesWritten;
			MemoryHandle hRemoteMem = this.AllocMemory(Size);

			if (!Win32.WriteProcessMemory(this.hProc, hRemoteMem, Buffer, (uint)Size, out _lpNumBytesWritten))
				throw new Win32Exception();

			return hRemoteMem;
		}
		#endregion

		#region Write To
		public void WriteByte(IntPtr Address, byte Value)
		{
			this.WriteStruct(Address, Value);
		}

		public void WriteInt16(IntPtr Address, short Value)
		{
			this.WriteStruct(Address, Value);
		}

		public void WriteInt32(IntPtr Address, int Value)
		{
			this.WriteStruct(Address, Value);
		}

		public void WriteInt64(IntPtr Address, long Value)
		{
			this.WriteStruct(Address, Value);
		}

		public void WriteIntPtr(IntPtr Address, IntPtr Value)
		{
			this.WriteStruct(Address, Value);
		}

		#region WriteString
		public void WriteStringAnsi(IntPtr Address, string Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			this.WriteBytes(Address, Encoding.Default.GetBytes(Value + DllInjector.Null));
		}

		public void WriteStringAnsi(IntPtr Address, StringBuilder Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			this.WriteBytes(Address, Encoding.Default.GetBytes(Value + DllInjector.Null));
		}

		public void WritePrefixedStringAnsi(IntPtr Address, string Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			this.WriteInt32(Address, Value.Length);
			this.WriteBytes(Address + sizeof(int), Encoding.Default.GetBytes(Value + DllInjector.Null));
		}

		public void WritePrefixedStringAnsi(IntPtr Address, StringBuilder Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			this.WriteInt32(Address, Value.Length);
			this.WriteBytes(Address + sizeof(int), Encoding.Default.GetBytes(Value + DllInjector.Null));
		}
	
		public void WriteStringUni(IntPtr Address, string Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			this.WriteBytes(Address, Encoding.Unicode.GetBytes(Value + DllInjector.Null));
		}

		public void WriteStringUni(IntPtr Address, StringBuilder Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			this.WriteBytes(Address, Encoding.Unicode.GetBytes(Value + DllInjector.Null));
		}

		public void WritePrefixedStringUni(IntPtr Address, string Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			this.WriteInt32(Address, Value.Length);
			this.WriteBytes(Address + sizeof(int), Encoding.Unicode.GetBytes(Value + DllInjector.Null));
		}

		public void WritePrefixedStringUni(IntPtr Address, StringBuilder Value)
		{
			if (Value == null)
				throw new ArgumentNullException("Value");

			this.WriteInt32(Address, Value.Length);
			this.WriteBytes(Address + sizeof(int), Encoding.Unicode.GetBytes(Value + DllInjector.Null));
		}
		#endregion

		public void WriteArray(IntPtr Address, Array Value)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			if (Value == null)
				throw new ArgumentNullException("Value");

			this.WriteMemory(Address, Marshal.UnsafeAddrOfPinnedArrayElement(Value, 0), Buffer.ByteLength(Value));
		}

		public void WriteBytes(IntPtr Address, byte[] Buffer)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			if (Buffer == null)
				throw new ArgumentNullException("Buffer");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			uint NumBytesWritten;

			if (!Win32.WriteProcessMemory(this.hProc, Address, Buffer, (uint)Buffer.Length, out NumBytesWritten))
				throw new Win32Exception();
		}

		public void WriteBytes(IntPtr Address, byte[] Buffer, int Offset, int Length)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			if (Buffer == null)
				throw new ArgumentNullException("Buffer");

			if (Buffer.Length < Offset)
				throw new ArgumentOutOfRangeException("Offset");

			if (Buffer.Length < Offset + Length)
				throw new ArgumentOutOfRangeException("Length");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			GCHandle lpBuffer = GCHandle.Alloc(Buffer, GCHandleType.Pinned);

			try
			{
				uint NumBytesWritten;

				if (!Win32.WriteProcessMemory(this.hProc, Address, lpBuffer.AddrOfPinnedObject() + Offset, (uint)Length, out NumBytesWritten))
					throw new Win32Exception();
			}
			finally
			{
				lpBuffer.Free();
			}
		}

		public void WritePrefixedBytes(IntPtr Address, byte[] Buffer)
		{
			if (Buffer == null)
				throw new ArgumentNullException("Buffer");

			this.WriteInt32(Address, Buffer.Length);
			this.WriteBytes(Address + sizeof(int), Buffer);
		}

		public void WriteStruct(IntPtr Address, object Data)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			if (Data == null)
				throw new ArgumentNullException("Data");

			if (Data is IntPtr)
			{
				if (this.Is64BitProcess)
					this.WriteInt64(Address, ((IntPtr)Data).ToInt64());
				else
					this.WriteInt32(Address, (int)((IntPtr)Data).ToInt64());
				
				return;
			}

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			int DataLength = Marshal.SizeOf(Data);
			IntPtr ptr = Marshal.AllocHGlobal(DataLength);

			try
			{
				uint NumBytesWritten;

				Marshal.StructureToPtr(Data, ptr, false);

				if (!Win32.WriteProcessMemory(this.hProc, Address, ptr, (uint)DataLength, out NumBytesWritten))
					throw new Win32Exception();
			}
			finally
			{
				Marshal.FreeHGlobal(ptr);
			}
		}

		public void WriteMachineCode(IntPtr Address, byte[] Buffer)
		{
			this.WriteBytes(Address, Buffer);
			
			if (!Win32.FlushInstructionCache(this.hProc, Address, (uint)Buffer.Length))
				throw new Win32Exception();
		}

		public void WriteMachineCode(IntPtr Address, byte[] Bufferx86, byte[] Bufferx64)
		{
			this.WriteMachineCode(Address, this.Is64BitProcess ? Bufferx64 : Bufferx86);
		}

		public void WriteMemory(IntPtr Address, IntPtr Buffer, int Size)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			if (Buffer == IntPtr.Zero)
				throw new ArgumentNullException("Buffer");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			uint NumBytesWritten;

			if (!Win32.WriteProcessMemory(this.hProc, Address, Buffer, (uint)Size, out NumBytesWritten))
				throw new Win32Exception();
		}
		#endregion
		#endregion

		public void CopyMemory(IntPtr Destination, IntPtr Source, int Size)
		{
			if (Destination == IntPtr.Zero)
				throw new ArgumentNullException("Destination");

			if (Source == IntPtr.Zero)
				throw new ArgumentNullException("Source");

			this.WriteBytes(Destination, this.ReadBytes(Source, Size));
		}

		public void SetMemory(IntPtr Address, byte Value, int Size)
		{
			this.WriteBytes(Address, Enumerable.Repeat(Value, Size).ToArray());
		}

		public MemoryHandle AllocMemory(int Size, MemoryProtection Protection = MemoryProtection.PAGE_READWRITE, IntPtr Address = default(IntPtr))
		{
			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			IntPtr hRemoteMem = Win32.VirtualAllocEx(this.hProc, Address, (uint)Size, Win32.VirtualAllocExAllocationType.MEM_COMMIT | Win32.VirtualAllocExAllocationType.MEM_RESERVE, Protection);

			if (hRemoteMem == IntPtr.Zero)
				throw new Win32Exception();

			return new MemoryHandle(this, hRemoteMem);
		}

		public void FreeMemory(MemoryHandle RemoteMem)
		{
			if (RemoteMem == null)
				throw new ArgumentNullException("RemoteMem");

			RemoteMem.Dispose();
		}

		public void FreeMemory(IntPtr Address)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			if (!Win32.VirtualFreeEx(this.hProc, Address, 0, Win32.VirtualFreeExFreeType.MEM_RELEASE))
				throw new Win32Exception();
		}

		public MemoryProtection ProtectMemory(IntPtr Address, int Size, MemoryProtection NewProtect)
		{
			if (Address == IntPtr.Zero)
				throw new ArgumentNullException("Address");

			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();

			MemoryProtection flOldProtect;

			if (!Win32.VirtualProtectEx(this.hProc, Address, (uint)Size, NewProtect, out flOldProtect))
				throw new Win32Exception();

			return flOldProtect;
		}
	}

	public class MemoryHandle : SafeHandle
	{
		internal protected MemoryHandle(DllInjector Injector, IntPtr hRemoteMem)
		{
			this.Injector = Injector;
			this.hRemoteMem = hRemoteMem;
		}

		private DllInjector Injector;
		internal protected bool Disposed;

		private IntPtr hRemoteMem;

		public override IntPtr Value
		{
			get
			{
				if (this.Disposed)
					throw new ObjectDisposedException(this.GetType().Name);

				return this.hRemoteMem;
			}
		}

		public override void Dispose()
		{
			if (this.Disposed)
				return;

			if (this.hRemoteMem != IntPtr.Zero)
				this.Injector.FreeMemory(this.hRemoteMem);

			this.hRemoteMem = IntPtr.Zero;
			this.Disposed = true;
		}
	}

	[Flags]
	public enum MemoryProtection : uint
	{
		PAGE_EXECUTE = 0x10,
		PAGE_EXECUTE_READ = 0x20,
		PAGE_EXECUTE_READWRITE = 0x40,
		PAGE_EXECUTE_WRITECOPY = 0x80,
		PAGE_NOACCESS = 0x1,
		PAGE_READONLY = 0x2,
		PAGE_READWRITE = 0x4,
		PAGE_WRITECOPY = 0x8,
		PAGE_GUARD = 0x100,
		PAGE_NOCACHE = 0x200,
		PAGE_WRITECOMBINE = 0x400
	}
}