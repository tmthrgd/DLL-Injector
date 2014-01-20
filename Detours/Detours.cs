/*
 * 
 */
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Text;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		private bool DetoursPendingCommit = false;
		private DetourOperation DetoursPendingOperations = null;
		/*private DetourThread DetoursPendingThreads = null;*/
		private uint DetoursPendingError = Win32.NO_ERROR;
		private IntPtr DetoursppPendingError = IntPtr.Zero;
		private IntPtr DetourspRegions = IntPtr.Zero;
		private bool DetoursRetainRegions = false;
		private IntPtr DetourspRegion = IntPtr.Zero;
		private bool DetoursIgnoreTooSmall = false;

		private const uint SIZE_OF_JMP = 5;
		private const uint DETOUR_REGION_SIZE = 0x10000;
		private static readonly uint DETOUR_REGION_SIGNATURE = BitConverter.ToUInt32(Encoding.Default.GetBytes("Rrtd"), 0);
		private static readonly uint DETOUR_TRAMPOLINES_PER_REGIONx86 = (uint)(DETOUR_REGION_SIZE / Marshal.SizeOf(typeof(DETOUR_TRAMPOLINEx86))) - 1;

		[StructLayout(LayoutKind.Sequential)]
		private struct DETOUR_ALIGN
		{
			private byte _value;

			public byte obTarget
			{
				get
				{
					return (byte)(this._value & 0x7);
				}
				set
				{
					this._value &= unchecked((byte)~0x7);
					this._value |= (byte)(value & 0x7);
				}
			}
			public byte obTrampoline
			{
				get
				{
					return (byte)((this._value >> 3) & 0x1F);
				}
				set
				{
					this._value &= unchecked((byte)~0xF8);
					this._value |= (byte)((value & 0x7) << 3);
				}
			}
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct DETOUR_TRAMPOLINEx86
		{
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 30)]
			public byte[] rbCode;     // target code + jmp to pbRemain
			public byte cbCode;         // size of moved target code.
			public byte cbCodeBreak;    // padding to make debugging easier.
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 22)]
			public byte[] rbRestore;  // original target code.
			public byte cbRestore;      // size of original target code.
			public byte cbRestoreBreak; // padding to make debugging easier.
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
			public DETOUR_ALIGN[] rAlign;      // instruction alignment array.
			private int _pbRemain;       // first instruction after moved code. [free list]
			private int _pbDetour;       // first instruction of detour function.

			public IntPtr pbRemain
			{
				get { return new IntPtr(this._pbRemain); }
				set { this._pbRemain = (int)value.ToInt64(); }
			}

			public IntPtr pbDetour
			{
				get { return new IntPtr(this._pbDetour); }
				set { this._pbDetour = (int)value.ToInt64(); }
			}
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct DETOUR_REGIONx86
		{
			public uint dwSignature;
			private int _pNext; // DETOUR_REGION  // Next region in list of regions.
			private int _pFree; // DETOUR_TRAMPOLINE // List of free trampolines in this region.

			public IntPtr pNext
			{
				get { return new IntPtr(this._pNext); }
				set { this._pNext = (int)value.ToInt64(); }
			}

			public IntPtr pFree
			{
				get { return new IntPtr(this._pFree); }
				set { this._pFree = (int)value.ToInt64(); }
			}
		}

		/*private sealed class DetourThread
		{
			public DetourThread pNext; // DetourThread
			public IntPtr hThread;
		}*/

		private sealed class DetourOperation
		{
			public DetourOperation pNext; // DetourOperation
			public bool fIsRemove;
			public GCHandle ppbPointer;
			public IntPtr pbTarget;
			public IntPtr pTrampoline; // DETOUR_TRAMPOLINE
			public MemoryProtection dwPerm;
		}

		private void detour_writable_trampoline_regions()
		{
			// Mark all of the regions as writable.
			IntPtr pRegion = this.DetourspRegions;

			while (pRegion != IntPtr.Zero)
			{
				this.ProtectMemory(pRegion, (int)DETOUR_REGION_SIZE, MemoryProtection.PAGE_EXECUTE_READWRITE);
				pRegion = this.ReadStruct<DETOUR_REGIONx86>(pRegion).pNext;
			}
		}

		private IntPtr detour_gen_jmp_immediate(IntPtr pbCode, IntPtr pbJmpVal)
		{
			IntPtr pbJmpSrc = pbCode + 5;
			this.WriteByte(pbCode, 0xE9); // jmp +imm32
			pbCode += sizeof(byte);

			this.WriteInt32(pbCode, (int)(pbJmpVal.ToInt64() - pbJmpSrc.ToInt64()));
			pbCode += sizeof(int);

			return pbCode;
		}

		private IntPtr detour_gen_brk(IntPtr pbCode, IntPtr pbLimit)
		{
			long _pbLimit = pbLimit.ToInt64();

			while (pbCode.ToInt64() < _pbLimit)
			{
				this.WriteByte(pbCode, 0xcc); // brk;
				pbCode += sizeof(byte);
			}

			return pbCode;
		}

		private static byte detour_align_from_trampoline(DETOUR_TRAMPOLINEx86 Trampoline, byte obTrampoline)
		{
			for (int n = 0; n < Trampoline.rAlign.Length; n++)
				if (Trampoline.rAlign[n].obTrampoline == obTrampoline)
					return Trampoline.rAlign[n].obTarget;

			return 0;
		}

		private static int detour_align_from_target(DETOUR_TRAMPOLINEx86 Trampoline, int obTarget)
		{
			for (int n = 0; n < Trampoline.rAlign.Length; n++)
				if (Trampoline.rAlign[n].obTarget == obTarget)
					return Trampoline.rAlign[n].obTrampoline;

			return 0;
		}

		private void detour_free_trampoline(IntPtr pTrampoline, DETOUR_TRAMPOLINEx86 Trampoline)
		{
			IntPtr pRegion = new IntPtr(pTrampoline.ToInt64() & ~0xffff);

			this.WriteBytes(pTrampoline, new byte[Marshal.SizeOf(typeof(DETOUR_TRAMPOLINEx86))]);

			DETOUR_REGIONx86 Region = this.ReadStruct<DETOUR_REGIONx86>(pRegion);

			Trampoline.pbRemain = Region.pFree;
			this.WriteStruct(pTrampoline, Trampoline);

			Region.pFree = pTrampoline;
			this.WriteStruct(pRegion, Region);
		}

		private bool detour_is_region_empty(IntPtr pRegion, DETOUR_REGIONx86 Region)
		{
			// Stop if the region isn't a region (this would be bad).
			if (Region.dwSignature != DETOUR_REGION_SIGNATURE)
				return false;

			IntPtr pbRegionBeg = pRegion;
			IntPtr pbRegionLim = pbRegionBeg + (int)DETOUR_REGION_SIZE;

			// Stop if any of the trampolines aren't free.
			IntPtr pTrampoline = pRegion + Marshal.SizeOf(typeof(DETOUR_TRAMPOLINEx86));

			for (int i = 0; i < DETOUR_TRAMPOLINES_PER_REGIONx86; i++)
			{
				DETOUR_TRAMPOLINEx86 Trampoline = this.ReadStruct<DETOUR_TRAMPOLINEx86>(pTrampoline);
				pTrampoline += Marshal.SizeOf(typeof(DETOUR_TRAMPOLINEx86));

				if (Trampoline.pbRemain != IntPtr.Zero &&
					(Trampoline.pbRemain.ToInt64() < pbRegionBeg.ToInt64() ||
					 Trampoline.pbRemain.ToInt64() >= pbRegionLim.ToInt64()))
					return false;
			}

			// OK, the region is empty.
			return true;
		}

		private void detour_free_unused_trampoline_regions()
		{
			//IntPtr* ppRegionBase = &s_pRegions;
			IntPtr pRegion = this.DetourspRegions;

			while (pRegion != IntPtr.Zero)
			{
				DETOUR_REGIONx86 Region = this.ReadStruct<DETOUR_REGIONx86>(pRegion);

				if (this.detour_is_region_empty(pRegion, Region))
				{
					//*ppRegionBase = pRegion->pNext;
					this.DetourspRegions = Region.pNext;

					this.FreeMemory(pRegion);
					this.DetourspRegion = IntPtr.Zero;
				}
				else
					//ppRegionBase = &pRegion->pNext;
					this.DetourspRegions = Region.pNext;

				//pRegion = *ppRegionBase;
				pRegion = this.DetourspRegions;
			}
		}

		private void detour_runnable_trampoline_regions()
		{
			// Mark all of the regions as executable.
			IntPtr pRegion = DetourspRegions;

			while (pRegion != IntPtr.Zero)
			{
				this.ProtectMemory(pRegion, (int)DETOUR_REGION_SIZE, MemoryProtection.PAGE_EXECUTE_READ);
				Win32.FlushInstructionCache(this.hProc, pRegion, DETOUR_REGION_SIZE);
				pRegion = this.ReadStruct<DETOUR_REGIONx86>(pRegion).pNext;
			}
		}

		private bool detour_is_imported(IntPtr pbCode, IntPtr pbAddress)
		{
			this.ThrowIfx64();

			Win32.MEMORY_BASIC_INFORMATION mbi;

			if (Win32.VirtualQueryEx(this.hProc, pbCode, out mbi, (uint)Marshal.SizeOf(typeof(Win32.MEMORY_BASIC_INFORMATION))) == 0)
				throw new Win32Exception();

			IntPtr pDosHeader = mbi.AllocationBase;
			Win32.IMAGE_DOS_HEADER DosHeader = this.ReadStruct<Win32.IMAGE_DOS_HEADER>(pDosHeader);

			if (DosHeader._e_magic != "MZ")
				return false;

			Win32.IMAGE_NT_HEADERS32 NtHeader = this.ReadStruct<Win32.IMAGE_NT_HEADERS32>(pDosHeader + (int)DosHeader.e_lfanew);

			if (NtHeader._Signature != "PE")
				return false;

			if (pbAddress.ToInt64() >= (pDosHeader.ToInt64() +
							  NtHeader.OptionalHeader.DataDirectory[Win32.IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress) &&
				pbAddress.ToInt64() < (pDosHeader.ToInt64() +
							 NtHeader.OptionalHeader
							 .DataDirectory[Win32.IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress +
							 NtHeader.OptionalHeader
							 .DataDirectory[Win32.IMAGE_DIRECTORY_ENTRY_IAT].Size))
				return true;

			return false;
		}

		private IntPtr detour_skip_jmp(IntPtr pbCode, IntPtr ppGlobals)
		{
			if (pbCode == IntPtr.Zero)
				return IntPtr.Zero;

			if (ppGlobals != IntPtr.Zero)
				this.WriteIntPtr(ppGlobals, IntPtr.Zero);

			// First, skip over the import vector if there is one.
			//if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [imm32]
			if (this.ReadInt16(pbCode) == 0x25ff)
			{
				// Looks like an import alias jump, then get the code it points to.
				IntPtr pbTarget = pbCode + 2;

				if (this.detour_is_imported(pbCode, pbTarget))
				{
					IntPtr pbNew = this.ReadIntPtr(pbTarget);
					Utilities.Log("{0}->{1}: skipped over import table.\n", pbCode, pbNew);
					pbCode = pbNew;
				}
			}

			// Then, skip over a patch jump
			if (this.ReadByte(pbCode) == 0xeb)
			{
				// jmp +imm8
				IntPtr pbNew = pbCode + 2 + this.ReadInt16(pbCode + 1);
				Utilities.Log("{0}->{1}: skipped over short jump.\n", pbCode, pbNew);
				pbCode = pbNew;

				// Finally, skip over a long jump if it is the target of the patch jump.
				if (this.ReadByte(pbCode) == 0xe9)
				{   // jmp +imm32
					pbNew = pbCode + 5 + this.ReadInt32(pbCode + 1);
					Utilities.Log("{0}->{1}: skipped over long jump.\n", pbCode, pbNew);
					pbCode = pbNew;
				}
			}

			return pbCode;
		}

		private static IntPtr detour_alloc_round_down_to_region(IntPtr pbTry)
		{
			// WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
			IntPtr extra = new IntPtr(pbTry.ToInt64() & (DETOUR_REGION_SIZE - 1));

			if (extra != IntPtr.Zero)
				pbTry -= (int)extra.ToInt64();

			return pbTry;
		}

		private static IntPtr detour_alloc_round_up_to_region(IntPtr pbTry)
		{
			// WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
			IntPtr extra = new IntPtr(pbTry.ToInt64() & (DETOUR_REGION_SIZE - 1));

			if (extra != IntPtr.Zero)
				pbTry -= (int)(DETOUR_REGION_SIZE - extra.ToInt64());

			return pbTry;
		}

		private IntPtr detour_alloc_region_from_lo(IntPtr pbLo, IntPtr pbHi)
		{
			IntPtr pbTry = detour_alloc_round_up_to_region(pbLo);

			Utilities.Log(" Looking for free region in {0}..{1} from {2}:\n", pbLo, pbHi, pbTry);

			while (pbTry.ToInt64() < pbHi.ToInt64())
			{
				if (pbTry.ToInt64() >= 0x50000000 &&
					pbTry.ToInt64() <= 0x80000000)
				{
					// Skip region reserved for system DLLs.
					pbTry = new IntPtr(0x80000000 + DETOUR_REGION_SIZE);
					continue;
				}

				Win32.MEMORY_BASIC_INFORMATION mbi;

				if (Win32.VirtualQueryEx(this.hProc, pbTry, out mbi, (uint)Marshal.SizeOf(typeof(Win32.MEMORY_BASIC_INFORMATION))) == 0)
				{
					Utilities.Log(new Win32Exception());
					break;
				}

				Utilities.Log("  Try {0} => {1}..{2} {3}\n",
							  pbTry,
							  mbi.BaseAddress,
							  mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64() - 1,
							  mbi.State);

				if (mbi.State == Win32.MEM_FREE && mbi.RegionSize.ToInt64() >= DETOUR_REGION_SIZE)
				{
					IntPtr pv = this.AllocMemory((int)DETOUR_REGION_SIZE, MemoryProtection.PAGE_EXECUTE_READWRITE, pbTry);

					if (pv != IntPtr.Zero)
						return pv;

					pbTry += (int)DETOUR_REGION_SIZE;
				}
				else
					pbTry = detour_alloc_round_up_to_region(mbi.BaseAddress + (int)mbi.RegionSize);
			}

			return IntPtr.Zero;
		}

		private IntPtr detour_alloc_region_from_hi(IntPtr pbLo, IntPtr pbHi)
		{
			IntPtr pbTry = detour_alloc_round_down_to_region(pbHi - (int)DETOUR_REGION_SIZE);

			Utilities.Log(" Looking for free region in {0}..{1} from {2}:\n", pbLo, pbHi, pbTry);

			while (pbTry.ToInt64() > pbLo.ToInt64())
			{
				Utilities.Log("  Try {0}\n", pbTry);

				if (pbTry.ToInt64() >= 0x50000000 &&
					pbTry.ToInt64() <= 0x80000000)
				{
					// Skip region reserved for system DLLs.
					pbTry = new IntPtr(0x50000000 - DETOUR_REGION_SIZE);
					continue;
				}

				Win32.MEMORY_BASIC_INFORMATION mbi;

				if (Win32.VirtualQueryEx(this.hProc, pbTry, out mbi, (uint)Marshal.SizeOf(typeof(Win32.MEMORY_BASIC_INFORMATION))) == 0)
				{
					Utilities.Log(new Win32Exception());
					break;
				}

				Utilities.Log("  Try {0} => {1}..{2} {3}\n",
							  pbTry,
							  mbi.BaseAddress,
							  mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64() - 1,
							  mbi.State);

				if (mbi.State == Win32.MEM_FREE && mbi.RegionSize.ToInt64() >= DETOUR_REGION_SIZE)
				{
					IntPtr pv = this.AllocMemory((int)DETOUR_REGION_SIZE, MemoryProtection.PAGE_EXECUTE_READWRITE, pbTry);

					if (pv != IntPtr.Zero)
						return pv;

					pbTry -= (int)DETOUR_REGION_SIZE;
				}
				else
					pbTry = detour_alloc_round_down_to_region(mbi.AllocationBase - (int)DETOUR_REGION_SIZE);
			}

			return IntPtr.Zero;
		}

		private IntPtr detour_alloc_trampoline(IntPtr pbTarget)
		{
			// We have to place trampolines within +/- 2GB of target.

			IntPtr pLo = new IntPtr((pbTarget.ToInt64() > 0x7ff80000)
				 ? (pbTarget.ToInt64() - 0x7ff80000) : DETOUR_REGION_SIZE);
			long _pHi = (long)(((ulong)pbTarget.ToInt64() < 0xffffffff80000000)
				 ? (ulong)(pbTarget.ToInt64() + 0x7ff80000) : 0xfffffffffff80000);
			IntPtr pHi = new IntPtr(this.Is64BitProcess ? _pHi : unchecked((int)_pHi));
			Utilities.Log("[{0:X}..{1:X}..{2:X}]\n", pLo, pbTarget, pHi);

			IntPtr pTrampoline = IntPtr.Zero;
			DETOUR_REGIONx86 Region;
			DETOUR_TRAMPOLINEx86 Trampoline;

			// Insure that there is a default region.
			if (this.DetourspRegion == IntPtr.Zero && this.DetourspRegions != IntPtr.Zero)
				this.DetourspRegion = this.DetourspRegions;

			// First check the default region for an valid free block.
			if (this.DetourspRegion != IntPtr.Zero)
			{
				Region = this.ReadStruct<DETOUR_REGIONx86>(this.DetourspRegion);

				if (Region.pFree != IntPtr.Zero && Region.pFree.ToInt64() >= pLo.ToInt64() && Region.pFree.ToInt64() <= pHi.ToInt64())
					goto found_region;
			}

			// Then check the existing regions for a valid free block.
			this.DetourspRegion = this.DetourspRegions;

			while (this.DetourspRegion != IntPtr.Zero)
			{
				Region = this.ReadStruct<DETOUR_REGIONx86>(this.DetourspRegion);

				if (Region.pFree != IntPtr.Zero && Region.pFree.ToInt64() >= pLo.ToInt64() && Region.pFree.ToInt64() <= pHi.ToInt64())
					goto found_region;

				this.DetourspRegion = Region.pNext;
			}

			// We need to allocate a new region.

			// Round pbTarget down to 64KB block.
			//pbTarget = pbTarget - (PtrToUlong(pbTarget) & 0xffff);
			pbTarget -= pbTarget.ToInt32() & 0xffff;

			IntPtr pbTry = IntPtr.Zero;

			// First, we try looking 1GB below.
			if (pbTarget.ToInt64() > 0x40000000)
			{
				pbTry = this.detour_alloc_region_from_lo(pbTarget - 0x40000000, pbTarget);

				if (pbTry == IntPtr.Zero)
					pbTry = this.detour_alloc_region_from_hi(pLo, pbTarget - 0x40000000);
			}

			// Then, we try looking 1GB above.
			if (pbTry == IntPtr.Zero && (ulong)pbTarget.ToInt64() < 0xffffffff40000000)
			{
				pbTry = this.detour_alloc_region_from_hi(pbTarget, pbTarget + 0x40000000);

				if (pbTry == IntPtr.Zero)
					pbTry = this.detour_alloc_region_from_lo(pbTarget + 0x40000000, pHi);
			}

			// Then, we try anything below.
			if (pbTry == IntPtr.Zero)
				pbTry = this.detour_alloc_region_from_hi(pLo, pbTarget);

			// Then, we try anything above.
			if (pbTry == IntPtr.Zero)
				pbTry = detour_alloc_region_from_lo(pbTarget, pHi);

			if (pbTry != IntPtr.Zero)
			{
				this.DetourspRegion = pbTry;
				Region = this.ReadStruct<DETOUR_REGIONx86>(this.DetourspRegion);
				Region.dwSignature = DETOUR_REGION_SIGNATURE;
				Region.pFree = IntPtr.Zero;
				Region.pNext = this.DetourspRegions;
				this.DetourspRegions = this.DetourspRegion;
				Utilities.Log("  Allocated region {0}..{1}\n\n",
							  this.DetourspRegion, this.DetourspRegion + (int)DETOUR_REGION_SIZE - 1);

				// Put everything but the first trampoline on the free list.
				IntPtr pFree = IntPtr.Zero;
				pTrampoline = this.DetourspRegion + Marshal.SizeOf(typeof(DETOUR_TRAMPOLINEx86));

				for (uint i = DETOUR_TRAMPOLINES_PER_REGIONx86 - 1; i > 1; i--)
				{
					Trampoline = this.ReadStruct<DETOUR_TRAMPOLINEx86>(pTrampoline);
					Trampoline.pbRemain = pFree;
					this.WriteStruct(pTrampoline, Trampoline);
					pFree = pTrampoline;
					pTrampoline += Marshal.SizeOf(typeof(DETOUR_TRAMPOLINEx86));
				}

				Region.pFree = pFree;
				this.WriteStruct(this.DetourspRegion, Region);
				goto found_region;
			}

			Utilities.Log("Couldn't find available memory region!\n");
			return IntPtr.Zero;

		found_region:
			pTrampoline = Region.pFree;

			// do a last sanity check on region.
			if (pTrampoline.ToInt64() < pLo.ToInt64() || pTrampoline.ToInt64() > _pHi)
				return IntPtr.Zero;

			Trampoline = this.ReadStruct<DETOUR_TRAMPOLINEx86>(pTrampoline);
			Region.pFree = Trampoline.pbRemain;
			this.WriteStruct(this.DetourspRegion, Region);
			this.SetMemory(pTrampoline, 0xcc, Marshal.SizeOf(typeof(DETOUR_TRAMPOLINEx86)));
			return pTrampoline;
		}

		private bool detour_does_code_end_function(IntPtr pbCode)
		{
			byte pbCode0 = this.ReadByte(pbCode);
			byte pbCode1 = this.ReadByte(pbCode + 1);

			if (pbCode0 == 0xeb ||    // jmp +imm8
				pbCode0 == 0xe9 ||    // jmp +imm32
				pbCode0 == 0xe0 ||    // jmp eax
				pbCode0 == 0xc2 ||    // ret +imm8
				pbCode0 == 0xc3 ||    // ret
				pbCode0 == 0xcc)      // brk
				return true;
			else if (pbCode0 == 0xff && pbCode1 == 0x25)  // jmp [+imm32]
				return true;
			else if ((pbCode0 == 0x26 ||      // jmp es:
					  pbCode0 == 0x2e ||      // jmp cs:
					  pbCode0 == 0x36 ||      // jmp ss:
					  pbCode0 == 0xe3 ||      // jmp ds:
					  pbCode0 == 0x64 ||      // jmp fs:
					  pbCode0 == 0x65) &&     // jmp gs:
					 pbCode1 == 0xff &&       // jmp [+imm32]
					 this.ReadByte(pbCode + 2) == 0x25)
				return true;

			return false;
		}

		private int detour_is_code_filler(IntPtr pbCode)
		{
			if (this.ReadByte(pbCode) == 0x90) // nop
				return 1;

			return 0;
		}

		private IntPtr DetourCopyInstruction(IntPtr pDst, ref IntPtr ppDstPool, IntPtr pSrc, IntPtr ppTarget, out int lExtra)
		{
			GCHandle plExtra = GCHandle.Alloc(0);

			CDetourDis oDetourDisasm = new CDetourDis(this, ppTarget, plExtra);
			IntPtr ptr = oDetourDisasm.CopyInstruction(pDst, pSrc);

			lExtra = (int)plExtra.Target;
			return ptr;
		}

		private IntPtr DetourCodeFromPointer(IntPtr pPointer, IntPtr ppGlobals)
		{
			return this.detour_skip_jmp(pPointer, ppGlobals);
		}

		public void DetourTransactionBegin()
		{
			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();
			this.ThrowIfx64();

			// Only one transaction is allowed at a time.
			if (this.DetoursPendingCommit)
				throw new InvalidOperationException();

			// Make sure only one thread can start a transaction.
			this.DetoursPendingCommit = true;

			this.DetoursPendingOperations = null;
			/*this.DetoursPendingThreads = null;*/
			this.DetoursPendingError = Win32.NO_ERROR;
			this.DetoursppPendingError = IntPtr.Zero;

			// Make sure the trampoline pages are writable.
			this.detour_writable_trampoline_regions();
		}

		public void DetourTransactionAbort()
		{
			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();
			this.ThrowIfx64();

			throw new NotImplementedException();
		}

		public void DetourTransactionCommit()
		{
			IntPtr ppFailedPointer;
			this.DetourTransactionCommitEx(out ppFailedPointer);
		}

		private void DetourTransactionCommitEx(out IntPtr ppFailedPointer)
		{
			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();
			this.ThrowIfx64();

			// Used to get the last error.
			ppFailedPointer = this.DetoursppPendingError;

			if (!this.DetoursPendingCommit)
				throw new InvalidOperationException();

			// If any of the pending operations failed, then we abort the whole transaction.
			if (this.DetoursPendingError != Win32.NO_ERROR)
			{
				this.DetourTransactionAbort();
				throw new Win32Exception((int)this.DetoursPendingError);
			}

			// Common variables.
			DetourOperation o = this.DetoursPendingOperations;
			/*DetourThread t = this.DetoursPendingThreads;*/
			bool freed = false;

			// Insert or remove each of the detours.
			while (o != null)
			{
				DETOUR_TRAMPOLINEx86 Trampoline = this.ReadStruct<DETOUR_TRAMPOLINEx86>(o.pTrampoline);

				if (o.fIsRemove)
				{
					this.WriteBytes(o.pbTarget,
							   Trampoline.rbRestore,
							   0,
							   Trampoline.cbRestore);

					if (!this.Is64BitProcess)
						o.ppbPointer.Target = o.pbTarget;
				}
				else
				{
					Utilities.Log("detours: pbTramp={0}, pbRemain={1}, pbDetour={2}, cbRestore={3}\n",
								  o.pTrampoline,
								  Trampoline.pbRemain,
								  Trampoline.pbDetour,
								  Trampoline.cbRestore);

					Utilities.Log("detours: pbTarget={0}: " +
								  "{1} [before]\n",
								  o.pbTarget,
								  new SoapHexBinary(this.ReadBytes(o.pbTarget, 12)));

					if (!this.Is64BitProcess)
					{
						IntPtr pbCode = this.detour_gen_jmp_immediate(o.pbTarget, Trampoline.pbDetour);
						pbCode = this.detour_gen_brk(pbCode, Trampoline.pbRemain);
						o.ppbPointer.Target = Utilities.OffsetOf<DETOUR_TRAMPOLINEx86>(o.pTrampoline, "rbCode");
					}

					Utilities.Log("detours: pbTarget={0}: " +
								  "{1} [after]\n",
								  o.pbTarget,
								new SoapHexBinary(this.ReadBytes(o.pbTarget, 12)));

					Utilities.Log("detours: pbTramp ={0}: " +
								  "{1}\n",
								  o.pTrampoline,
								  new SoapHexBinary(Trampoline.rbCode));
				}

				o = o.pNext;
			}

			// Update any suspended threads.
			/*while (t != null)
			{
				Win32.CONTEXT cxt = new Win32.CONTEXT();
				cxt.ContextFlags = Win32.CONTEXT_FLAGS.CONTEXT_CONTROL;

				if (Win32.GetThreadContext(t.hThread, ref cxt))
				{
					o = this.DetoursPendingOperations;

					while (o != null)
					{
						DETOUR_TRAMPOLINEx86 Trampoline = this.ReadStruct<DETOUR_TRAMPOLINEx86>(o.pTrampoline);

						if (o.fIsRemove)
						{
							if (cxt.Eip >= o.pTrampoline.ToInt64() &&
								cxt.Eip < o.pTrampoline.ToInt64() + Marshal.SizeOf(typeof(DETOUR_TRAMPOLINEx86))
							   )
							{
								cxt.Eip = (uint)
									(o.pbTarget
									 + detour_align_from_trampoline(Trampoline,
																	(byte)(cxt.Eip
																		   - (uint)o.pTrampoline.ToInt64()))).ToInt64();

								Win32.SetThreadContext(t.hThread, ref cxt);
							}
						}
						else
						{
							if (cxt.Eip >= o.pbTarget.ToInt64() &&
								cxt.Eip < o.pbTarget.ToInt64() + Trampoline.cbRestore
							   )
							{

								cxt.Eip = (uint)
								 (o.pTrampoline
								  + detour_align_from_target(Trampoline,
															 (byte)(cxt.Eip
																	-
																	o.pbTarget.ToInt64())));

								Win32.SetThreadContext(t.hThread, ref cxt);
							}
						}

						o = o.pNext;
					}
				}

				t = t.pNext;
			}*/

			// Restore all of the page permissions and flush the icache.
			o = this.DetoursPendingOperations;

			while (o != null)
			{
				DETOUR_TRAMPOLINEx86 Trampoline = this.ReadStruct<DETOUR_TRAMPOLINEx86>(o.pTrampoline);

				// We don't care if this fails, because the code is still accessible.
				this.ProtectMemory(o.pbTarget, (int)Trampoline.cbRestore, o.dwPerm);
				Win32.FlushInstructionCache(this.hProc, o.pbTarget, Trampoline.cbRestore);

				if (o.fIsRemove && o.pTrampoline != IntPtr.Zero)
				{
					this.detour_free_trampoline(o.pTrampoline, Trampoline);
					o.pTrampoline = IntPtr.Zero;
					freed = true;
				}

				o = o.pNext;
			}

			this.DetoursPendingOperations = null;

			// Free any trampoline regions that are now unused.
			if (freed && !this.DetoursRetainRegions)
				detour_free_unused_trampoline_regions();

			// Make sure the trampoline pages are no longer writable.
			this.detour_runnable_trampoline_regions();

			/*t = this.DetoursPendingThreads;

			// Resume any suspended threads.
			while (t != null)
			{
				// There is nothing we can do if this fails.
				Win32.ResumeThread(t.hThread);

				t = t.pNext;
			}

			this.DetoursPendingThreads = null;*/
			this.DetoursPendingCommit = false;

			ppFailedPointer = this.DetoursppPendingError;

			if (DetoursPendingError != Win32.NO_ERROR)
				throw new Win32Exception((int)DetoursPendingError);
		}

		public void DetourAttach(GCHandle pPointer, IntPtr pDetour)
		{
			this.DetourAttachEx(pPointer, pDetour, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
		}

		private void DetourAttachEx(GCHandle pPointer, IntPtr pDetour, IntPtr ppRealTrampoline, IntPtr ppRealTarget, IntPtr ppRealDetour)
		{
			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();
			this.ThrowIfx64();

			uint error = Win32.NO_ERROR;

			if (ppRealTrampoline != IntPtr.Zero)
				this.WriteIntPtr(ppRealTrampoline, IntPtr.Zero);

			if (ppRealTarget != IntPtr.Zero)
				this.WriteIntPtr(ppRealTarget, IntPtr.Zero);

			if (ppRealDetour != IntPtr.Zero)
				this.WriteIntPtr(ppRealDetour, IntPtr.Zero);

			if (!this.DetoursPendingCommit)
				throw new InvalidOperationException();

			// If any of the pending operations failed, then we don't need to do this.
			if (this.DetoursPendingError != Win32.NO_ERROR)
			{
				Utilities.Log("pending transaction error={0}\n", DetoursPendingError);
				throw new Win32Exception((int)this.DetoursPendingError);
			}

			if (pPointer == null)
			{
				Utilities.Log("pPointer is null\n");
				throw new ArgumentNullException("pPointer");
			}

			IntPtr pbTarget = (IntPtr)pPointer.Target;

			if (pbTarget == IntPtr.Zero)
			{
				error = Win32.ERROR_INVALID_HANDLE;
				this.DetoursPendingError = error;
				this.DetoursppPendingError = pPointer.AddrOfPinnedObject();
				Utilities.Log("*ppPointer is null (ppPointer=%p)\n", pPointer);
				System.Diagnostics.Debugger.Break();
				throw new Win32Exception((int)error);
			}

			IntPtr pTrampoline = IntPtr.Zero;

			pbTarget = this.DetourCodeFromPointer(pbTarget, IntPtr.Zero);
			pDetour = this.DetourCodeFromPointer(pDetour, IntPtr.Zero);

			// Don't follow a jump if its destination is the target function.
			// This happens when the detour does nothing other than call the target.
			if (pDetour == pbTarget)
			{
				if (this.DetoursIgnoreTooSmall)
					goto stop;
				else
				{
					System.Diagnostics.Debugger.Break();
					goto fail;
				}
			}

			if (ppRealTarget != IntPtr.Zero)
				this.WriteIntPtr(ppRealTarget, pbTarget);

			if (ppRealDetour != IntPtr.Zero)
				this.WriteIntPtr(ppRealDetour, pDetour);

			pTrampoline = this.detour_alloc_trampoline(pbTarget);

			if (pTrampoline == IntPtr.Zero)
			{
				error = Win32.ERROR_NOT_ENOUGH_MEMORY;
				System.Diagnostics.Debugger.Break();
				goto fail;
			}

			if (ppRealTrampoline != IntPtr.Zero)
				this.WriteIntPtr(ppRealTrampoline, pTrampoline);

			Utilities.Log("detours: pbTramp={0}, pDetour={1}\n", pTrampoline, pDetour);

			DETOUR_TRAMPOLINEx86 Trampoline = this.ReadStruct<DETOUR_TRAMPOLINEx86>(pTrampoline);
			//memset(pTrampoline->rAlign, 0, sizeof(pTrampoline->rAlign));

			// Determine the number of movable target instructions.
			IntPtr pbSrc = pbTarget;
			IntPtr pbTrampoline = Utilities.OffsetOf<DETOUR_TRAMPOLINEx86>(pTrampoline, "rbCode");
			IntPtr pbPool = pbTrampoline + Trampoline.rbCode.Length;
			uint cbTarget = 0;
			uint cbJump = SIZE_OF_JMP;
			uint nAlign = 0;

			while (cbTarget < cbJump)
			{
				IntPtr pbOp = pbSrc;
				int lExtra;

				Utilities.Log(" DetourCopyInstruction({0},{1})\n", pbTrampoline, pbSrc);
				pbSrc = DetourCopyInstruction(pbTrampoline, ref pbPool, pbSrc, IntPtr.Zero, out lExtra);
				Utilities.Log(" DetourCopyInstruction() = {0} ({1} bytes)\n", pbSrc, (int)(pbSrc.ToInt64() - pbOp.ToInt64()));
				pbTrampoline += (int)((pbSrc.ToInt64() - pbOp.ToInt64()) + lExtra);
				cbTarget = (uint)(pbSrc.ToInt64() - pbTarget.ToInt64());
				Trampoline.rAlign[nAlign].obTarget = (byte)cbTarget;
				Trampoline.rAlign[nAlign].obTrampoline = (byte)(pbTrampoline.ToInt64() - Utilities.OffsetOf<DETOUR_TRAMPOLINEx86>(pTrampoline, "rbCode").ToInt64());

				if (this.detour_does_code_end_function(pbOp))
					break;
			}

			// Consume, but don't duplicate padding if it is needed and available.
			while (cbTarget < cbJump)
			{
				int cFiller = this.detour_is_code_filler(pbSrc);

				if (cFiller == 0)
					break;

				pbSrc += cFiller;
				cbTarget = (uint)(pbSrc.ToInt64() - pbTarget.ToInt64());
			}

#if DEBUG
			Utilities.Log(" detours: rAlign [");

			for (uint n = 0; n < Trampoline.rAlign.Length; n++)
			{
				if (Trampoline.rAlign[n].obTarget == 0 &&
					Trampoline.rAlign[n].obTrampoline == 0)
					break;

				Utilities.Log(" {0}/{1}",
							  Trampoline.rAlign[n].obTarget,
							  Trampoline.rAlign[n].obTrampoline
							  );

			}

			Utilities.Log(" ]\n");
#endif

			if (cbTarget < cbJump || nAlign > Trampoline.rAlign.Length)
			{
				// Too few instructions.

				error = Win32.ERROR_INVALID_BLOCK;

				if (this.DetoursIgnoreTooSmall)
					goto stop;
				else
				{
					System.Diagnostics.Debugger.Break();
					goto fail;
				}
			}

			if (pbTrampoline.ToInt64() > pbPool.ToInt64())
				System.Diagnostics.Debugger.Break();

#if ___FALSE___ // [GalenH]
    if (cbTarget < pbTrampoline - pTrampoline->rbCode) {
        System.Diagnostics.Debugger.Break();
    }
#endif

			Trampoline.cbCode = (byte)(pbTrampoline.ToInt64() - Utilities.OffsetOf<DETOUR_TRAMPOLINEx86>(pTrampoline, "rbCode").ToInt64());
			Trampoline.cbRestore = (byte)cbTarget;
			this.ReadBytes(pbTarget, Trampoline.rbRestore, 0, (int)cbTarget);

			if (cbTarget > Trampoline.rbCode.Length - cbJump)
			{
				// Too many instructions.
				error = Win32.ERROR_INVALID_HANDLE;
				System.Diagnostics.Debugger.Break();
				goto fail;
			}

			Trampoline.pbRemain = pbTarget + (int)cbTarget;
			Trampoline.pbDetour = pDetour;

			IntPtr pbTrampoline2 = Utilities.OffsetOf<DETOUR_TRAMPOLINEx86>(pTrampoline, "rbCode");
			
			pbTrampoline = pbTrampoline2 + (int)Trampoline.cbCode;
			pbTrampoline = this.detour_gen_jmp_immediate(pbTrampoline, Trampoline.pbRemain);
			pbTrampoline = this.detour_gen_brk(pbTrampoline, pbPool);

			Trampoline.rbCode = this.ReadBytes(pbTrampoline2, Trampoline.rbCode.Length);
			this.WriteStruct(pTrampoline, Trampoline);

			MemoryProtection dwOld = this.ProtectMemory(pbTarget, (int)cbTarget, MemoryProtection.PAGE_EXECUTE_READWRITE);

			Utilities.Log("detours: pbTarget={0}: " +
						  "{1}\n",
						  pbTarget,
						  new SoapHexBinary(this.ReadBytes(pbTarget, 12)));
			Utilities.Log("detours: pbTramp ={0}: " +
						  "{1}\n",
						  pTrampoline,
						  new SoapHexBinary(Trampoline.rbCode));

			DetourOperation o = new DetourOperation();
			o.fIsRemove = false;
			o.ppbPointer = pPointer;
			o.pTrampoline = pTrampoline;
			o.pbTarget = pbTarget;
			o.dwPerm = dwOld;
			o.pNext = this.DetoursPendingOperations;
			this.DetoursPendingOperations = o;
			return;

		fail:
			this.DetoursPendingError = error;
		stop:
			if (pTrampoline != IntPtr.Zero)
			{
				this.detour_free_trampoline(pTrampoline, this.ReadStruct<DETOUR_TRAMPOLINEx86>(pTrampoline));
				pTrampoline = IntPtr.Zero;

				if (ppRealTrampoline != IntPtr.Zero)
					this.WriteIntPtr(ppRealTrampoline, IntPtr.Zero);
			}

			this.DetoursppPendingError = (IntPtr)pPointer.Target;
			throw new Win32Exception((int)error);
		}

		public void DetourDetach()
		{
			this.ThrowIfDisposed();
			this.ThrowIfNoHandle();
			this.ThrowIfx64();

			throw new NotImplementedException();
		}

		public void DetourAttachAndCommit(ref IntPtr pPointer, IntPtr pDetour)
		{
			GCHandle ppPointer = GCHandle.Alloc(pPointer, GCHandleType.Pinned);

			try
			{
				this.DetourTransactionBegin();
				this.DetourAttach(ppPointer, pDetour);
				this.DetourTransactionCommit();

				pPointer = (IntPtr)ppPointer.Target;
			}
			finally
			{
				ppPointer.Free();
			}
		}

		public void DetourAttachAndCommit(ref IntPtr pPointer1, IntPtr pDetour1, ref IntPtr pPointer2, IntPtr pDetour2)
		{
			GCHandle ppPointer1 = GCHandle.Alloc(pPointer1, GCHandleType.Pinned);
			GCHandle ppPointer2 = GCHandle.Alloc(pPointer2, GCHandleType.Pinned);

			try
			{
				this.DetourTransactionBegin();
				this.DetourAttach(ppPointer1, pDetour1);
				this.DetourAttach(ppPointer2, pDetour2);
				this.DetourTransactionCommit();

				pPointer1 = (IntPtr)ppPointer1.Target;
				pPointer2 = (IntPtr)ppPointer2.Target;
			}
			finally
			{
				ppPointer1.Free();
				ppPointer2.Free();
			}
		}

		public void DetourAttachAndCommit(ref IntPtr pPointer1, IntPtr pDetour1, ref IntPtr pPointer2, IntPtr pDetour2, ref IntPtr pPointer3, IntPtr pDetour3)
		{
			GCHandle ppPointer1 = GCHandle.Alloc(pPointer1, GCHandleType.Pinned);
			GCHandle ppPointer2 = GCHandle.Alloc(pPointer2, GCHandleType.Pinned);
			GCHandle ppPointer3 = GCHandle.Alloc(pPointer3, GCHandleType.Pinned);

			try
			{
				this.DetourTransactionBegin();
				this.DetourAttach(ppPointer1, pDetour1);
				this.DetourAttach(ppPointer2, pDetour2);
				this.DetourAttach(ppPointer3, pDetour3);
				this.DetourTransactionCommit();

				pPointer1 = (IntPtr)ppPointer1.Target;
				pPointer2 = (IntPtr)ppPointer2.Target;
				pPointer3 = (IntPtr)ppPointer3.Target;
			}
			finally
			{
				ppPointer1.Free();
				ppPointer2.Free();
				ppPointer3.Free();
			}
		}

		public void DetourAttachAndCommit(ref IntPtr pPointer1, IntPtr pDetour1, ref IntPtr pPointer2, IntPtr pDetour2, ref IntPtr pPointer3, IntPtr pDetour3, ref IntPtr pPointer4, IntPtr pDetour4)
		{
			GCHandle ppPointer1 = GCHandle.Alloc(pPointer1, GCHandleType.Pinned);
			GCHandle ppPointer2 = GCHandle.Alloc(pPointer2, GCHandleType.Pinned);
			GCHandle ppPointer3 = GCHandle.Alloc(pPointer3, GCHandleType.Pinned);
			GCHandle ppPointer4 = GCHandle.Alloc(pPointer4, GCHandleType.Pinned);

			try
			{
				this.DetourTransactionBegin();
				this.DetourAttach(ppPointer1, pDetour1);
				this.DetourAttach(ppPointer2, pDetour2);
				this.DetourAttach(ppPointer3, pDetour3);
				this.DetourAttach(ppPointer4, pDetour4);
				this.DetourTransactionCommit();

				pPointer1 = (IntPtr)ppPointer1.Target;
				pPointer2 = (IntPtr)ppPointer2.Target;
				pPointer3 = (IntPtr)ppPointer3.Target;
				pPointer4 = (IntPtr)ppPointer4.Target;
			}
			finally
			{
				ppPointer1.Free();
				ppPointer2.Free();
				ppPointer3.Free();
				ppPointer4.Free();
			}
		}

		public void DetourAttachAndCommit(ref IntPtr pPointer1, IntPtr pDetour1, ref IntPtr pPointer2, IntPtr pDetour2, ref IntPtr pPointer3, IntPtr pDetour3, ref IntPtr pPointer4, IntPtr pDetour4, ref IntPtr pPointer5, IntPtr pDetour5)
		{
			GCHandle ppPointer1 = GCHandle.Alloc(pPointer1, GCHandleType.Pinned);
			GCHandle ppPointer2 = GCHandle.Alloc(pPointer2, GCHandleType.Pinned);
			GCHandle ppPointer3 = GCHandle.Alloc(pPointer3, GCHandleType.Pinned);
			GCHandle ppPointer4 = GCHandle.Alloc(pPointer4, GCHandleType.Pinned);
			GCHandle ppPointer5 = GCHandle.Alloc(pPointer5, GCHandleType.Pinned);

			try
			{
				this.DetourTransactionBegin();
				this.DetourAttach(ppPointer1, pDetour1);
				this.DetourAttach(ppPointer2, pDetour2);
				this.DetourAttach(ppPointer3, pDetour3);
				this.DetourAttach(ppPointer4, pDetour4);
				this.DetourAttach(ppPointer5, pDetour5);
				this.DetourTransactionCommit();

				pPointer1 = (IntPtr)ppPointer1.Target;
				pPointer2 = (IntPtr)ppPointer2.Target;
				pPointer3 = (IntPtr)ppPointer3.Target;
				pPointer4 = (IntPtr)ppPointer4.Target;
				pPointer5 = (IntPtr)ppPointer5.Target;
			}
			finally
			{
				ppPointer1.Free();
				ppPointer2.Free();
				ppPointer3.Free();
				ppPointer4.Free();
				ppPointer5.Free();
			}
		}

		public void DetourAttachAndCommit(ref IntPtr pPointer1, IntPtr pDetour1, ref IntPtr pPointer2, IntPtr pDetour2, ref IntPtr pPointer3, IntPtr pDetour3, ref IntPtr pPointer4, IntPtr pDetour4, ref IntPtr pPointer5, IntPtr pDetour5, ref IntPtr pPointer6, IntPtr pDetour6)
		{
			GCHandle ppPointer1 = GCHandle.Alloc(pPointer1, GCHandleType.Pinned);
			GCHandle ppPointer2 = GCHandle.Alloc(pPointer2, GCHandleType.Pinned);
			GCHandle ppPointer3 = GCHandle.Alloc(pPointer3, GCHandleType.Pinned);
			GCHandle ppPointer4 = GCHandle.Alloc(pPointer4, GCHandleType.Pinned);
			GCHandle ppPointer5 = GCHandle.Alloc(pPointer5, GCHandleType.Pinned);
			GCHandle ppPointer6 = GCHandle.Alloc(pPointer6, GCHandleType.Pinned);

			try
			{
				this.DetourTransactionBegin();
				this.DetourAttach(ppPointer1, pDetour1);
				this.DetourAttach(ppPointer2, pDetour2);
				this.DetourAttach(ppPointer3, pDetour3);
				this.DetourAttach(ppPointer4, pDetour4);
				this.DetourAttach(ppPointer5, pDetour5);
				this.DetourAttach(ppPointer6, pDetour6);
				this.DetourTransactionCommit();

				pPointer1 = (IntPtr)ppPointer1.Target;
				pPointer2 = (IntPtr)ppPointer2.Target;
				pPointer3 = (IntPtr)ppPointer3.Target;
				pPointer4 = (IntPtr)ppPointer4.Target;
				pPointer5 = (IntPtr)ppPointer5.Target;
				pPointer6 = (IntPtr)ppPointer6.Target;
			}
			finally
			{
				ppPointer1.Free();
				ppPointer2.Free();
				ppPointer3.Free();
				ppPointer4.Free();
				ppPointer5.Free();
				ppPointer6.Free();
			}
		}

		public void DetourAttachAndCommit(ref IntPtr pPointer1, IntPtr pDetour1, ref IntPtr pPointer2, IntPtr pDetour2, ref IntPtr pPointer3, IntPtr pDetour3, ref IntPtr pPointer4, IntPtr pDetour4, ref IntPtr pPointer5, IntPtr pDetour5, ref IntPtr pPointer6, IntPtr pDetour6, ref IntPtr pPointer7, IntPtr pDetour7)
		{
			GCHandle ppPointer1 = GCHandle.Alloc(pPointer1, GCHandleType.Pinned);
			GCHandle ppPointer2 = GCHandle.Alloc(pPointer2, GCHandleType.Pinned);
			GCHandle ppPointer3 = GCHandle.Alloc(pPointer3, GCHandleType.Pinned);
			GCHandle ppPointer4 = GCHandle.Alloc(pPointer4, GCHandleType.Pinned);
			GCHandle ppPointer5 = GCHandle.Alloc(pPointer5, GCHandleType.Pinned);
			GCHandle ppPointer6 = GCHandle.Alloc(pPointer6, GCHandleType.Pinned);
			GCHandle ppPointer7 = GCHandle.Alloc(pPointer7, GCHandleType.Pinned);

			try
			{
				this.DetourTransactionBegin();
				this.DetourAttach(ppPointer1, pDetour1);
				this.DetourAttach(ppPointer2, pDetour2);
				this.DetourAttach(ppPointer3, pDetour3);
				this.DetourAttach(ppPointer4, pDetour4);
				this.DetourAttach(ppPointer5, pDetour5);
				this.DetourAttach(ppPointer6, pDetour6);
				this.DetourAttach(ppPointer7, pDetour7);
				this.DetourTransactionCommit();

				pPointer1 = (IntPtr)ppPointer1.Target;
				pPointer2 = (IntPtr)ppPointer2.Target;
				pPointer3 = (IntPtr)ppPointer3.Target;
				pPointer4 = (IntPtr)ppPointer4.Target;
				pPointer5 = (IntPtr)ppPointer5.Target;
				pPointer6 = (IntPtr)ppPointer6.Target;
				pPointer7 = (IntPtr)ppPointer7.Target;
			}
			finally
			{
				ppPointer1.Free();
				ppPointer2.Free();
				ppPointer3.Free();
				ppPointer4.Free();
				ppPointer5.Free();
				ppPointer6.Free();
				ppPointer7.Free();
			}
		}
	}
}