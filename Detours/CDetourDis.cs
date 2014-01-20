/*
 * 
 */
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Com.Xenthrax.DllInjector
{
	public partial class DllInjector : IDisposable
	{
		private sealed class CDetourDis
		{
			private delegate IntPtr COPYFUNC(ref COPYENTRY pEntry, IntPtr pbDst, IntPtr pbSrc);

			private enum Flags : byte
			{
				DYNAMIC = 0x1,
				ADDRESS = 0x2,
				NOENLARGE = 0x4,
				RAX = 0x8,

				SIB = 0x10,
				RIP = 0x20,
				NOTSIB = 0x0f
			}

			private sealed class COPYENTRY
			{
				public COPYENTRY() { }

				public COPYENTRY(uint nOpcode, COPYENTRY ent)
				{
					this.nOpcode = nOpcode;
					this.nFixedSize = ent.nFixedSize;
					this.nFixedSize16 = ent.nFixedSize16;
					this.nModOffset = ent.nModOffset;
					this.nRelOffset = ent.nRelOffset;
					this.nTargetBack = ent.nTargetBack;
					this.nFlagBits = ent.nFlagBits;
					this._Copy = ent._Copy;
				}

				public COPYENTRY(uint nFixedSize, uint nFixedSize16, uint nModOffset, uint nRelOffset, uint nTargetBack, Flags nFlagBits, string Copy)
				{
					this.nFixedSize = nFixedSize;
					this.nFixedSize16 = nFixedSize16;
					this.nModOffset = nModOffset;
					this.nRelOffset = nRelOffset;
					this.nTargetBack = nTargetBack;
					this.nFlagBits = nFlagBits;
					this._Copy = (Copy == null)
						? null
						: typeof(CDetourDis).GetMethod(Copy, BindingFlags.Instance | BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Public);
				}

				// Opcode
				public uint nOpcode;
				// Fixed size of opcode
				public uint nFixedSize;
				// Fixed size when 16 bit operand
				public uint nFixedSize16;
				// Offset to mod/rm byte (0=none)
				public uint nModOffset;
				// Offset to relative target.
				public uint nRelOffset;
				// Offset back to absolute or rip target
				public uint nTargetBack;
				// Flags for DYNAMIC, etc.
				public Flags nFlagBits;
				// Function pointer.
				internal MethodInfo _Copy;

				public IntPtr Copy(CDetourDis This, ref COPYENTRY a, IntPtr b, IntPtr c)
				{
					object[] Params = new object[] { a, b, c };
					object value = this._Copy.Invoke(This, Params);
					a = (COPYENTRY)Params[0];
					return (IntPtr)value;
				}
			}

			private static readonly IntPtr DETOUR_INSTRUCTION_TARGET_NONE = IntPtr.Zero;
			private static readonly IntPtr DETOUR_INSTRUCTION_TARGET_DYNAMIC = new IntPtr(-1);

			private static readonly COPYENTRY ENTRY_CopyBytes1 = new COPYENTRY(1, 1, 0, 0, 0, 0, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes1Dynamic = new COPYENTRY(1, 1, 0, 0, 0, Flags.DYNAMIC, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes2 = new COPYENTRY(2, 2, 0, 0, 0, 0, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes2Jump = new COPYENTRY(2, 2, 0, 1, 0, 0, "CopyBytesJump");
			private static readonly COPYENTRY ENTRY_CopyBytes2CantJump = new COPYENTRY(2, 2, 0, 1, 0, Flags.NOENLARGE, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes2Dynamic = new COPYENTRY(2, 2, 0, 0, 0, Flags.DYNAMIC, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes3 = new COPYENTRY(3, 3, 0, 0, 0, 0, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes3Dynamic = new COPYENTRY(3, 3, 0, 0, 0, Flags.DYNAMIC, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes3Or5 = new COPYENTRY(5, 3, 0, 0, 0, 0, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes3Or5Rax = new COPYENTRY(5, 3, 0, 0, 0, Flags.RAX, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes3Or5Target = new COPYENTRY(5, 3, 0, 1, 0, 0, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes5Or7Dynamic = new COPYENTRY(7, 5, 0, 0, 0, Flags.DYNAMIC, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes3Or5Address = new COPYENTRY(5, 3, 0, 0, 0, Flags.ADDRESS, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes4 = new COPYENTRY(4, 4, 0, 0, 0, 0, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes5 = new COPYENTRY(5, 5, 0, 0, 0, 0, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes7 = new COPYENTRY(7, 7, 0, 0, 0, 0, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes2Mod = new COPYENTRY(2, 2, 1, 0, 0, 0, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes2Mod1 = new COPYENTRY(3, 3, 1, 0, 1, 0, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes2ModOperand = new COPYENTRY(6, 4, 1, 0, 4, 0, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytes3Mod = new COPYENTRY(3, 3, 2, 0, 0, 0, "CopyBytes");
			private static readonly COPYENTRY ENTRY_CopyBytesPrefix = new COPYENTRY(1, 1, 0, 0, 0, 0, "CopyBytesPrefix");
			private static readonly COPYENTRY ENTRY_CopyBytesRax = new COPYENTRY(1, 1, 0, 0, 0, 0, "CopyBytesRax");
			private static readonly COPYENTRY ENTRY_Copy0F = new COPYENTRY(1, 1, 0, 0, 0, 0, "Copy0F");
			private static readonly COPYENTRY ENTRY_Copy66 = new COPYENTRY(1, 1, 0, 0, 0, 0, "Copy66");
			private static readonly COPYENTRY ENTRY_Copy67 = new COPYENTRY(1, 1, 0, 0, 0, 0, "Copy67");
			private static readonly COPYENTRY ENTRY_CopyF6 = new COPYENTRY(0, 0, 0, 0, 0, 0, "CopyF6");
			private static readonly COPYENTRY ENTRY_CopyF7 = new COPYENTRY(0, 0, 0, 0, 0, 0, "CopyF7");
			private static readonly COPYENTRY ENTRY_CopyFF = new COPYENTRY(0, 0, 0, 0, 0, 0, "CopyFF");
			private static readonly COPYENTRY ENTRY_Invalid = new COPYENTRY(1, 1, 0, 0, 0, 0, "Invalid");
			private static readonly COPYENTRY ENTRY_End = new COPYENTRY(0, 0, 0, 0, 0, 0, null);

			private static readonly COPYENTRY[] s_rceCopyTable = new COPYENTRY[257]
			{
				new COPYENTRY(0x00, ENTRY_CopyBytes2Mod),                      // ADD /r
				new COPYENTRY(0x01, ENTRY_CopyBytes2Mod),                      // ADD /r
				new COPYENTRY(0x02, ENTRY_CopyBytes2Mod),                      // ADD /r
				new COPYENTRY(0x03, ENTRY_CopyBytes2Mod),                      // ADD /r
				new COPYENTRY(0x04, ENTRY_CopyBytes2),                         // ADD ib
				new COPYENTRY(0x05, ENTRY_CopyBytes3Or5),                      // ADD iw
				new COPYENTRY(0x06, ENTRY_CopyBytes1),                         // PUSH
				new COPYENTRY(0x07, ENTRY_CopyBytes1),                         // POP
				new COPYENTRY(0x08, ENTRY_CopyBytes2Mod),                      // OR /r
				new COPYENTRY(0x09, ENTRY_CopyBytes2Mod),                      // OR /r
				new COPYENTRY(0x0A, ENTRY_CopyBytes2Mod),                      // OR /r
				new COPYENTRY(0x0B, ENTRY_CopyBytes2Mod),                      // OR /r
				new COPYENTRY(0x0C, ENTRY_CopyBytes2),                         // OR ib
				new COPYENTRY(0x0D, ENTRY_CopyBytes3Or5),                      // OR iw
				new COPYENTRY(0x0E, ENTRY_CopyBytes1),                         // PUSH
				new COPYENTRY(0x0F, ENTRY_Copy0F),                             // Extension Ops
				new COPYENTRY(0x10, ENTRY_CopyBytes2Mod),                      // ADC /r
				new COPYENTRY(0x11, ENTRY_CopyBytes2Mod),                      // ADC /r
				new COPYENTRY(0x12, ENTRY_CopyBytes2Mod),                      // ADC /r
				new COPYENTRY(0x13, ENTRY_CopyBytes2Mod),                      // ADC /r
				new COPYENTRY(0x14, ENTRY_CopyBytes2),                         // ADC ib
				new COPYENTRY(0x15, ENTRY_CopyBytes3Or5),                      // ADC id
				new COPYENTRY(0x16, ENTRY_CopyBytes1),                         // PUSH
				new COPYENTRY(0x17, ENTRY_CopyBytes1),                         // POP
				new COPYENTRY(0x18, ENTRY_CopyBytes2Mod),                      // SBB /r
				new COPYENTRY(0x19, ENTRY_CopyBytes2Mod),                      // SBB /r
				new COPYENTRY(0x1A, ENTRY_CopyBytes2Mod),                      // SBB /r
				new COPYENTRY(0x1B, ENTRY_CopyBytes2Mod),                      // SBB /r
				new COPYENTRY(0x1C, ENTRY_CopyBytes2),                         // SBB ib
				new COPYENTRY(0x1D, ENTRY_CopyBytes3Or5),                      // SBB id
				new COPYENTRY(0x1E, ENTRY_CopyBytes1),                         // PUSH
				new COPYENTRY(0x1F, ENTRY_CopyBytes1),                         // POP
				new COPYENTRY(0x20, ENTRY_CopyBytes2Mod),                      // AND /r
				new COPYENTRY(0x21, ENTRY_CopyBytes2Mod),                      // AND /r
				new COPYENTRY(0x22, ENTRY_CopyBytes2Mod),                      // AND /r
				new COPYENTRY(0x23, ENTRY_CopyBytes2Mod),                      // AND /r
				new COPYENTRY(0x24, ENTRY_CopyBytes2),                         // AND ib
				new COPYENTRY(0x25, ENTRY_CopyBytes3Or5),                      // AND id
				new COPYENTRY(0x26, ENTRY_CopyBytesPrefix),                    // ES prefix
				new COPYENTRY(0x27, ENTRY_CopyBytes1),                         // DAA
				new COPYENTRY(0x28, ENTRY_CopyBytes2Mod),                      // SUB /r
				new COPYENTRY(0x29, ENTRY_CopyBytes2Mod),                      // SUB /r
				new COPYENTRY(0x2A, ENTRY_CopyBytes2Mod),                      // SUB /r
				new COPYENTRY(0x2B, ENTRY_CopyBytes2Mod),                      // SUB /r
				new COPYENTRY(0x2C, ENTRY_CopyBytes2),                         // SUB ib
				new COPYENTRY(0x2D, ENTRY_CopyBytes3Or5),                      // SUB id
				new COPYENTRY(0x2E, ENTRY_CopyBytesPrefix),                    // CS prefix
				new COPYENTRY(0x2F, ENTRY_CopyBytes1),                         // DAS
				new COPYENTRY(0x30, ENTRY_CopyBytes2Mod),                      // XOR /r
				new COPYENTRY(0x31, ENTRY_CopyBytes2Mod),                      // XOR /r
				new COPYENTRY(0x32, ENTRY_CopyBytes2Mod),                      // XOR /r
				new COPYENTRY(0x33, ENTRY_CopyBytes2Mod),                      // XOR /r
				new COPYENTRY(0x34, ENTRY_CopyBytes2),                         // XOR ib
				new COPYENTRY(0x35, ENTRY_CopyBytes3Or5),                      // XOR id
				new COPYENTRY(0x36, ENTRY_CopyBytesPrefix),                    // SS prefix
				new COPYENTRY(0x37, ENTRY_CopyBytes1),                         // AAA
				new COPYENTRY(0x38, ENTRY_CopyBytes2Mod),                      // CMP /r
				new COPYENTRY(0x39, ENTRY_CopyBytes2Mod),                      // CMP /r
				new COPYENTRY(0x3A, ENTRY_CopyBytes2Mod),                      // CMP /r
				new COPYENTRY(0x3B, ENTRY_CopyBytes2Mod),                      // CMP /r
				new COPYENTRY(0x3C, ENTRY_CopyBytes2),                         // CMP ib
				new COPYENTRY(0x3D, ENTRY_CopyBytes3Or5),                      // CMP id
				new COPYENTRY(0x3E, ENTRY_CopyBytesPrefix),                    // DS prefix
				new COPYENTRY(0x3F, ENTRY_CopyBytes1),                         // AAS
				new COPYENTRY(0x40, ENTRY_CopyBytes1),                         // INC
				new COPYENTRY(0x41, ENTRY_CopyBytes1),                         // INC
				new COPYENTRY(0x42, ENTRY_CopyBytes1),                         // INC
				new COPYENTRY(0x43, ENTRY_CopyBytes1),                         // INC
				new COPYENTRY(0x44, ENTRY_CopyBytes1),                         // INC
				new COPYENTRY(0x45, ENTRY_CopyBytes1),                         // INC
				new COPYENTRY(0x46, ENTRY_CopyBytes1),                         // INC
				new COPYENTRY(0x47, ENTRY_CopyBytes1),                         // INC
				new COPYENTRY(0x48, ENTRY_CopyBytes1),                         // DEC
				new COPYENTRY(0x49, ENTRY_CopyBytes1),                         // DEC
				new COPYENTRY(0x4A, ENTRY_CopyBytes1),                         // DEC
				new COPYENTRY(0x4B, ENTRY_CopyBytes1),                         // DEC
				new COPYENTRY(0x4C, ENTRY_CopyBytes1),                         // DEC
				new COPYENTRY(0x4D, ENTRY_CopyBytes1),                         // DEC
				new COPYENTRY(0x4E, ENTRY_CopyBytes1),                         // DEC
				new COPYENTRY(0x4F, ENTRY_CopyBytes1),                         // DEC
				new COPYENTRY(0x50, ENTRY_CopyBytes1),                         // PUSH
				new COPYENTRY(0x51, ENTRY_CopyBytes1),                         // PUSH
				new COPYENTRY(0x52, ENTRY_CopyBytes1),                         // PUSH
				new COPYENTRY(0x53, ENTRY_CopyBytes1),                         // PUSH
				new COPYENTRY(0x54, ENTRY_CopyBytes1),                         // PUSH
				new COPYENTRY(0x55, ENTRY_CopyBytes1),                         // PUSH
				new COPYENTRY(0x56, ENTRY_CopyBytes1),                         // PUSH
				new COPYENTRY(0x57, ENTRY_CopyBytes1),                         // PUSH
				new COPYENTRY(0x58, ENTRY_CopyBytes1),                         // POP
				new COPYENTRY(0x59, ENTRY_CopyBytes1),                         // POP
				new COPYENTRY(0x5A, ENTRY_CopyBytes1),                         // POP
				new COPYENTRY(0x5B, ENTRY_CopyBytes1),                         // POP
				new COPYENTRY(0x5C, ENTRY_CopyBytes1),                         // POP
				new COPYENTRY(0x5D, ENTRY_CopyBytes1),                         // POP
				new COPYENTRY(0x5E, ENTRY_CopyBytes1),                         // POP
				new COPYENTRY(0x5F, ENTRY_CopyBytes1),                         // POP
				new COPYENTRY(0x60, ENTRY_CopyBytes1),                         // PUSHAD
				new COPYENTRY(0x61, ENTRY_CopyBytes1),                         // POPAD
				new COPYENTRY(0x62, ENTRY_CopyBytes2Mod),                      // BOUND /r
				new COPYENTRY(0x63, ENTRY_CopyBytes2Mod),                      // ARPL /r
				new COPYENTRY(0x64, ENTRY_CopyBytesPrefix),                    // FS prefix
				new COPYENTRY(0x65, ENTRY_CopyBytesPrefix),                    // GS prefix
				new COPYENTRY(0x66, ENTRY_Copy66),                             // Operand Prefix
				new COPYENTRY(0x67, ENTRY_Copy67),                             // Address Prefix
				new COPYENTRY(0x68, ENTRY_CopyBytes3Or5),                      // PUSH
				new COPYENTRY(0x69, ENTRY_CopyBytes2ModOperand),               //
				new COPYENTRY(0x6A, ENTRY_CopyBytes2),                         // PUSH
				new COPYENTRY(0x6B, ENTRY_CopyBytes2Mod1),                     // IMUL /r ib
				new COPYENTRY(0x6C, ENTRY_CopyBytes1),                         // INS
				new COPYENTRY(0x6D, ENTRY_CopyBytes1),                         // INS
				new COPYENTRY(0x6E, ENTRY_CopyBytes1),                         // OUTS/OUTSB
				new COPYENTRY(0x6F, ENTRY_CopyBytes1),                         // OUTS/OUTSW
				new COPYENTRY(0x70, ENTRY_CopyBytes2Jump),                     // JO           // 0f80
				new COPYENTRY(0x71, ENTRY_CopyBytes2Jump),                     // JNO          // 0f81
				new COPYENTRY(0x72, ENTRY_CopyBytes2Jump),                     // JB/JC/JNAE   // 0f82
				new COPYENTRY(0x73, ENTRY_CopyBytes2Jump),                     // JAE/JNB/JNC  // 0f83
				new COPYENTRY(0x74, ENTRY_CopyBytes2Jump),                     // JE/JZ        // 0f84
				new COPYENTRY(0x75, ENTRY_CopyBytes2Jump),                     // JNE/JNZ      // 0f85
				new COPYENTRY(0x76, ENTRY_CopyBytes2Jump),                     // JBE/JNA      // 0f86
				new COPYENTRY(0x77, ENTRY_CopyBytes2Jump),                     // JA/JNBE      // 0f87
				new COPYENTRY(0x78, ENTRY_CopyBytes2Jump),                     // JS           // 0f88
				new COPYENTRY(0x79, ENTRY_CopyBytes2Jump),                     // JNS          // 0f89
				new COPYENTRY(0x7A, ENTRY_CopyBytes2Jump),                     // JP/JPE       // 0f8a
				new COPYENTRY(0x7B, ENTRY_CopyBytes2Jump),                     // JNP/JPO      // 0f8b
				new COPYENTRY(0x7C, ENTRY_CopyBytes2Jump),                     // JL/JNGE      // 0f8c
				new COPYENTRY(0x7D, ENTRY_CopyBytes2Jump),                     // JGE/JNL      // 0f8d
				new COPYENTRY(0x7E, ENTRY_CopyBytes2Jump),                     // JLE/JNG      // 0f8e
				new COPYENTRY(0x7F, ENTRY_CopyBytes2Jump),                     // JG/JNLE      // 0f8f
				new COPYENTRY(0x80, ENTRY_CopyBytes2Mod1),                     // ADC/2 ib, etc.s
				new COPYENTRY(0x81, ENTRY_CopyBytes2ModOperand),               //
				new COPYENTRY(0x82, ENTRY_CopyBytes2),                         // MOV al,x
				new COPYENTRY(0x83, ENTRY_CopyBytes2Mod1),                     // ADC/2 ib, etc.
				new COPYENTRY(0x84, ENTRY_CopyBytes2Mod),                      // TEST /r
				new COPYENTRY(0x85, ENTRY_CopyBytes2Mod),                      // TEST /r
				new COPYENTRY(0x86, ENTRY_CopyBytes2Mod),                      // XCHG /r @todo
				new COPYENTRY(0x87, ENTRY_CopyBytes2Mod),                      // XCHG /r @todo
				new COPYENTRY(0x88, ENTRY_CopyBytes2Mod),                      // MOV /r
				new COPYENTRY(0x89, ENTRY_CopyBytes2Mod),                      // MOV /r
				new COPYENTRY(0x8A, ENTRY_CopyBytes2Mod),                      // MOV /r
				new COPYENTRY(0x8B, ENTRY_CopyBytes2Mod),                      // MOV /r
				new COPYENTRY(0x8C, ENTRY_CopyBytes2Mod),                      // MOV /r
				new COPYENTRY(0x8D, ENTRY_CopyBytes2Mod),                      // LEA /r
				new COPYENTRY(0x8E, ENTRY_CopyBytes2Mod),                      // MOV /r
				new COPYENTRY(0x8F, ENTRY_CopyBytes2Mod),                      // POP /0
				new COPYENTRY(0x90, ENTRY_CopyBytes1),                         // NOP
				new COPYENTRY(0x91, ENTRY_CopyBytes1),                         // XCHG
				new COPYENTRY(0x92, ENTRY_CopyBytes1),                         // XCHG
				new COPYENTRY(0x93, ENTRY_CopyBytes1),                         // XCHG
				new COPYENTRY(0x94, ENTRY_CopyBytes1),                         // XCHG
				new COPYENTRY(0x95, ENTRY_CopyBytes1),                         // XCHG
				new COPYENTRY(0x96, ENTRY_CopyBytes1),                         // XCHG
				new COPYENTRY(0x97, ENTRY_CopyBytes1),                         // XCHG
				new COPYENTRY(0x98, ENTRY_CopyBytes1),                         // CWDE
				new COPYENTRY(0x99, ENTRY_CopyBytes1),                         // CDQ
				new COPYENTRY(0x9A, ENTRY_CopyBytes5Or7Dynamic),               // CALL cp
				new COPYENTRY(0x9B, ENTRY_CopyBytes1),                         // WAIT/FWAIT
				new COPYENTRY(0x9C, ENTRY_CopyBytes1),                         // PUSHFD
				new COPYENTRY(0x9D, ENTRY_CopyBytes1),                         // POPFD
				new COPYENTRY(0x9E, ENTRY_CopyBytes1),                         // SAHF
				new COPYENTRY(0x9F, ENTRY_CopyBytes1),                         // LAHF
				new COPYENTRY(0xA0, ENTRY_CopyBytes3Or5Address),               // MOV
				new COPYENTRY(0xA1, ENTRY_CopyBytes3Or5Address),               // MOV
				new COPYENTRY(0xA2, ENTRY_CopyBytes3Or5Address),               // MOV
				new COPYENTRY(0xA3, ENTRY_CopyBytes3Or5Address),               // MOV
				new COPYENTRY(0xA4, ENTRY_CopyBytes1),                         // MOVS
				new COPYENTRY(0xA5, ENTRY_CopyBytes1),                         // MOVS/MOVSD
				new COPYENTRY(0xA6, ENTRY_CopyBytes1),                         // CMPS/CMPSB
				new COPYENTRY(0xA7, ENTRY_CopyBytes1),                         // CMPS/CMPSW
				new COPYENTRY(0xA8, ENTRY_CopyBytes2),                         // TEST
				new COPYENTRY(0xA9, ENTRY_CopyBytes3Or5),                      // TEST
				new COPYENTRY(0xAA, ENTRY_CopyBytes1),                         // STOS/STOSB
				new COPYENTRY(0xAB, ENTRY_CopyBytes1),                         // STOS/STOSW
				new COPYENTRY(0xAC, ENTRY_CopyBytes1),                         // LODS/LODSB
				new COPYENTRY(0xAD, ENTRY_CopyBytes1),                         // LODS/LODSW
				new COPYENTRY(0xAE, ENTRY_CopyBytes1),                         // SCAS/SCASB
				new COPYENTRY(0xAF, ENTRY_CopyBytes1),                         // SCAS/SCASD
				new COPYENTRY(0xB0, ENTRY_CopyBytes2),                         // MOV B0+rb
				new COPYENTRY(0xB1, ENTRY_CopyBytes2),                         // MOV B0+rb
				new COPYENTRY(0xB2, ENTRY_CopyBytes2),                         // MOV B0+rb
				new COPYENTRY(0xB3, ENTRY_CopyBytes2),                         // MOV B0+rb
				new COPYENTRY(0xB4, ENTRY_CopyBytes2),                         // MOV B0+rb
				new COPYENTRY(0xB5, ENTRY_CopyBytes2),                         // MOV B0+rb
				new COPYENTRY(0xB6, ENTRY_CopyBytes2),                         // MOV B0+rb
				new COPYENTRY(0xB7, ENTRY_CopyBytes2),                         // MOV B0+rb
				new COPYENTRY(0xB8, ENTRY_CopyBytes3Or5Rax),                   // MOV B8+rb
				new COPYENTRY(0xB9, ENTRY_CopyBytes3Or5),                      // MOV B8+rb
				new COPYENTRY(0xBA, ENTRY_CopyBytes3Or5),                      // MOV B8+rb
				new COPYENTRY(0xBB, ENTRY_CopyBytes3Or5),                      // MOV B8+rb
				new COPYENTRY(0xBC, ENTRY_CopyBytes3Or5),                      // MOV B8+rb
				new COPYENTRY(0xBD, ENTRY_CopyBytes3Or5),                      // MOV B8+rb
				new COPYENTRY(0xBE, ENTRY_CopyBytes3Or5),                      // MOV B8+rb
				new COPYENTRY(0xBF, ENTRY_CopyBytes3Or5),                      // MOV B8+rb
				new COPYENTRY(0xC0, ENTRY_CopyBytes2Mod1),                     // RCL/2 ib, etc.
				new COPYENTRY(0xC1, ENTRY_CopyBytes2Mod1),                     // RCL/2 ib, etc.
				new COPYENTRY(0xC2, ENTRY_CopyBytes3),                         // RET
				new COPYENTRY(0xC3, ENTRY_CopyBytes1),                         // RET
				new COPYENTRY(0xC4, ENTRY_CopyBytes2Mod),                      // LES
				new COPYENTRY(0xC5, ENTRY_CopyBytes2Mod),                      // LDS
				new COPYENTRY(0xC6, ENTRY_CopyBytes2Mod1),                     // MOV
				new COPYENTRY(0xC7, ENTRY_CopyBytes2ModOperand),               // MOV
				new COPYENTRY(0xC8, ENTRY_CopyBytes4),                         // ENTER
				new COPYENTRY(0xC9, ENTRY_CopyBytes1),                         // LEAVE
				new COPYENTRY(0xCA, ENTRY_CopyBytes3Dynamic),                  // RET
				new COPYENTRY(0xCB, ENTRY_CopyBytes1Dynamic),                  // RET
				new COPYENTRY(0xCC, ENTRY_CopyBytes1Dynamic),                  // INT 3
				new COPYENTRY(0xCD, ENTRY_CopyBytes2Dynamic),                  // INT ib
				new COPYENTRY(0xCE, ENTRY_CopyBytes1Dynamic),                  // INTO
				new COPYENTRY(0xCF, ENTRY_CopyBytes1Dynamic),                  // IRET
				new COPYENTRY(0xD0, ENTRY_CopyBytes2Mod),                      // RCL/2, etc.
				new COPYENTRY(0xD1, ENTRY_CopyBytes2Mod),                      // RCL/2, etc.
				new COPYENTRY(0xD2, ENTRY_CopyBytes2Mod),                      // RCL/2, etc.
				new COPYENTRY(0xD3, ENTRY_CopyBytes2Mod),                      // RCL/2, etc.
				new COPYENTRY(0xD4, ENTRY_CopyBytes2),                         // AAM
				new COPYENTRY(0xD5, ENTRY_CopyBytes2),                         // AAD
				new COPYENTRY(0xD6, ENTRY_Invalid),                            //
				new COPYENTRY(0xD7, ENTRY_CopyBytes1),                         // XLAT/XLATB
				new COPYENTRY(0xD8, ENTRY_CopyBytes2Mod),                      // FADD, etc.
				new COPYENTRY(0xD9, ENTRY_CopyBytes2Mod),                      // F2XM1, etc.
				new COPYENTRY(0xDA, ENTRY_CopyBytes2Mod),                      // FLADD, etc.
				new COPYENTRY(0xDB, ENTRY_CopyBytes2Mod),                      // FCLEX, etc.
				new COPYENTRY(0xDC, ENTRY_CopyBytes2Mod),                      // FADD/0, etc.
				new COPYENTRY(0xDD, ENTRY_CopyBytes2Mod),                      // FFREE, etc.
				new COPYENTRY(0xDE, ENTRY_CopyBytes2Mod),                      // FADDP, etc.
				new COPYENTRY(0xDF, ENTRY_CopyBytes2Mod),                      // FBLD/4, etc.
				new COPYENTRY(0xE0, ENTRY_CopyBytes2CantJump),                 // LOOPNE cb
				new COPYENTRY(0xE1, ENTRY_CopyBytes2CantJump),                 // LOOPE cb
				new COPYENTRY(0xE2, ENTRY_CopyBytes2CantJump),                 // LOOP cb
				new COPYENTRY(0xE3, ENTRY_CopyBytes2Jump),                     // JCXZ/JECXZ
				new COPYENTRY(0xE4, ENTRY_CopyBytes2),                         // IN ib
				new COPYENTRY(0xE5, ENTRY_CopyBytes2),                         // IN id
				new COPYENTRY(0xE6, ENTRY_CopyBytes2),                         // OUT ib
				new COPYENTRY(0xE7, ENTRY_CopyBytes2),                         // OUT ib
				new COPYENTRY(0xE8, ENTRY_CopyBytes3Or5Target),                // CALL cd
				new COPYENTRY(0xE9, ENTRY_CopyBytes3Or5Target),                // JMP cd
				new COPYENTRY(0xEA, ENTRY_CopyBytes5Or7Dynamic),               // JMP cp
				new COPYENTRY(0xEB, ENTRY_CopyBytes2Jump),                     // JMP cb
				new COPYENTRY(0xEC, ENTRY_CopyBytes1),                         // IN ib
				new COPYENTRY(0xED, ENTRY_CopyBytes1),                         // IN id
				new COPYENTRY(0xEE, ENTRY_CopyBytes1),                         // OUT
				new COPYENTRY(0xEF, ENTRY_CopyBytes1),                         // OUT
				new COPYENTRY(0xF0, ENTRY_CopyBytesPrefix),                    // LOCK prefix
				new COPYENTRY(0xF1, ENTRY_Invalid),                            //
				new COPYENTRY(0xF2, ENTRY_CopyBytesPrefix),                    // REPNE prefix
				new COPYENTRY(0xF3, ENTRY_CopyBytesPrefix),                    // REPE prefix
				new COPYENTRY(0xF4, ENTRY_CopyBytes1),                         // HLT
				new COPYENTRY(0xF5, ENTRY_CopyBytes1),                         // CMC
				new COPYENTRY(0xF6, ENTRY_CopyF6),                             // TEST/0, DIV/6
				new COPYENTRY(0xF7, ENTRY_CopyF7),                             // TEST/0, DIV/6
				new COPYENTRY(0xF8, ENTRY_CopyBytes1),                         // CLC
				new COPYENTRY(0xF9, ENTRY_CopyBytes1),                         // STC
				new COPYENTRY(0xFA, ENTRY_CopyBytes1),                         // CLI
				new COPYENTRY(0xFB, ENTRY_CopyBytes1),                         // STI
				new COPYENTRY(0xFC, ENTRY_CopyBytes1),                         // CLD
				new COPYENTRY(0xFD, ENTRY_CopyBytes1),                         // STD
				new COPYENTRY(0xFE, ENTRY_CopyBytes2Mod),                      // DEC/1,INC/0
				new COPYENTRY(0xFF, ENTRY_CopyFF),                             // CALL/2
				new COPYENTRY(0, ENTRY_End),
			};
			private static readonly COPYENTRY[] s_rceCopyTable0F = new COPYENTRY[257]
			{
				new COPYENTRY(0x00, ENTRY_CopyBytes2Mod),                      // LLDT/2, etc.
				new COPYENTRY(0x01, ENTRY_CopyBytes2Mod),                      // INVLPG/7, etc.
				new COPYENTRY(0x02, ENTRY_CopyBytes2Mod),                      // LAR/r
				new COPYENTRY(0x03, ENTRY_CopyBytes2Mod),                      // LSL/r
				new COPYENTRY(0x04, ENTRY_Invalid),                            // _04
				new COPYENTRY(0x05, ENTRY_Invalid),                            // _05
				new COPYENTRY(0x06, ENTRY_CopyBytes2),                         // CLTS
				new COPYENTRY(0x07, ENTRY_Invalid),                            // _07
				new COPYENTRY(0x08, ENTRY_CopyBytes2),                         // INVD
				new COPYENTRY(0x09, ENTRY_CopyBytes2),                         // WBINVD
				new COPYENTRY(0x0A, ENTRY_Invalid),                            // _0A
				new COPYENTRY(0x0B, ENTRY_CopyBytes2),                         // UD2
				new COPYENTRY(0x0C, ENTRY_Invalid),                            // _0C
				new COPYENTRY(0x0D, ENTRY_CopyBytes2Mod),                      // PREFETCH
				new COPYENTRY(0x0E, ENTRY_CopyBytes2),                         // FEMMS
				new COPYENTRY(0x0F, ENTRY_CopyBytes3Mod),                      // 3DNow Opcodes
				new COPYENTRY(0x10, ENTRY_CopyBytes2Mod),                      // MOVSS MOVUPD MOVSD
				new COPYENTRY(0x11, ENTRY_CopyBytes2Mod),                      // MOVSS MOVUPD MOVSD
				new COPYENTRY(0x12, ENTRY_CopyBytes2Mod),                      // MOVLPD
				new COPYENTRY(0x13, ENTRY_CopyBytes2Mod),                      // MOVLPD
				new COPYENTRY(0x14, ENTRY_CopyBytes2Mod),                      // UNPCKLPD
				new COPYENTRY(0x15, ENTRY_CopyBytes2Mod),                      // UNPCKHPD
				new COPYENTRY(0x16, ENTRY_CopyBytes2Mod),                      // MOVHPD
				new COPYENTRY(0x17, ENTRY_CopyBytes2Mod),                      // MOVHPD
				new COPYENTRY(0x18, ENTRY_CopyBytes2Mod),                      // PREFETCHINTA...
				new COPYENTRY(0x19, ENTRY_Invalid),                            // _19
				new COPYENTRY(0x1A, ENTRY_Invalid),                            // _1A
				new COPYENTRY(0x1B, ENTRY_Invalid),                            // _1B
				new COPYENTRY(0x1C, ENTRY_Invalid),                            // _1C
				new COPYENTRY(0x1D, ENTRY_Invalid),                            // _1D
				new COPYENTRY(0x1E, ENTRY_Invalid),                            // _1E
				new COPYENTRY(0x1F, ENTRY_CopyBytes2Mod),                      // NOP/r
				new COPYENTRY(0x20, ENTRY_CopyBytes2Mod),                      // MOV/r
				new COPYENTRY(0x21, ENTRY_CopyBytes2Mod),                      // MOV/r
				new COPYENTRY(0x22, ENTRY_CopyBytes2Mod),                      // MOV/r
				new COPYENTRY(0x23, ENTRY_CopyBytes2Mod),                      // MOV/r
				new COPYENTRY(0x24, ENTRY_Invalid),                            // _24
				new COPYENTRY(0x25, ENTRY_Invalid),                            // _25
				new COPYENTRY(0x26, ENTRY_Invalid),                            // _26
				new COPYENTRY(0x27, ENTRY_Invalid),                            // _27
				new COPYENTRY(0x28, ENTRY_CopyBytes2Mod),                      // MOVAPS MOVAPD
				new COPYENTRY(0x29, ENTRY_CopyBytes2Mod),                      // MOVAPS MOVAPD
				new COPYENTRY(0x2A, ENTRY_CopyBytes2Mod),                      // CVPI2PS &
				new COPYENTRY(0x2B, ENTRY_CopyBytes2Mod),                      // MOVNTPS MOVNTPD
				new COPYENTRY(0x2C, ENTRY_CopyBytes2Mod),                      // CVTTPS2PI &
				new COPYENTRY(0x2D, ENTRY_CopyBytes2Mod),                      // CVTPS2PI &
				new COPYENTRY(0x2E, ENTRY_CopyBytes2Mod),                      // UCOMISS UCOMISD
				new COPYENTRY(0x2F, ENTRY_CopyBytes2Mod),                      // COMISS COMISD
				new COPYENTRY(0x30, ENTRY_CopyBytes2),                         // WRMSR
				new COPYENTRY(0x31, ENTRY_CopyBytes2),                         // RDTSC
				new COPYENTRY(0x32, ENTRY_CopyBytes2),                         // RDMSR
				new COPYENTRY(0x33, ENTRY_CopyBytes2),                         // RDPMC
				new COPYENTRY(0x34, ENTRY_CopyBytes2),                         // SYSENTER
				new COPYENTRY(0x35, ENTRY_CopyBytes2),                         // SYSEXIT
				new COPYENTRY(0x36, ENTRY_Invalid),                            // _36
				new COPYENTRY(0x37, ENTRY_Invalid),                            // _37
				new COPYENTRY(0x38, ENTRY_Invalid),                            // _38
				new COPYENTRY(0x39, ENTRY_Invalid),                            // _39
				new COPYENTRY(0x3A, ENTRY_Invalid),                            // _3A
				new COPYENTRY(0x3B, ENTRY_Invalid),                            // _3B
				new COPYENTRY(0x3C, ENTRY_Invalid),                            // _3C
				new COPYENTRY(0x3D, ENTRY_Invalid),                            // _3D
				new COPYENTRY(0x3E, ENTRY_Invalid),                            // _3E
				new COPYENTRY(0x3F, ENTRY_Invalid),                            // _3F
				new COPYENTRY(0x40, ENTRY_CopyBytes2Mod),                      // CMOVO (0F 40)
				new COPYENTRY(0x41, ENTRY_CopyBytes2Mod),                      // CMOVNO (0F 41)
				new COPYENTRY(0x42, ENTRY_CopyBytes2Mod),                      // CMOVB & CMOVNE (0F 42)
				new COPYENTRY(0x43, ENTRY_CopyBytes2Mod),                      // CMOVAE & CMOVNB (0F 43)
				new COPYENTRY(0x44, ENTRY_CopyBytes2Mod),                      // CMOVE & CMOVZ (0F 44)
				new COPYENTRY(0x45, ENTRY_CopyBytes2Mod),                      // CMOVNE & CMOVNZ (0F 45)
				new COPYENTRY(0x46, ENTRY_CopyBytes2Mod),                      // CMOVBE & CMOVNA (0F 46)
				new COPYENTRY(0x47, ENTRY_CopyBytes2Mod),                      // CMOVA & CMOVNBE (0F 47)
				new COPYENTRY(0x48, ENTRY_CopyBytes2Mod),                      // CMOVS (0F 48)
				new COPYENTRY(0x49, ENTRY_CopyBytes2Mod),                      // CMOVNS (0F 49)
				new COPYENTRY(0x4A, ENTRY_CopyBytes2Mod),                      // CMOVP & CMOVPE (0F 4A)
				new COPYENTRY(0x4B, ENTRY_CopyBytes2Mod),                      // CMOVNP & CMOVPO (0F 4B)
				new COPYENTRY(0x4C, ENTRY_CopyBytes2Mod),                      // CMOVL & CMOVNGE (0F 4C)
				new COPYENTRY(0x4D, ENTRY_CopyBytes2Mod),                      // CMOVGE & CMOVNL (0F 4D)
				new COPYENTRY(0x4E, ENTRY_CopyBytes2Mod),                      // CMOVLE & CMOVNG (0F 4E)
				new COPYENTRY(0x4F, ENTRY_CopyBytes2Mod),                      // CMOVG & CMOVNLE (0F 4F)
				new COPYENTRY(0x50, ENTRY_CopyBytes2Mod),                      // MOVMSKPD MOVMSKPD
				new COPYENTRY(0x51, ENTRY_CopyBytes2Mod),                      // SQRTPS &
				new COPYENTRY(0x52, ENTRY_CopyBytes2Mod),                      // RSQRTTS RSQRTPS
				new COPYENTRY(0x53, ENTRY_CopyBytes2Mod),                      // RCPPS RCPSS
				new COPYENTRY(0x54, ENTRY_CopyBytes2Mod),                      // ANDPS ANDPD
				new COPYENTRY(0x55, ENTRY_CopyBytes2Mod),                      // ANDNPS ANDNPD
				new COPYENTRY(0x56, ENTRY_CopyBytes2Mod),                      // ORPS ORPD
				new COPYENTRY(0x57, ENTRY_CopyBytes2Mod),                      // XORPS XORPD
				new COPYENTRY(0x58, ENTRY_CopyBytes2Mod),                      // ADDPS &
				new COPYENTRY(0x59, ENTRY_CopyBytes2Mod),                      // MULPS &
				new COPYENTRY(0x5A, ENTRY_CopyBytes2Mod),                      // CVTPS2PD &
				new COPYENTRY(0x5B, ENTRY_CopyBytes2Mod),                      // CVTDQ2PS &
				new COPYENTRY(0x5C, ENTRY_CopyBytes2Mod),                      // SUBPS &
				new COPYENTRY(0x5D, ENTRY_CopyBytes2Mod),                      // MINPS &
				new COPYENTRY(0x5E, ENTRY_CopyBytes2Mod),                      // DIVPS &
				new COPYENTRY(0x5F, ENTRY_CopyBytes2Mod),                      // MASPS &
				new COPYENTRY(0x60, ENTRY_CopyBytes2Mod),                      // PUNPCKLBW/r
				new COPYENTRY(0x61, ENTRY_CopyBytes2Mod),                      // PUNPCKLWD/r
				new COPYENTRY(0x62, ENTRY_CopyBytes2Mod),                      // PUNPCKLWD/r
				new COPYENTRY(0x63, ENTRY_CopyBytes2Mod),                      // PACKSSWB/r
				new COPYENTRY(0x64, ENTRY_CopyBytes2Mod),                      // PCMPGTB/r
				new COPYENTRY(0x65, ENTRY_CopyBytes2Mod),                      // PCMPGTW/r
				new COPYENTRY(0x66, ENTRY_CopyBytes2Mod),                      // PCMPGTD/r
				new COPYENTRY(0x67, ENTRY_CopyBytes2Mod),                      // PACKUSWB/r
				new COPYENTRY(0x68, ENTRY_CopyBytes2Mod),                      // PUNPCKHBW/r
				new COPYENTRY(0x69, ENTRY_CopyBytes2Mod),                      // PUNPCKHWD/r
				new COPYENTRY(0x6A, ENTRY_CopyBytes2Mod),                      // PUNPCKHDQ/r
				new COPYENTRY(0x6B, ENTRY_CopyBytes2Mod),                      // PACKSSDW/r
				new COPYENTRY(0x6C, ENTRY_CopyBytes2Mod),                      // PUNPCKLQDQ
				new COPYENTRY(0x6D, ENTRY_CopyBytes2Mod),                      // PUNPCKHQDQ
				new COPYENTRY(0x6E, ENTRY_CopyBytes2Mod),                      // MOVD/r
				new COPYENTRY(0x6F, ENTRY_CopyBytes2Mod),                      // MOV/r
				new COPYENTRY(0x70, ENTRY_CopyBytes2Mod1),                     // PSHUFW/r ib
				new COPYENTRY(0x71, ENTRY_CopyBytes2Mod1),                     // PSLLW/6 ib,PSRAW/4 ib,PSRLW/2 ib
				new COPYENTRY(0x72, ENTRY_CopyBytes2Mod1),                     // PSLLD/6 ib,PSRAD/4 ib,PSRLD/2 ib
				new COPYENTRY(0x73, ENTRY_CopyBytes2Mod1),                     // PSLLQ/6 ib,PSRLQ/2 ib
				new COPYENTRY(0x74, ENTRY_CopyBytes2Mod),                      // PCMPEQB/r
				new COPYENTRY(0x75, ENTRY_CopyBytes2Mod),                      // PCMPEQW/r
				new COPYENTRY(0x76, ENTRY_CopyBytes2Mod),                      // PCMPEQD/r
				new COPYENTRY(0x77, ENTRY_CopyBytes2),                         // EMMS
				new COPYENTRY(0x78, ENTRY_Invalid),                            // _78
				new COPYENTRY(0x79, ENTRY_Invalid),                            // _79
				new COPYENTRY(0x7A, ENTRY_Invalid),                            // _7A
				new COPYENTRY(0x7B, ENTRY_Invalid),                            // _7B
				new COPYENTRY(0x7C, ENTRY_Invalid),                            // _7C
				new COPYENTRY(0x7D, ENTRY_Invalid),                            // _7D
				new COPYENTRY(0x7E, ENTRY_CopyBytes2Mod),                      // MOVD/r
				new COPYENTRY(0x7F, ENTRY_CopyBytes2Mod),                      // MOV/r
				new COPYENTRY(0x80, ENTRY_CopyBytes3Or5Target),                // JO
				new COPYENTRY(0x81, ENTRY_CopyBytes3Or5Target),                // JNO
				new COPYENTRY(0x82, ENTRY_CopyBytes3Or5Target),                // JB,JC,JNAE
				new COPYENTRY(0x83, ENTRY_CopyBytes3Or5Target),                // JAE,JNB,JNC
				new COPYENTRY(0x84, ENTRY_CopyBytes3Or5Target),                // JE,JZ,JZ
				new COPYENTRY(0x85, ENTRY_CopyBytes3Or5Target),                // JNE,JNZ
				new COPYENTRY(0x86, ENTRY_CopyBytes3Or5Target),                // JBE,JNA
				new COPYENTRY(0x87, ENTRY_CopyBytes3Or5Target),                // JA,JNBE
				new COPYENTRY(0x88, ENTRY_CopyBytes3Or5Target),                // JS
				new COPYENTRY(0x89, ENTRY_CopyBytes3Or5Target),                // JNS
				new COPYENTRY(0x8A, ENTRY_CopyBytes3Or5Target),                // JP,JPE
				new COPYENTRY(0x8B, ENTRY_CopyBytes3Or5Target),                // JNP,JPO
				new COPYENTRY(0x8C, ENTRY_CopyBytes3Or5Target),                // JL,NGE
				new COPYENTRY(0x8D, ENTRY_CopyBytes3Or5Target),                // JGE,JNL
				new COPYENTRY(0x8E, ENTRY_CopyBytes3Or5Target),                // JLE,JNG
				new COPYENTRY(0x8F, ENTRY_CopyBytes3Or5Target),                // JG,JNLE
				new COPYENTRY(0x90, ENTRY_CopyBytes2Mod),                      // CMOVO (0F 40)
				new COPYENTRY(0x91, ENTRY_CopyBytes2Mod),                      // CMOVNO (0F 41)
				new COPYENTRY(0x92, ENTRY_CopyBytes2Mod),                      // CMOVB & CMOVC & CMOVNAE (0F 42)
				new COPYENTRY(0x93, ENTRY_CopyBytes2Mod),                      // CMOVAE & CMOVNB & CMOVNC (0F 43)
				new COPYENTRY(0x94, ENTRY_CopyBytes2Mod),                      // CMOVE & CMOVZ (0F 44)
				new COPYENTRY(0x95, ENTRY_CopyBytes2Mod),                      // CMOVNE & CMOVNZ (0F 45)
				new COPYENTRY(0x96, ENTRY_CopyBytes2Mod),                      // CMOVBE & CMOVNA (0F 46)
				new COPYENTRY(0x97, ENTRY_CopyBytes2Mod),                      // CMOVA & CMOVNBE (0F 47)
				new COPYENTRY(0x98, ENTRY_CopyBytes2Mod),                      // CMOVS (0F 48)
				new COPYENTRY(0x99, ENTRY_CopyBytes2Mod),                      // CMOVNS (0F 49)
				new COPYENTRY(0x9A, ENTRY_CopyBytes2Mod),                      // CMOVP & CMOVPE (0F 4A)
				new COPYENTRY(0x9B, ENTRY_CopyBytes2Mod),                      // CMOVNP & CMOVPO (0F 4B)
				new COPYENTRY(0x9C, ENTRY_CopyBytes2Mod),                      // CMOVL & CMOVNGE (0F 4C)
				new COPYENTRY(0x9D, ENTRY_CopyBytes2Mod),                      // CMOVGE & CMOVNL (0F 4D)
				new COPYENTRY(0x9E, ENTRY_CopyBytes2Mod),                      // CMOVLE & CMOVNG (0F 4E)
				new COPYENTRY(0x9F, ENTRY_CopyBytes2Mod),                      // CMOVG & CMOVNLE (0F 4F)
				new COPYENTRY(0xA0, ENTRY_CopyBytes2),                         // PUSH
				new COPYENTRY(0xA1, ENTRY_CopyBytes2),                         // POP
				new COPYENTRY(0xA2, ENTRY_CopyBytes2),                         // CPUID
				new COPYENTRY(0xA3, ENTRY_CopyBytes2Mod),                      // BT  (0F A3)
				new COPYENTRY(0xA4, ENTRY_CopyBytes2Mod1),                     // SHLD
				new COPYENTRY(0xA5, ENTRY_CopyBytes2Mod),                      // SHLD
				new COPYENTRY(0xA6, ENTRY_Invalid),                            // _A6
				new COPYENTRY(0xA7, ENTRY_Invalid),                            // _A7
				new COPYENTRY(0xA8, ENTRY_CopyBytes2),                         // PUSH
				new COPYENTRY(0xA9, ENTRY_CopyBytes2),                         // POP
				new COPYENTRY(0xAA, ENTRY_CopyBytes2),                         // RSM
				new COPYENTRY(0xAB, ENTRY_CopyBytes2Mod),                      // BTS (0F AB)
				new COPYENTRY(0xAC, ENTRY_CopyBytes2Mod1),                     // SHRD
				new COPYENTRY(0xAD, ENTRY_CopyBytes2Mod),                      // SHRD
				new COPYENTRY(0xAE, ENTRY_CopyBytes2Mod),                      // FXRSTOR/1,FXSAVE/0
				new COPYENTRY(0xAF, ENTRY_CopyBytes2Mod),                      // IMUL (0F AF)
				new COPYENTRY(0xB0, ENTRY_CopyBytes2Mod),                      // CMPXCHG (0F B0)
				new COPYENTRY(0xB1, ENTRY_CopyBytes2Mod),                      // CMPXCHG (0F B1)
				new COPYENTRY(0xB2, ENTRY_CopyBytes2Mod),                      // LSS/r
				new COPYENTRY(0xB3, ENTRY_CopyBytes2Mod),                      // BTR (0F B3)
				new COPYENTRY(0xB4, ENTRY_CopyBytes2Mod),                      // LFS/r
				new COPYENTRY(0xB5, ENTRY_CopyBytes2Mod),                      // LGS/r
				new COPYENTRY(0xB6, ENTRY_CopyBytes2Mod),                      // MOVZX/r
				new COPYENTRY(0xB7, ENTRY_CopyBytes2Mod),                      // MOVZX/r
				new COPYENTRY(0xB8, ENTRY_Invalid),                            // _B8
				new COPYENTRY(0xB9, ENTRY_Invalid),                            // _B9
				new COPYENTRY(0xBA, ENTRY_CopyBytes2Mod1),                     // BT & BTC & BTR & BTS (0F BA)
				new COPYENTRY(0xBB, ENTRY_CopyBytes2Mod),                      // BTC (0F BB)
				new COPYENTRY(0xBC, ENTRY_CopyBytes2Mod),                      // BSF (0F BC)
				new COPYENTRY(0xBD, ENTRY_CopyBytes2Mod),                      // BSR (0F BD)
				new COPYENTRY(0xBE, ENTRY_CopyBytes2Mod),                      // MOVSX/r
				new COPYENTRY(0xBF, ENTRY_CopyBytes2Mod),                      // MOVSX/r
				new COPYENTRY(0xC0, ENTRY_CopyBytes2Mod),                      // XADD/r
				new COPYENTRY(0xC1, ENTRY_CopyBytes2Mod),                      // XADD/r
				new COPYENTRY(0xC2, ENTRY_CopyBytes2Mod),                      // CMPPS &
				new COPYENTRY(0xC3, ENTRY_CopyBytes2Mod),                      // MOVNTI
				new COPYENTRY(0xC4, ENTRY_CopyBytes2Mod1),                     // PINSRW /r ib
				new COPYENTRY(0xC5, ENTRY_CopyBytes2Mod1),                     // PEXTRW /r ib
				new COPYENTRY(0xC6, ENTRY_CopyBytes2Mod1),                     // SHUFPS & SHUFPD
				new COPYENTRY(0xC7, ENTRY_CopyBytes2Mod),                      // CMPXCHG8B (0F C7)
				new COPYENTRY(0xC8, ENTRY_CopyBytes2),                         // BSWAP 0F C8 + rd
				new COPYENTRY(0xC9, ENTRY_CopyBytes2),                         // BSWAP 0F C8 + rd
				new COPYENTRY(0xCA, ENTRY_CopyBytes2),                         // BSWAP 0F C8 + rd
				new COPYENTRY(0xCB, ENTRY_CopyBytes2),                         //CVTPD2PI BSWAP 0F C8 + rd
				new COPYENTRY(0xCC, ENTRY_CopyBytes2),                         // BSWAP 0F C8 + rd
				new COPYENTRY(0xCD, ENTRY_CopyBytes2),                         // BSWAP 0F C8 + rd
				new COPYENTRY(0xCE, ENTRY_CopyBytes2),                         // BSWAP 0F C8 + rd
				new COPYENTRY(0xCF, ENTRY_CopyBytes2),                         // BSWAP 0F C8 + rd
				new COPYENTRY(0xD0, ENTRY_Invalid),                            // _D0
				new COPYENTRY(0xD1, ENTRY_CopyBytes2Mod),                      // PSRLW/r
				new COPYENTRY(0xD2, ENTRY_CopyBytes2Mod),                      // PSRLD/r
				new COPYENTRY(0xD3, ENTRY_CopyBytes2Mod),                      // PSRLQ/r
				new COPYENTRY(0xD4, ENTRY_CopyBytes2Mod),                      // PADDQ
				new COPYENTRY(0xD5, ENTRY_CopyBytes2Mod),                      // PMULLW/r
				new COPYENTRY(0xD6, ENTRY_CopyBytes2Mod),                      // MOVDQ2Q / MOVQ2DQ
				new COPYENTRY(0xD7, ENTRY_CopyBytes2Mod),                      // PMOVMSKB/r
				new COPYENTRY(0xD8, ENTRY_CopyBytes2Mod),                      // PSUBUSB/r
				new COPYENTRY(0xD9, ENTRY_CopyBytes2Mod),                      // PSUBUSW/r
				new COPYENTRY(0xDA, ENTRY_CopyBytes2Mod),                      // PMINUB/r
				new COPYENTRY(0xDB, ENTRY_CopyBytes2Mod),                      // PAND/r
				new COPYENTRY(0xDC, ENTRY_CopyBytes2Mod),                      // PADDUSB/r
				new COPYENTRY(0xDD, ENTRY_CopyBytes2Mod),                      // PADDUSW/r
				new COPYENTRY(0xDE, ENTRY_CopyBytes2Mod),                      // PMAXUB/r
				new COPYENTRY(0xDF, ENTRY_CopyBytes2Mod),                      // PANDN/r
				new COPYENTRY(0xE0, ENTRY_CopyBytes2Mod),                     // PAVGB
				new COPYENTRY(0xE1, ENTRY_CopyBytes2Mod),                      // PSRAW/r
				new COPYENTRY(0xE2, ENTRY_CopyBytes2Mod),                      // PSRAD/r
				new COPYENTRY(0xE3, ENTRY_CopyBytes2Mod),                      // PAVGW
				new COPYENTRY(0xE4, ENTRY_CopyBytes2Mod),                      // PMULHUW/r
				new COPYENTRY(0xE5, ENTRY_CopyBytes2Mod),                      // PMULHW/r
				new COPYENTRY(0xE6, ENTRY_CopyBytes2Mod),                      // CTDQ2PD &
				new COPYENTRY(0xE7, ENTRY_CopyBytes2Mod),                      // MOVNTQ
				new COPYENTRY(0xE8, ENTRY_CopyBytes2Mod),                      // PSUBB/r
				new COPYENTRY(0xE9, ENTRY_CopyBytes2Mod),                      // PSUBW/r
				new COPYENTRY(0xEA, ENTRY_CopyBytes2Mod),                      // PMINSW/r
				new COPYENTRY(0xEB, ENTRY_CopyBytes2Mod),                      // POR/r
				new COPYENTRY(0xEC, ENTRY_CopyBytes2Mod),                      // PADDSB/r
				new COPYENTRY(0xED, ENTRY_CopyBytes2Mod),                      // PADDSW/r
				new COPYENTRY(0xEE, ENTRY_CopyBytes2Mod),                      // PMAXSW /r
				new COPYENTRY(0xEF, ENTRY_CopyBytes2Mod),                      // PXOR/r
				new COPYENTRY(0xF0, ENTRY_Invalid),                            // _F0
				new COPYENTRY(0xF1, ENTRY_CopyBytes2Mod),                      // PSLLW/r
				new COPYENTRY(0xF2, ENTRY_CopyBytes2Mod),                      // PSLLD/r
				new COPYENTRY(0xF3, ENTRY_CopyBytes2Mod),                      // PSLLQ/r
				new COPYENTRY(0xF4, ENTRY_CopyBytes2Mod),                      // PMULUDQ/r
				new COPYENTRY(0xF5, ENTRY_CopyBytes2Mod),                      // PMADDWD/r
				new COPYENTRY(0xF6, ENTRY_CopyBytes2Mod),                      // PSADBW/r
				new COPYENTRY(0xF7, ENTRY_CopyBytes2Mod),                      // MASKMOVQ
				new COPYENTRY(0xF8, ENTRY_CopyBytes2Mod),                      // PSUBB/r
				new COPYENTRY(0xF9, ENTRY_CopyBytes2Mod),                      // PSUBW/r
				new COPYENTRY(0xFA, ENTRY_CopyBytes2Mod),                      // PSUBD/r
				new COPYENTRY(0xFB, ENTRY_CopyBytes2Mod),                      // FSUBQ/r
				new COPYENTRY(0xFC, ENTRY_CopyBytes2Mod),                      // PADDB/r
				new COPYENTRY(0xFD, ENTRY_CopyBytes2Mod),                      // PADDW/r
				new COPYENTRY(0xFE, ENTRY_CopyBytes2Mod),                      // PADDD/r
				new COPYENTRY(0xFF, ENTRY_Invalid),                            // _FF
				new COPYENTRY(0, ENTRY_End),
			};
			private byte[] s_rbModRm = new byte[256]
			{
				0,0,0,0, (byte)((byte)Flags.SIB|1),(byte)((byte)Flags.RIP|4),0,0, 0,0,0,0, (byte)((byte)Flags.SIB|1),(byte)((byte)Flags.RIP|4),0,0, // 0x
			    0,0,0,0, (byte)((byte)Flags.SIB|1),(byte)((byte)Flags.RIP|4),0,0, 0,0,0,0, (byte)((byte)Flags.SIB|1),(byte)((byte)Flags.RIP|4),0,0, // 1x
			    0,0,0,0, (byte)((byte)Flags.SIB|1),(byte)((byte)Flags.RIP|4),0,0, 0,0,0,0, (byte)((byte)Flags.SIB|1),(byte)((byte)Flags.RIP|4),0,0, // 2x
			    0,0,0,0, (byte)((byte)Flags.SIB|1),(byte)((byte)Flags.RIP|4),0,0, 0,0,0,0, (byte)((byte)Flags.SIB|1),(byte)((byte)Flags.RIP|4),0,0, // 3x
			    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 4x
			    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 5x
			    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 6x
			    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 7x
			    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // 8x
			    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // 9x
				4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // Ax
				4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // Bx
			    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 // Cx
				0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 // Dx
			    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 // Ex
			    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0                  // Fx
			};

			private bool m_bOperandOverride;
			private bool m_bAddressOverride;
			private bool m_bRaxOverride;

			private IntPtr m_ppbTarget;
			private GCHandle m_plExtra;

			private GCHandle m_plScratchExtra;
			private IntPtr m_ppbScratchTarget;
			private IntPtr m_prbScratchDst;

			private DllInjector Injector;

			public CDetourDis(DllInjector Injector, IntPtr ppbTarget, GCHandle plExtra)
			{
				this.Injector = Injector;

				this.m_bOperandOverride = false;
				this.m_bAddressOverride = false;
				this.m_bRaxOverride = false;

				if (ppbTarget == IntPtr.Zero)
					this.m_ppbTarget = (this.m_ppbScratchTarget = Injector.WriteIntPtr(IntPtr.Zero));
				else
					this.m_ppbTarget = ppbTarget;

				if (plExtra == null)
					this.m_plExtra = (this.m_plScratchExtra = GCHandle.Alloc(0));
				else
					this.m_plExtra = plExtra;

				Injector.WriteIntPtr(this.m_ppbTarget, DETOUR_INSTRUCTION_TARGET_NONE);
				this.m_plExtra.Target = 0;

				this.m_prbScratchDst = Injector.AllocMemory(64);
			}

			public static bool SanityCheckSystem()
			{
				for (uint n = 0; n < 256; n++)
				{
					COPYENTRY pEntry = s_rceCopyTable[n];

					if (n != pEntry.nOpcode)
					{
						Utilities.Log("ASSERT(n == pEntry->nOpcode)");
						return false;
					}
				}

				if (s_rceCopyTable[256]._Copy != null)
				{
					Utilities.Log("ASSERT(!\"Missing end marker.\")");
					return false;
				}

				for (uint n = 0; n < 256; n++)
				{
					COPYENTRY pEntry = s_rceCopyTable0F[n];

					if (n != pEntry.nOpcode)
					{
						Utilities.Log("ASSERT(n == pEntry->nOpcode)");
						return false;
					}
				}

				if (s_rceCopyTable0F[256]._Copy != null)
				{
					Utilities.Log("ASSERT(!\"Missing end marker.\")");
					return false;
				}

				return true;
			}

			public IntPtr CopyInstruction(IntPtr pbDst, IntPtr pbSrc)
			{
				// Configure scratch areas if real areas are not available.
				if (IntPtr.Zero == pbDst)
					pbDst = this.m_prbScratchDst;

				if (IntPtr.Zero == pbSrc)
					// We can't copy a non-existent instruction.
					throw new System.IO.InvalidDataException();

				// Figure out how big the instruction is, do the appropriate copy,
				// and figure out what the target of the instruction is if any.
				//
				COPYENTRY pEntry = s_rceCopyTable[this.Injector.ReadByte(pbSrc)];
				return pEntry.Copy(this, ref pEntry, pbDst, pbSrc);
			}

			private IntPtr CopyBytes(ref COPYENTRY pEntry, IntPtr pbDst, IntPtr pbSrc)
			{
				uint nBytesFixed = ((pEntry.nFlagBits & Flags.ADDRESS) != 0)
					? (this.m_bAddressOverride ? pEntry.nFixedSize16 : pEntry.nFixedSize)
					: (this.m_bOperandOverride ? pEntry.nFixedSize16 : pEntry.nFixedSize);

				uint nBytes = nBytesFixed;
				uint nRelOffset = pEntry.nRelOffset;
				uint cbTarget = nBytes - nRelOffset;

				if (pEntry.nModOffset > 0)
				{
					byte bModRm = this.Injector.ReadByte(pbSrc + (int)pEntry.nModOffset);
					byte bFlags = this.s_rbModRm[bModRm];

					nBytes += (uint)(bFlags & (byte)Flags.NOTSIB);

					if ((bFlags & (byte)Flags.SIB) != 0)
					{
						byte bSib = this.Injector.ReadByte(pbSrc + (int)pEntry.nModOffset + 1);

						if ((bSib & 0x07) == 0x05)
						{
							if ((bModRm & 0xc0) == 0x00)
								nBytes += 4;
							else if ((bModRm & 0xc0) == 0x40)
								nBytes += 1;
							else if ((bModRm & 0xc0) == 0x80)
								nBytes += 4;
						}

						cbTarget = nBytes - nRelOffset;
					}
					else if ((bFlags & (byte)Flags.RIP) != 0)
					{
					}
				}

				this.Injector.CopyMemory(pbDst, pbSrc, (int)nBytes);

				if (nRelOffset != 0)
					this.Injector.WriteIntPtr(this.m_ppbTarget, this.AdjustTarget(pbDst, pbSrc, nBytesFixed, nRelOffset, cbTarget));

				if ((pEntry.nFlagBits & Flags.NOENLARGE) != 0)
					this.m_plExtra.Target = -(int)this.m_plExtra.Target;

				if ((pEntry.nFlagBits & Flags.DYNAMIC) != 0)
					this.Injector.WriteIntPtr(this.m_ppbTarget, DETOUR_INSTRUCTION_TARGET_DYNAMIC);

				return pbSrc + (int)nBytes;
			}

			private IntPtr CopyBytesPrefix(ref COPYENTRY pEntry, IntPtr pbDst, IntPtr pbSrc)
			{
				this.CopyBytes(ref pEntry, pbDst, pbSrc);

				pEntry = s_rceCopyTable[this.Injector.ReadByte(pbSrc + 1)];
				return pEntry.Copy(this, ref pEntry, pbDst + 1, pbSrc + 1);
			}

			private IntPtr CopyBytesRax(ref COPYENTRY pEntry, IntPtr pbDst, IntPtr pbSrc)
			{
				this.CopyBytes(ref pEntry, pbDst, pbSrc);

				if ((this.Injector.ReadByte(pbSrc) & 0x8) != 0)
					this.m_bRaxOverride = true;

				pEntry = s_rceCopyTable[this.Injector.ReadByte(pbSrc + 1)];
				return pEntry.Copy(this, ref pEntry, pbDst + 1, pbSrc + 1);
			}

			private IntPtr CopyBytesJump(ref COPYENTRY pEntry, IntPtr pbDst, IntPtr pbSrc)
			{
				IntPtr pvSrcAddr = pbSrc + 1;
				IntPtr pvDstAddr = IntPtr.Zero;
				IntPtr nOldOffset = new IntPtr(this.Injector.ReadByte(pvSrcAddr));
				IntPtr nNewOffset = IntPtr.Zero;

				this.Injector.WriteIntPtr(this.m_ppbTarget, pbSrc + 2 + nOldOffset.ToInt32());

				if (this.Injector.ReadByte(pbSrc) == 0xeb)
				{
					this.Injector.WriteByte(pbDst, 0xe9);
					pvDstAddr = pbDst + 1;
					nNewOffset = new IntPtr(nOldOffset.ToInt64() - ((pbDst.ToInt64() - pbSrc.ToInt64()) + 3));
					this.Injector.WriteInt32(pvDstAddr, nNewOffset.ToInt32());

					this.m_plExtra.Target = 3;
					return pbSrc + 2;
				}

				if (!(this.Injector.ReadByte(pbSrc) >= 0x70 && this.Injector.ReadByte(pbSrc) <= 0x7f))
					Utilities.Log("ASSERT(pbSrc[0] >= 0x70 && pbSrc[0] <= 0x7f)");

				this.Injector.WriteByte(pbDst, 0x0f);
				this.Injector.WriteByte(pbDst + 1, (byte)(0x80 | (this.Injector.ReadByte(pbSrc) & 0xf)));

				pvDstAddr = pbDst + 2;
				nNewOffset = new IntPtr(nOldOffset.ToInt64() - ((pbDst.ToInt64() - pbSrc.ToInt64()) + 4));
				this.Injector.WriteInt32(pvDstAddr, nNewOffset.ToInt32());

				this.m_plExtra.Target = 4;
				return pbSrc + 2;
			}

			private IntPtr Invalid(ref COPYENTRY pEntry, IntPtr pbDst, IntPtr pbSrc)
			{
				Utilities.Log("ASSERT(!\"Invalid Instruction\")");
				return pbSrc + 1;
			}

			private IntPtr AdjustTarget(IntPtr pbDst, IntPtr pbSrc, uint cbOp, uint cbTargetOffset, uint cbTargetSize)
			{
				IntPtr pbTarget = IntPtr.Zero;
				IntPtr pvTargetAddr = pbDst + (int)cbTargetOffset;
				IntPtr nOldOffset = IntPtr.Zero;

				switch (cbTargetSize)
				{
					case 1:
						nOldOffset = new IntPtr(this.Injector.ReadByte(pvTargetAddr));
						break;
					case 2:
						nOldOffset = new IntPtr(this.Injector.ReadInt16(pvTargetAddr));
						break;
					case 4:
						nOldOffset = new IntPtr(this.Injector.ReadInt32(pvTargetAddr));
						break;
					case 8:
						nOldOffset = new IntPtr(this.Injector.ReadInt64(pvTargetAddr));
						break;
					default:
						Utilities.Log("ASSERT(!\"cbTargetSize is invalid.\")");
						break;
				}

				pbTarget = new IntPtr(pbSrc.ToInt64() + cbOp + nOldOffset.ToInt64());
				IntPtr nNewOffset = new IntPtr(nOldOffset.ToInt64() - (pbDst.ToInt64() - pbSrc.ToInt64()));

				switch (cbTargetSize)
				{
					case 1:
						this.Injector.WriteByte(pvTargetAddr, (byte)nNewOffset);

						if (nNewOffset.ToInt64() < sbyte.MinValue || nNewOffset.ToInt64() > sbyte.MaxValue)
							this.m_plExtra.Target = sizeof(uint) - 1;

						break;
					case 2:
						this.Injector.WriteInt16(pvTargetAddr, (short)nNewOffset);

						if (nNewOffset.ToInt64() < short.MinValue || nNewOffset.ToInt64() > short.MaxValue)
							this.m_plExtra.Target = sizeof(uint) - 2;

						break;
					case 4:
						this.Injector.WriteInt32(pvTargetAddr, (int)nNewOffset);

						if (nNewOffset.ToInt64() < int.MinValue || nNewOffset.ToInt64() > int.MaxValue)
							this.m_plExtra.Target = sizeof(uint) - 4;

						break;
					case 8:
						this.Injector.WriteInt64(pvTargetAddr, (long)nNewOffset);
						break;
				}

				if (!(new IntPtr(pbDst.ToInt64() + cbOp + nNewOffset.ToInt64()) == pbTarget))
					Utilities.Log("ASSERT(pbDst + cbOp + nNewOffset == pbTarget)");

				return pbTarget;
			}

			private IntPtr Copy0F(ref COPYENTRY pEntry, IntPtr pbDst, IntPtr pbSrc)
			{
				this.CopyBytes(ref pEntry, pbDst, pbSrc);

				pEntry = s_rceCopyTable0F[this.Injector.ReadByte(pbSrc + 1)];
				return pEntry.Copy(this, ref pEntry, pbDst + 1, pbSrc + 1);
			}

			private IntPtr Copy66(ref COPYENTRY pEntry, IntPtr pbDst, IntPtr pbSrc)
			{
				// Operand-size override prefix
				this.m_bOperandOverride = true;
				return this.CopyBytesPrefix(ref pEntry, pbDst, pbSrc);
			}

			private IntPtr Copy67(ref COPYENTRY pEntry, IntPtr pbDst, IntPtr pbSrc)
			{
				// Address size override prefix
				this.m_bAddressOverride = true;
				return CopyBytesPrefix(ref pEntry, pbDst, pbSrc);
			}

			private IntPtr CopyF6(ref COPYENTRY pEntry, IntPtr pbDst, IntPtr pbSrc)
			{
				COPYENTRY ce;

				// TEST BYTE /0
				if (0x00 == (0x38 & this.Injector.ReadByte(pbSrc + 1)))
				{    // reg(bits 543) of ModR/M == 0
					ce = new COPYENTRY(0xf6, ENTRY_CopyBytes2Mod1);
					return ce.Copy(this, ref ce, pbDst, pbSrc);
				}
				// DIV /6
				// IDIV /7
				// IMUL /5
				// MUL /4
				// NEG /3
				// NOT /2

				ce = new COPYENTRY(0xf6, ENTRY_CopyBytes2Mod);
				return ce.Copy(this, ref ce, pbDst, pbSrc);
			}

			private IntPtr CopyF7(ref COPYENTRY pEntry, IntPtr pbDst, IntPtr pbSrc)
			{
				COPYENTRY ce;

				// TEST WORD /0
				if (0x00 == (0x38 & this.Injector.ReadByte(pbSrc + 1)))
				{    // reg(bits 543) of ModR/M == 0
					ce = new COPYENTRY(0xf7, ENTRY_CopyBytes2ModOperand);
					return ce.Copy(this, ref ce, pbDst, pbSrc);
				}

				// DIV /6
				// IDIV /7
				// IMUL /5
				// MUL /4
				// NEG /3
				// NOT /2
				ce = new COPYENTRY(0xf7, ENTRY_CopyBytes2Mod);
				return ce.Copy(this, ref ce, pbDst, pbSrc);
			}

			private IntPtr CopyFF(ref COPYENTRY pEntry, IntPtr pbDst, IntPtr pbSrc)
			{
				// CALL /2
				// CALL /3
				// INC /0
				// JMP /4
				// JMP /5
				// PUSH /6

				if (0x15 == this.Injector.ReadByte(pbSrc + 1) || 0x25 == this.Injector.ReadByte(pbSrc + 1))
				{         // CALL [], JMP []
					IntPtr ppbTarget = this.Injector.ReadIntPtr(pbSrc + 2);
					this.Injector.WriteIntPtr(this.m_ppbTarget, this.Injector.ReadIntPtr(ppbTarget));
				}
				else if (0x10 == (0x38 & this.Injector.ReadByte(pbSrc + 1)) || // CALL /2 --> reg(bits 543) of ModR/M == 010
						 0x18 == (0x38 & this.Injector.ReadByte(pbSrc + 1)) || // CALL /3 --> reg(bits 543) of ModR/M == 011
						 0x20 == (0x38 & this.Injector.ReadByte(pbSrc + 1)) || // JMP /4 --> reg(bits 543) of ModR/M == 100
						 0x28 == (0x38 & this.Injector.ReadByte(pbSrc + 1))    // JMP /5 --> reg(bits 543) of ModR/M == 101
						)
					this.Injector.WriteIntPtr(this.m_ppbTarget, DETOUR_INSTRUCTION_TARGET_DYNAMIC);

				COPYENTRY ce = new COPYENTRY(0xff, ENTRY_CopyBytes2Mod);
				return ce.Copy(this, ref ce, pbDst, pbSrc);
			}
		}
	}
}