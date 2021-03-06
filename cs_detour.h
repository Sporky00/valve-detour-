#pragma once

#include <Windows.h>
#include <minwindef.h>

#include <map>
#include <set>
#include <vector>

#define MAX_HOOKED_FUNCTION_PREAMBLE_LENGTH 48
#define BYTES_FOR_TRAMPOLINE_ALLOCATION 64

enum EOpCodeOffsetType
{
	k_ENoRelativeOffsets,
	k_EDWORDOffsetAtByteTwo,
	k_EDWORDOffsetAtByteThree,
	k_EDWORDOffsetAtByteFour,
	k_EBYTEOffsetAtByteTwo,
};

#pragma pack( push, 1 )
typedef struct
{
	BYTE m_JmpOpCode[2]; // 0xFF 0x25 = jmp ptr qword
	DWORD m_JumpPtrOffset; // offset to jump to the qword ptr (0)
	uint64_t m_QWORDTarget; // address to jump to
} JumpCodeDirectX64_t;

typedef struct
{
	BYTE m_JmpOpCode; // 0xE9 = near jmp( dword )
	int32_t m_JumpOffset; // offset to jump to
} JumpCodeRelative_t;
#pragma pack( pop )

typedef struct
{
	BYTE* m_pFuncHookedAddr;
	BYTE* m_pTrampolineRealFunc;
	BYTE* m_pTrampolineEntryPoint;
	int32_t m_nOriginalPreambleLength;
	BYTE m_rgOriginalPreambleCode[MAX_HOOKED_FUNCTION_PREAMBLE_LENGTH];
} HookData_t;

typedef struct
{
	unsigned char m_OpCodeB1;	// first opcode byte
	unsigned char m_OpCodeB2;	// second opcode byte 
	unsigned char m_OpCodeB3;	// third opcode byte 
	unsigned char m_OpCodeB4;	// fourth opcode byte
	unsigned char m_TotalLength; // total length of opcodes and data
	int m_cOpCodeBytesToMatch; // Normally 1, 2 if this is a 2 byte opcode, 3 if it's 3 bytes (ie, has x64 prefix or such)
	EOpCodeOffsetType m_EOffsetType;  // if true, this opcode has IP relative data
} KnownOpCode_t;

const static KnownOpCode_t s_rgKnownOpCodes[] =
{
#ifndef _WIN64
	{ 0x08, 0xE9, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // or cl,ch
	{ 0x0F, 0x57, 0xC0, 0x00, 3, 3, k_ENoRelativeOffsets }, // xorps xmm0,xmm0 (simd)
	{ 0x31, 0xC0, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // xor eax,eax
	{ 0x31, 0xD2, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // xor edx,edx 
	{ 0x31, 0xED, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // xor ebp,ebp
	{ 0x31, 0xF6, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // xor esi,esi 
	{ 0x32, 0xC0, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // xor al,al
	{ 0x33, 0xC0, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // xor eax,eax
	{ 0x33, 0xF6, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // xor esi,esi
	{ 0x3C, 0x00, 0x00, 0x00, 2, 1, k_ENoRelativeOffsets }, // cmp al,immediate byte
	{ 0x39, 0x74, 0x00, 0x00, 4, 2, k_ENoRelativeOffsets }, // cmp dword ptr [rega+regb*coefficient+imm8],esi -- rega, regb, and coefficient depend on value of byte 3
	{ 0x3D, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // cmp eax,immediate dword
	{ 0x3F, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // aas (ascii adjust al after subtraction)

	{ 0x40, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // inc eax
	{ 0x41, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // inc ecx
	{ 0x42, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // inc edx
	{ 0x43, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // inc ebx
	{ 0x44, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // inc esp
	{ 0x45, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // inc ebp
	{ 0x46, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // inc esi
	{ 0x47, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // inc edi

	{ 0x48, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // dec eax
	{ 0x49, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // dec ecx
	{ 0x4A, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // dec edx
	{ 0x4B, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // dec ebx
	{ 0x4C, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // dec esp
	{ 0x4D, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // dec ebp
	{ 0x4E, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // dec esi
	{ 0x4F, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // dec edi

	{ 0x50, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push eax
	{ 0x51, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push ecx
	{ 0x52, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push edx
	{ 0x53, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push ebx
	{ 0x54, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push esp
	{ 0x55, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push ebp
	{ 0x56, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push esi
	{ 0x57, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push edi

	{ 0x58, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // pop eax
	{ 0x59, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // pop ecx
	{ 0x5A, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // pop edx
	{ 0x5B, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // pop ebx
	{ 0x5C, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // pop esp
	{ 0x5D, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // pop ebp
	{ 0x5E, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // pop esi
	{ 0x5F, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // pop edi


	{ 0x60, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // pushad
	{ 0x61, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // popad

	{ 0x64, 0xA1, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr fs:[imm32] 

	{ 0x68, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // push immediate doubleword
	{ 0x6A, 0x00, 0x00, 0x00, 2, 1, k_ENoRelativeOffsets }, // push immediate byte

	{ 0x80, 0x3D, 0x00, 0x00, 7, 2, k_ENoRelativeOffsets }, // cmp byte ptr ds:[dword],imm8
	{ 0x81, 0xEC, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // sub esp immediate dword
	{ 0x81, 0xF9, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // cmp ecx, immediate dword
	{ 0x83, 0x3D, 0x00, 0x00, 7, 2, k_ENoRelativeOffsets }, // cmp dword ptr to immediate byte
	{ 0x83, 0x40, 0x00, 0x00, 4, 2, k_ENoRelativeOffsets }, // add dword ptr [eax+imm8],imm8
	{ 0x83, 0x41, 0x00, 0x00, 4, 2, k_ENoRelativeOffsets }, // add dword ptr [ecx+imm8],imm8
	{ 0x83, 0x6C, 0x00,	0x00, 5, 2, k_ENoRelativeOffsets },	// sub dword ptr [rega+regb*coefficient+imm8a],imm8b -- rega, regb, and coefficient depend on value of byte 3
	{ 0x83, 0x7C, 0x00, 0x00, 5, 2, k_ENoRelativeOffsets }, // cmp dword ptr [rega+regb*coefficient+imm8a],imm8b -- rega, regb, and coefficient depend on value of byte 3
	{ 0x83, 0x7D, 0x00, 0x00, 4, 2, k_ENoRelativeOffsets }, // cmp dword ptr [ebp+imm8],imm8

	{ 0x83, 0xC0, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // add eax immediate byte
	{ 0x83, 0xC1, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // add ecx immediate byte
	{ 0x83, 0xC2, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // add edx immediate byte
	{ 0x83, 0xC3, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // add ebx immediate byte
	{ 0x83, 0xC4, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // add esp immediate byte
	{ 0x83, 0xC5, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // add ebp immediate byte
	{ 0x83, 0xC6, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // add esi immediate byte
	{ 0x83, 0xC7, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // add edi immediate byte

	{ 0x83, 0xE4, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // and esp,0FFFFFF00+immediate byte
	{ 0x83, 0xE8, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // sub eax immediate byte
	{ 0x83, 0xE9, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // sub ecx immediate byte
	{ 0x83, 0xEA, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // sub edx immediate byte
	{ 0x83, 0xEB, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // sub ebx immediate byte
	{ 0x83, 0xEC, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // sub esp immediate byte
	{ 0x83, 0xED, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // sub ebp immediate byte
	{ 0x83, 0xEE, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // sub esi immediate byte
	{ 0x83, 0xEF, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // sub edi immediate byte

	{ 0x83, 0xFA, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // lock cmp edx,imm8

	{ 0x85, 0xC7, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // test edi,eax 
	{ 0x85, 0xC8, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // test eax,ecx 
	{ 0x85, 0xC9, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // test ecx,ecx 
	{ 0x85, 0xCA, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // test edx,ecx 

	{ 0x87, 0x05, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // xchg eax, dword ptr
	{ 0x89, 0xE5, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebp,esp 
	{ 0x89, 0x5C, 0x24, 0x00, 4, 3, k_ENoRelativeOffsets }, // mov dword ptr [esp+imm8],ebx 

	{ 0x8B, 0x00, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [eax]
	{ 0x8B, 0x01, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [ecx]
	{ 0x8B, 0x02, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [edx]
	{ 0x8B, 0x03, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [ebx]

	{ 0x8B, 0x06, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [esi]
	{ 0x8B, 0x07, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [edi]
	{ 0x8B, 0x08, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [eax]
	{ 0x8B, 0x09, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [ecx]
	{ 0x8B, 0x0B, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [ebx]
	{ 0x8B, 0x0D, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [_gpsi]
	{ 0x8B, 0x0E, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [esi]
	{ 0x8B, 0x0F, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [edi]

	{ 0x8B, 0x10, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [eax]
	{ 0x8B, 0x11, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [ecx]
	{ 0x8B, 0x12, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [edx]
	{ 0x8B, 0x13, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [ebx]

	{ 0x8B, 0x16, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [esi]
	{ 0x8B, 0x17, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [edi]

	{ 0x8B, 0x18, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [eax]
	{ 0x8B, 0x19, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [ecx]
	{ 0x8B, 0x1B, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [ebx]
	{ 0x8B, 0x1E, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [edi]
	{ 0x8B, 0x1F, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [esi]

	{ 0x8B, 0x30, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [eax]
	{ 0x8B, 0x31, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [ecx]
	{ 0x8B, 0x32, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [edx]
	{ 0x8B, 0x33, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [ebx]
	{ 0x8B, 0x34, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [edi+eax], 3rd byte determines ptr
	{ 0x8B, 0x35, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [_gpsi]
	{ 0x8B, 0x36, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [esi]
	{ 0x8B, 0x37, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [edi]

	{ 0x8B, 0x38, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [eax]
	{ 0x8B, 0x39, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [ecx]
	{ 0x8B, 0x3B, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [ebx]
	{ 0x8B, 0x3E, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [esi]
	{ 0x8B, 0x3F, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [edi]

	{ 0x8B, 0x40, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [eax+rawbyte]
	{ 0x8B, 0x41, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [ecx+rawbyte]
	{ 0x8B, 0x42, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [edx+rawbyte]
	{ 0x8B, 0x43, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [ebx+rawbyte]
	{ 0x8B, 0x44, 0x00, 0x00, 4, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [esp+rawbyte]
	{ 0x8B, 0x45, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [ebp+rawbyte]
	{ 0x8B, 0x46, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [esi+rawbyte]
	{ 0x8B, 0x47, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [edi+rawbyte]

	{ 0x8B, 0x48, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [eax+rawbyte]
	{ 0x8B, 0x49, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [ecx+rawbyte]
	{ 0x8B, 0x4A, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [edx+rawbyte]
	{ 0x8B, 0x4B, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [ebx+rawbyte]
	{ 0x8B, 0x4C, 0x00, 0x00, 4, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [esp+rawbyte]
	{ 0x8B, 0x4D, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [ebp+rawbyte]
	{ 0x8B, 0x4E, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [esi+rawbyte]
	{ 0x8B, 0x4F, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [edi+rawbyte]

	{ 0x8B, 0x50, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [eax+rawbyte]
	{ 0x8B, 0x51, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [ecx+rawbyte]
	{ 0x8B, 0x52, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [edx+rawbyte]
	{ 0x8B, 0x53, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [ebx+rawbyte]
	{ 0x8B, 0x54, 0x00, 0x00, 4, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [esp+rawbyte]
	{ 0x8B, 0x55, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [ebp+rawbyte]
	{ 0x8B, 0x56, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [esi+rawbyte]
	{ 0x8B, 0x57, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [edi+rawbyte]

	{ 0x8B, 0x58, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [eax+rawbyte]
	{ 0x8B, 0x59, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [ecx+rawbyte]
	{ 0x8B, 0x5A, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [edx+rawbyte]
	{ 0x8B, 0x5B, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [ebx+rawbyte]
	{ 0x8B, 0x5C, 0x00, 0x00, 4, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [esp+rawbyte]
	{ 0x8B, 0x5D, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [ebp+rawbyte]
	{ 0x8B, 0x5E, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [esi+rawbyte]
	{ 0x8B, 0x5F, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [edi+rawbyte]

	{ 0x8B, 0x60, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov esp,dword ptr [eax+rawbyte]
	{ 0x8B, 0x61, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov esp,dword ptr [ecx+rawbyte]
	{ 0x8B, 0x62, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov esp,dword ptr [edx+rawbyte]
	{ 0x8B, 0x63, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov esp,dword ptr [ebx+rawbyte]
	{ 0x8B, 0x64, 0x00, 0x00, 4, 2, k_ENoRelativeOffsets }, // mov esp,dword ptr [esp+rawbyte]
	{ 0x8B, 0x65, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov esp,dword ptr [ebp+rawbyte]
	{ 0x8B, 0x66, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov esp,dword ptr [esi+rawbyte]
	{ 0x8B, 0x67, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov esp,dword ptr [edi+rawbyte]

	{ 0x8B, 0x68, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ebp,dword ptr [eax+rawbyte]
	{ 0x8B, 0x69, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ebp,dword ptr [ecx+rawbyte]
	{ 0x8B, 0x6A, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ebp,dword ptr [edx+rawbyte]
	{ 0x8B, 0x6B, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ebp,dword ptr [ebx+rawbyte]
	{ 0x8B, 0x6C, 0x00, 0x00, 4, 2, k_ENoRelativeOffsets }, // mov ebp,dword ptr [esp+rawbyte]
	{ 0x8B, 0x6D, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ebp,dword ptr [ebp+rawbyte]
	{ 0x8B, 0x6E, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ebp,dword ptr [esi+rawbyte]
	{ 0x8B, 0x6F, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov ebp,dword ptr [edi+rawbyte]

	{ 0x8B, 0x70, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [eax+rawbyte]
	{ 0x8B, 0x71, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [ecx+rawbyte]
	{ 0x8B, 0x72, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [edx+rawbyte]
	{ 0x8B, 0x73, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [ebx+rawbyte]
	{ 0x8B, 0x74, 0x00, 0x00, 4, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [esp+rawbyte]
	{ 0x8B, 0x75, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [ebp+rawbyte]
	{ 0x8B, 0x76, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [esi+rawbyte]
	{ 0x8B, 0x77, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [edi+rawbyte]

	{ 0x8B, 0x78, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [eax+rawbyte]
	{ 0x8B, 0x79, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [ecx+rawbyte]
	{ 0x8B, 0x7A, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [edx+rawbyte]
	{ 0x8B, 0x7B, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [ebx+rawbyte]
	{ 0x8B, 0x7C, 0x00, 0x00, 4, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [esp+rawbyte]
	{ 0x8B, 0x7D, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [ebp+rawbyte]
	{ 0x8B, 0x7E, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [esi+rawbyte]
	{ 0x8B, 0x7F, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [edi+rawbyte]

	{ 0x8B, 0x80, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [eax+rawdword]
	{ 0x8B, 0x81, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [ecx+rawdword]
	{ 0x8B, 0x82, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [edx+rawdword]
	{ 0x8B, 0x83, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [ebx+rawdword]
	{ 0x8B, 0x84, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [esp+rawdword]
	{ 0x8B, 0x85, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [ebp+rawdword]
	{ 0x8B, 0x86, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [esi+rawdword]
	{ 0x8B, 0x87, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [edi+rawdword]

	{ 0x8B, 0x88, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [eax+rawdword]
	{ 0x8B, 0x89, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [ecx+rawdword]
	{ 0x8B, 0x8A, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [edx+rawdword]
	{ 0x8B, 0x8B, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [ebx+rawdword]
	{ 0x8B, 0x8C, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [esp+rawdword]
	{ 0x8B, 0x8D, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [ebp+rawdword]
	{ 0x8B, 0x8E, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [esi+rawdword]
	{ 0x8B, 0x8F, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ecx,dword ptr [edi+rawdword]

	{ 0x8B, 0x90, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [eax+rawdword]
	{ 0x8B, 0x91, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [ecx+rawdword]
	{ 0x8B, 0x92, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [edx+rawdword]
	{ 0x8B, 0x93, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [ebx+rawdword]
	{ 0x8B, 0x94, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [esp+rawdword]
	{ 0x8B, 0x95, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [ebp+rawdword]
	{ 0x8B, 0x96, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [esi+rawdword]
	{ 0x8B, 0x97, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edx,dword ptr [edi+rawdword]

	{ 0x8B, 0x98, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [eax+rawdword]
	{ 0x8B, 0x99, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [ecx+rawdword]
	{ 0x8B, 0x9A, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [edx+rawdword]
	{ 0x8B, 0x9B, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [ebx+rawdword]
	{ 0x8B, 0x9C, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [esp+rawdword]
	{ 0x8B, 0x9D, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [ebp+rawdword]
	{ 0x8B, 0x9E, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [esi+rawdword]
	{ 0x8B, 0x9F, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov ebx,dword ptr [edi+rawdword]

	{ 0x8B, 0xB0, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [eax+rawdword]
	{ 0x8B, 0xB1, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [ecx+rawdword]
	{ 0x8B, 0xB2, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [edx+rawdword]
	{ 0x8B, 0xB3, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [ebx+rawdword]
	{ 0x8B, 0xB4, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [esp+rawdword]
	{ 0x8B, 0xB5, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [ebp+rawdword]
	{ 0x8B, 0xB6, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [esi+rawdword]
	{ 0x8B, 0xB7, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov esi,dword ptr [edi+rawdword]

	{ 0x8B, 0xB8, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [eax+rawdword]
	{ 0x8B, 0xB9, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [ecx+rawdword]
	{ 0x8B, 0xBA, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [edx+rawdword]
	{ 0x8B, 0xBB, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [ebx+rawdword]
	{ 0x8B, 0xBC, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [ebx+rawdword]
	{ 0x8B, 0xBD, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [ebp+rawdword]
	{ 0x8B, 0xBE, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [esi+rawdword]
	{ 0x8B, 0xBF, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov edi,dword ptr [edi+rawdword]

	{ 0x8B, 0xC0, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,eax
	{ 0x8B, 0xC1, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,ecx
	{ 0x8B, 0xC2, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,edx
	{ 0x8B, 0xC3, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,ebx
	{ 0x8B, 0xC4, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,esp
	{ 0x8B, 0xC5, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,ebp
	{ 0x8B, 0xC6, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,esi
	{ 0x8B, 0xC7, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,edi

	{ 0x8B, 0xC8, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ecx,eax
	{ 0x8B, 0xC9, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ecx,ecx
	{ 0x8B, 0xCA, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ecx,edx
	{ 0x8B, 0xCB, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ecx,ebx
	{ 0x8B, 0xCC, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ecx,esp
	{ 0x8B, 0xCD, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ecx,ebp
	{ 0x8B, 0xCE, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ecx,esi
	{ 0x8B, 0xCF, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ecx,edi

	{ 0x8B, 0xD0, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,eax
	{ 0x8B, 0xD1, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,ecx
	{ 0x8B, 0xD2, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,edx
	{ 0x8B, 0xD3, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,ebx
	{ 0x8B, 0xD4, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,esp
	{ 0x8B, 0xD5, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,ebp
	{ 0x8B, 0xD6, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,esi
	{ 0x8B, 0xD7, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,edi

	{ 0x8B, 0xD8, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebx,eax
	{ 0x8B, 0xD9, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebx,ecx
	{ 0x8B, 0xDA, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebx,edx
	{ 0x8B, 0xDB, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebx,ebx
	{ 0x8B, 0xDC, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebx,ebx
	{ 0x8B, 0xDD, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebx,ebp
	{ 0x8B, 0xDE, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebx,esi
	{ 0x8B, 0xDF, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebx,edi

	{ 0x8B, 0xE0, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esp,eax
	{ 0x8B, 0xE1, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esp,ecx
	{ 0x8B, 0xE2, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esp,edx
	{ 0x8B, 0xE3, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esp,ebx
	{ 0x8B, 0xE4, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esp,ebx
	{ 0x8B, 0xE5, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esp,ebp
	{ 0x8B, 0xE6, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esp,esi
	{ 0x8B, 0xE7, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esp,edi

	{ 0x8B, 0xE8, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebp,eax
	{ 0x8B, 0xE9, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebp,eax
	{ 0x8B, 0xEA, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebp,edx
	{ 0x8B, 0xEB, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebp,ebx
	{ 0x8B, 0xEC, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebp,esp
	{ 0x8B, 0xED, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebp,ebp
	{ 0x8B, 0xEE, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebp,esi
	{ 0x8B, 0xEF, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov ebp,edi

	{ 0x8B, 0xD3, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,ebx
	{ 0x8B, 0xD5, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,ebp
	{ 0x8B, 0xD6, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,esi
	{ 0x8B, 0xD7, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,edi

	{ 0x8B, 0xF0, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esi,eax
	{ 0x8B, 0xF1, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esi,ecx
	{ 0x8B, 0xF2, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esi,edx
	{ 0x8B, 0xF3, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esi,ebx
	{ 0x8B, 0xF4, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esi,esp
	{ 0x8B, 0xF5, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esi,ebp
	{ 0x8B, 0xF6, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esi,esi
	{ 0x8B, 0xF7, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov esi,edi

	{ 0x8B, 0xF8, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edi,eax
	{ 0x8B, 0xF9, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edi,ecx
	{ 0x8B, 0xFA, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edi,edx
	{ 0x8B, 0xFB, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edi,ebx
	{ 0x8B, 0xFC, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edi,esp
	{ 0x8B, 0xFD, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edi,ebp
	{ 0x8B, 0xFE, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edi,esi
	{ 0x8B, 0xFF, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edi,edi

	{ 0x8D, 0x44, 0x24, 0x00, 4, 3, k_ENoRelativeOffsets }, // lea eax,[esp+imm8] 
	{ 0x8D, 0x45, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // lea eax,[ebp+imm8] 
	{ 0x8D, 0x4C, 0x24, 0x00, 4, 3, k_ENoRelativeOffsets }, // lea ecx,[esp+imm8] 
	{ 0x8D, 0x64, 0x24, 0x00, 4, 3, k_ENoRelativeOffsets }, // lea esp,[esp+imm8] 
	{ 0x8D, 0xA4, 0x24, 0x00, 7, 3, k_ENoRelativeOffsets }, // lea esp,[esp+imm32] 
	{ 0x8D, 0xAC, 0x24, 0x00, 7, 3, k_ENoRelativeOffsets }, // lea ebp,[esp+imm32] 

	{ 0x90, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // nop 
	{ 0x97, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // xchg eax,edi
	{ 0x9C, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // pushfd
	{ 0x9D, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // popfd

	{ 0xA0, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // mov al,byte ptr ds:[imm32]

	{ 0xB9, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // mov immediate doubleword into ecx
	{ 0xBA, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // mov immediate doubleword into edx
	{ 0xBB, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // mov immediate doubleword into ebx
	{ 0xBC, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // mov immediate doubleword into esp
	{ 0xBD, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // mov immediate doubleword into ebp
	{ 0xBE, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // mov immediate doubleword into esi
	{ 0xB8, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // mov immediate doubleword into eax
	{ 0xBF, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // mov immediate doubleword into edi
	{ 0xA1, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // mov eax, dword ptr
	{ 0xA2, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // mov byte ptr, al 
	{ 0xA3, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // mov dword ptr, eax 
	{ 0xC3, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // ret
	{ 0xC7, 0x05, 0x00, 0x00, 10, 1, k_ENoRelativeOffsets }, // mov dword ptr ds:[dword],dword 
	{ 0xC9, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets },	// leave
	{ 0xCC, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // int3 

	{ 0xD0, 0x00, 0x00, 0x00, 2, 1, k_ENoRelativeOffsets }, // shr, sar, or rcr (shift right style operations on registers)

	// 0xF0 is the lock prefix
	{ 0xF0, 0x0F, 0xBA, 0x2D, 9, 4, k_ENoRelativeOffsets }, // lock bts dword ptr ds:[dword], imm byte

	{ 0xFA, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // cli
	{ 0xF8,	0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // clc
	{ 0xFC, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // cld
	{ 0xFF, 0x15, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // call dword ptr ds:[imm32]
	{ 0xFF, 0x48, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // dec dword ptr [eax+imm8] 
	{ 0xFF, 0x61, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // jmp dword ptr [ecx+imm8] 
	{ 0xFF, 0x74, 0x00, 0x00, 4, 2, k_ENoRelativeOffsets }, // push dword ptr
	{ 0xFF, 0x75, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // push dword ptr type 2
	{ 0xFF, 0x25, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // jmp dword ptr -- this is often at the start of win32 api functions that are just stubs to call some __imp__func call

	{ 0xE8, 0x00, 0x00, 0x00, 5, 1, k_EDWORDOffsetAtByteTwo }, // call DWORD rel
	{ 0xE9, 0x00, 0x00, 0x00, 5, 1, k_EDWORDOffsetAtByteTwo }, // jmp DWORD rel
	{ 0xEB, 0x00, 0x00, 0x00, 2, 1, k_EBYTEOffsetAtByteTwo }, // jmp byte rel
#else
	//
	// 64 bit specific opcodes
	//
	{ 0x0F, 0x1F, 0x00, 0x00, 3, 3,	k_ENoRelativeOffsets }, // nop dword ptr[rax] (canonical 3-byte NOP)
	{ 0x0F, 0x1F, 0x40, 0x00, 4, 3,	k_ENoRelativeOffsets }, // nop dword ptr[rax+imm8] (canonical 4-byte NOP)
	{ 0x0F, 0x1F, 0x44, 0x00, 5, 3,	k_ENoRelativeOffsets }, // nop dword ptr[rax+rax+imm8] (canonical 5-byte NOP)
	{ 0x0F, 0x1F, 0x80, 0x00, 7, 3,	k_ENoRelativeOffsets }, // nop dword ptr[rax+0x0] (canonical 7-byte NOP)
	{ 0x0F, 0xB6, 0x53, 0x00, 4, 3, k_ENoRelativeOffsets }, // movzx edx,byte ptr[rbx+byte]	
	{ 0x33, 0xD2, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // xor edx,edx

	// 0x40 indicates 64bit operands
	{ 0x40, 0x50, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rax
	{ 0x40, 0x51, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rcx
	{ 0x40, 0x52, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rdx
	{ 0x40, 0x53, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rbx
	{ 0x40, 0x54, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rsp
	{ 0x40, 0x55, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rbp
	{ 0x40, 0x56, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rsi

	{ 0x41, 0x50, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push r8
	{ 0x41, 0x51, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push r9
	{ 0x41, 0x52, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push r10
	{ 0x41, 0x53, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push r11
	{ 0x41, 0x54, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push r12
	{ 0x41, 0x55, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push r13
	{ 0x41, 0x56, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push r14
	{ 0x41, 0x57, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push r15
	{ 0x41, 0x58, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // pop r8
	{ 0x41, 0x59, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // pop r9
	{ 0x41, 0x5A, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // pop r10
	{ 0x41, 0x5B, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // pop r11
	{ 0x41, 0x5C, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // pop r12
	{ 0x41, 0x5D, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // pop r13
	{ 0x41, 0x5E, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // pop r14
	{ 0x41, 0x5F, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // pop r15

	{ 0x41, 0x8B, 0xC0, 0x00, 3, 3, k_ENoRelativeOffsets }, // mov eax,r8d 
	{ 0x41, 0x8B, 0xD8, 0x00, 3, 3, k_ENoRelativeOffsets }, // mov ebx,r8d

	{ 0x41, 0xB0, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov r8b, imm8
	{ 0x41, 0xB1, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov r9b, imm8

	{ 0x41, 0xB8, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov r8d, imm32
	{ 0x41, 0xB9, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // mov r9d, imm32

	// 44 is a prefix that indicates the mod r/m field is extended
	{ 0x44, 0x89, 0x44, 0x00, 5, 3, k_ENoRelativeOffsets }, // mov dword ptr [rsp+...], reg
	{ 0x44, 0x8D, 0x42, 0x00, 4, 3, k_ENoRelativeOffsets }, // lea r8d[rdx+...]

	{ 0x45, 0x33, 0xC0, 0x00, 3, 3, k_ENoRelativeOffsets }, // xor r8d,r8d
	{ 0x45, 0x33, 0xC9, 0x00, 3, 3, k_ENoRelativeOffsets }, // xor r9d,r9d

	// 48 is a prefix that indicates the operation takes 64 bit operands
	{ 0x48, 0x81, 0xEC, 0x00, 7, 3, k_ENoRelativeOffsets }, // sub rsp, imm32

	{ 0x48, 0x63, 0xC9, 0x00, 3, 3, k_ENoRelativeOffsets }, // movsxd rcx,ecx
	{ 0x48, 0x63, 0xD2, 0x00, 3, 3, k_ENoRelativeOffsets }, // movsxd rdx,edx

	{ 0x48, 0x83, 0x64, 0x00, 6, 3, k_ENoRelativeOffsets }, // and qword ptr [rsp+...], immediate
	{ 0x48, 0x83, 0xEC, 0x00, 4, 3, k_ENoRelativeOffsets }, // sub rsp, immediate
	{ 0x48, 0x83, 0xE9, 0x00, 4, 3, k_ENoRelativeOffsets }, // sub rcx, immediate byte
	{ 0x48, 0x83, 0xC1, 0x00, 4, 3, k_ENoRelativeOffsets }, // add rcx, immediate byte

	{ 0x48, 0x85, 0xC0, 0x00, 3, 3, k_ENoRelativeOffsets }, // test rax,rax
	{ 0x48, 0x85, 0xC9, 0x00, 3, 3, k_ENoRelativeOffsets }, // test rcx,rcx
	{ 0x48, 0x85, 0xD2, 0x00, 3, 3, k_ENoRelativeOffsets }, // text rdx,rdx

	{ 0x48, 0x89, 0x4C, 0x00, 5, 3, k_ENoRelativeOffsets }, // mov qword ptr[...+...+imm byte],rcx
	{ 0x48, 0x89, 0x54, 0x00, 5, 3, k_ENoRelativeOffsets }, // mov qword ptr[rsp+...],rdx
	{ 0x48, 0x89, 0x58, 0x00, 4, 3, k_ENoRelativeOffsets }, // mov qword ptr[rax+...],rbx
	{ 0x48, 0x89, 0x5C, 0x00, 5, 3, k_ENoRelativeOffsets }, // mov qword ptr[rsp+...], reg
	{ 0x48, 0x89, 0x68, 0x00, 4, 3, k_ENoRelativeOffsets }, // mov qword ptr[rax+...],rbp
	{ 0x48, 0x89, 0x6C, 0x00, 5, 3, k_ENoRelativeOffsets }, // mov qword ptr[rsp+...],rbp
	{ 0x48, 0x89, 0x70, 0x00, 4, 3, k_ENoRelativeOffsets }, // mov qword ptr[rax+...],rsi
	{ 0x48, 0x89, 0x74, 0x00, 5, 3, k_ENoRelativeOffsets }, // mov qword ptr[rsp+...],rsi

	{ 0x48, 0x8B, 0x01, 0x00, 3, 3, k_ENoRelativeOffsets }, // mov rax,qword ptr [rcx]
	{ 0x48, 0x8B, 0x04, 0x24, 4, 4, k_ENoRelativeOffsets }, // mov rax,qword ptr [rsp]
	{ 0x48, 0x8B, 0x44, 0x00, 5, 3, k_ENoRelativeOffsets }, // mov rax,qword ptr[...+...+imm byte]
	{ 0x48, 0x8B, 0x49, 0x00, 4, 3, k_ENoRelativeOffsets }, // mov rcx,qword ptr[rcx+im8]
	{ 0x48, 0x8B, 0x84, 0x00, 8, 3, k_ENoRelativeOffsets }, // mov rax,qword ptr[rsp+dword]
	{ 0x48, 0x8B, 0xC1, 0x00, 3, 3, k_ENoRelativeOffsets }, // mov rax,rcx
	{ 0x48, 0x8B, 0xC3, 0x00, 3, 3, k_ENoRelativeOffsets }, // mov ebx,r8d
	{ 0x48, 0x8B, 0xC4, 0x00, 3, 3, k_ENoRelativeOffsets }, // mov rax,rsp
	{ 0x48, 0x8B, 0xD9, 0x00, 3, 3, k_ENoRelativeOffsets }, // mov rbx,rbx
	{ 0x48, 0x8B, 0xEC, 0x00, 3, 3, k_ENoRelativeOffsets }, // mov rbp,rsp
	{ 0x48, 0x8B, 0xFA, 0x00, 3, 3, k_ENoRelativeOffsets }, // mov rdi,rdx

	{ 0x48, 0xB8, 0x00, 0x00, 10, 2, k_ENoRelativeOffsets }, // mov rax,imm64
	{ 0x48, 0xB9, 0x00, 0x00, 10, 2, k_ENoRelativeOffsets }, // mov rcx,imm64

	{ 0x48, 0xC7, 0x44, 0x00, 9, 3, k_ENoRelativeOffsets }, // mov qword ptr[rsp+...], dword immediate
	{ 0x48, 0xC7, 0xC0, 0x00, 7, 3, k_ENoRelativeOffsets }, // mov rax,dword ptr

	{ 0x48, 0x8D, 0x05, 0x00, 7, 3, k_EDWORDOffsetAtByteFour }, // lea rax, [imm dword offset]
	{ 0x48, 0x8D, 0x0D, 0x00, 7, 3, k_EDWORDOffsetAtByteFour }, // lea rcx, [imm dword offset]
	{ 0x48, 0x8D, 0x15, 0x00, 7, 3, k_EDWORDOffsetAtByteFour }, // lea rdx, [imm dword offset]
	{ 0x48, 0x8D, 0x1D, 0x00, 7, 3, k_EDWORDOffsetAtByteFour }, // lea rbx, [imm dword offset]
	{ 0x48, 0x8D, 0x44, 0x24, 5, 4, k_ENoRelativeOffsets }, // lea rax, [rsp+imm byte]
	{ 0x48, 0x8D, 0x4C, 0x24, 5, 4, k_ENoRelativeOffsets }, // lea rcx, [rsp+imm byte]
	{ 0x48, 0x8D, 0x54, 0x24, 5, 4, k_ENoRelativeOffsets }, // lea rdx, [rsp+imm byte]
	{ 0x48, 0x8D, 0x5C, 0x24, 5, 4, k_ENoRelativeOffsets }, // lea rbx, [rsp+imm byte]

	{ 0x48, 0xFF, 0x25, 0x00, 7, 3, k_EDWORDOffsetAtByteFour }, // jmp QWORD PTR [rip+dword] -- RIP-relative indirect jump

	{ 0x49, 0x89, 0x5B, 0x00, 4, 3, k_ENoRelativeOffsets }, // qword ptr[r11 + byte], rbx
	{ 0x49, 0x89, 0x73, 0x00, 4, 3, k_ENoRelativeOffsets }, // qword ptr[r11 + byte], rsi
	{ 0x49, 0x8B, 0xC1, 0x00, 3, 3, k_ENoRelativeOffsets }, // qword rax, r9

	{ 0x4C, 0x3B, 0xCF, 0x00, 3, 3, k_ENoRelativeOffsets }, // cmp r9,rdi

	{ 0x4C, 0x89, 0x40, 0x00, 4, 3, k_ENoRelativeOffsets }, // mov qword ptr [rax+immediate byte],r8
	{ 0x4C, 0x89, 0x48, 0x00, 4, 3, k_ENoRelativeOffsets }, // mov qword ptr [rax+immediate byte],r9 
	{ 0x4C, 0x89, 0x44, 0x00, 5, 3, k_ENoRelativeOffsets }, // mov qword ptr [rsp+imm byte],r8
	{ 0x4C, 0x89, 0x4C, 0x00, 5, 3, k_ENoRelativeOffsets }, // mov qword ptr [...+...+imm byte],r9
	{ 0x4C, 0x8B, 0xC2, 0x00, 3, 3, k_ENoRelativeOffsets }, // mov r8,rdx
	{ 0x4C, 0x8B, 0xD1, 0x00, 3, 3, k_ENoRelativeOffsets }, // mov r10,rcx
	{ 0x4C, 0x8B, 0xDC, 0x00, 3, 3, k_ENoRelativeOffsets }, // mov r11,rsp
	{ 0x4C, 0x8D, 0x44, 0x00, 5, 3, k_ENoRelativeOffsets }, // lea reg,[rsp+...]

	{ 0x4D, 0x85, 0xC0, 0x00, 3, 3, k_ENoRelativeOffsets }, // test r8,r8
	{ 0x4D, 0x85, 0xC9, 0x00, 3, 3, k_ENoRelativeOffsets }, // test r9,r9

	{ 0x50, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push rax
	{ 0x51, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push rcx
	{ 0x52, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push rdx
	{ 0x53, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push rbx
	{ 0x54, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push rsp
	{ 0x55, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push rbp
	{ 0x56, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push rsi
	{ 0x57, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // push rdi

	// 0x64 and 0x65 are prefixes for FS or GS relative memory addressing
	{ 0x64, 0x48, 0x89, 0x04, 5, 4, k_ENoRelativeOffsets }, // mov qword ptr fs:[register-based offset], rax
	{ 0x65, 0x48, 0x8b, 0x00, 9, 3, k_ENoRelativeOffsets }, // mov reg,qword ptr gs:[dword]

	{ 0x66, 0x90, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // xchg ax,ax  - canonical 2-byte NOP
	{ 0x66, 0x0F, 0x1F, 0x44, 6, 4, k_ENoRelativeOffsets }, // nop word ptr[rax+...] - canonical 6-byte NOP

	{ 0x81, 0x3A, 0x00, 0x00, 6, 2, k_ENoRelativeOffsets }, // cmp prt[rdx], 4 bytes

	{ 0x89, 0x70, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov dword ptr[rax+...],esi
	{ 0x89, 0x4C, 0x00, 0x00, 4, 2, k_ENoRelativeOffsets }, // mov dword ptr[rsp+...],ecx

	{ 0x8B, 0x40, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [rax+rawbyte]
	{ 0x8B, 0x41, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [rcx+rawbyte]
	{ 0x8B, 0x42, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [rdx+rawbyte]
	{ 0x8B, 0x43, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [rbx+rawbyte]
	{ 0x8B, 0x44, 0x00, 0x00, 4, 2, k_ENoRelativeOffsets },	// mov eax,dword ptr [rsp+rawbyte] 
	{ 0x8B, 0x45, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [rbp+rawbyte]
	{ 0x8B, 0x46, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [rsi+rawbyte]
	{ 0x8B, 0x47, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // mov eax,dword ptr [rdi+rawbyte]

	{ 0x8B, 0xC0, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,eax
	{ 0x8B, 0xC1, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,ecx
	{ 0x8B, 0xC2, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,edx
	{ 0x8B, 0xC3, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,ebx
	{ 0x8B, 0xC5, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,ebp
	{ 0x8B, 0xC6, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,esi
	{ 0x8B, 0xC7, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov eax,edi

	{ 0x8B, 0xD3, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,ebx
	{ 0x8B, 0xD5, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,ebp
	{ 0x8B, 0xD7, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // mov edx,edi

	{ 0xB8, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // mov eax, immediate dword
	{ 0xB9, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // mov ecx, immediate dword
	{ 0xBA, 0x00, 0x00, 0x00, 5, 1, k_ENoRelativeOffsets }, // mov edx, immediate dword

	{ 0xE8, 0x00, 0x00, 0x00, 5, 1, k_EDWORDOffsetAtByteTwo }, // call DWORD rel
	{ 0xE9, 0x00, 0x00, 0x00, 5, 1, k_EDWORDOffsetAtByteTwo }, // jmp DWORD rel
	{ 0xEB, 0x00, 0x00, 0x00, 2, 1, k_EBYTEOffsetAtByteTwo }, // jmp BYTE rel
	{ 0x90, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // nop
	{ 0xCC, 0x00, 0x00, 0x00, 1, 1, k_ENoRelativeOffsets }, // int 3

	// F0 is the lock prefix
	{ 0xF0, 0x83, 0x41, 0x00, 5, 3, k_ENoRelativeOffsets }, // lock add dword ptr[rcx+...], immediate
	{ 0xF0, 0x83, 0x05, 0x00, 8, 3, k_EDWORDOffsetAtByteFour }, // lock add dword ptr[rel], immediate byte

	{ 0xF6, 0xC1, 0x00, 0x00, 3, 2, k_ENoRelativeOffsets }, // test c1,byte

	{ 0xFF, 0x25, 0x00, 0x00, 6, 2, k_EDWORDOffsetAtByteThree }, // jmp dword offset
	{ 0xFF, 0xE0, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // jmp rax

	{ 0xFF, 0xF0, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rax
	{ 0xFF, 0xF1, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rcx
	{ 0xFF, 0xF2, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rdx
	{ 0xFF, 0xF3, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rbx
	{ 0xFF, 0xF4, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rsp
	{ 0xFF, 0xF5, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rbp
	{ 0xFF, 0xF6, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rsi
	{ 0xFF, 0xF7, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rdi
	{ 0xFF, 0xF8, 0x00, 0x00, 2, 2, k_ENoRelativeOffsets }, // push rsp
#endif
};

class CTrampolineRegionMutex
{
public:
	CTrampolineRegionMutex() { m_hMutex = ::CreateMutexA(NULL, FALSE, NULL); }
	void Release() { ReleaseMutex(m_hMutex); }

	bool BLock(DWORD dwTimeout)
	{
		if (WaitForSingleObject(m_hMutex, dwTimeout) != WAIT_OBJECT_0)
			return false;

		return true;
	}	

private:
	CTrampolineRegionMutex(const CTrampolineRegionMutex&);
	CTrampolineRegionMutex& operator=(const CTrampolineRegionMutex&);

	HANDLE m_hMutex;
};

class CDetourLock
{
public:
	CDetourLock() { InitializeCriticalSection(&m_cs); }
	~CDetourLock() { DeleteCriticalSection(&m_cs); }

	void Lock() { EnterCriticalSection(&m_cs); }
	void Unlock() { LeaveCriticalSection(&m_cs); }
private:
	CDetourLock(const CDetourLock&);
	CDetourLock& operator=(const CDetourLock&);

	CRITICAL_SECTION m_cs;
};

class GetLock
{
public:
	GetLock(CDetourLock& lock) : m_lock(lock) {	m_lock.Lock(); }
	~GetLock() { m_lock.Unlock(); }
private:
	GetLock(const GetLock&);
	GetLock& operator=(const GetLock&);

	CDetourLock& m_lock;
};

namespace cs_detour
{
	void UnhookFunc(BYTE* pRealFunctionAddr);
	bool HookFuncInternal(BYTE* pRealFunctionAddr, const BYTE* pHookFunctionAddr, void** ppRealFunctionAdr, BYTE** ppTrampolineAddressToReturn);
	bool HookFuncSafe(BYTE* pRealFunctionAddr, const BYTE* pHookFunctionAddr, void** ppRealFunctionAdr);
}