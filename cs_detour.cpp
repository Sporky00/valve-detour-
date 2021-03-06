#include "cs_detour.h"

//detour function copied straight from csgo source leak lmao
//must be super p undetected right??????????????????????????????????????

std::vector< void*> g_vecTrampolinesAllocated = {};
std::vector< void*> g_vecTrampolineRegionsReady = {};

std::map<void*, HookData_t> g_mapHookedFunctions = {};
std::set< const void* > g_setBlacklistedTrampolineSearchAddresses = {};

CDetourLock g_mapLock = {};
CTrampolineRegionMutex g_TrampolineRegionMutex = {};

inline DWORD GetSystemPageSize()
{
	static DWORD dwSystemPageSize = 0;

	if (!dwSystemPageSize)
	{
		SYSTEM_INFO sysInfo;
		::GetSystemInfo(&sysInfo);
		dwSystemPageSize = sysInfo.dwPageSize;
	}

	return dwSystemPageSize;
}

bool BIsAddressCommited(const void* pAddress)
{
	MEMORY_BASIC_INFORMATION memInfo = {};

	if (!VirtualQuery(pAddress, &memInfo, sizeof(memInfo)))
		return false;

	if (memInfo.State == MEM_COMMIT)
		return true;

	return false;
}

bool BIsAddressRangeExecutable(const void* pAddress, size_t length)
{
	MEMORY_BASIC_INFORMATION memInfo;
	if (!VirtualQuery((const void*)pAddress, &memInfo, sizeof(memInfo)))
		return false;

	if (memInfo.State != MEM_COMMIT)
		return false;

	if (memInfo.Protect != PAGE_EXECUTE && memInfo.Protect != PAGE_EXECUTE_READ &&
		memInfo.Protect != PAGE_EXECUTE_READWRITE && memInfo.Protect != PAGE_EXECUTE_WRITECOPY)
	{
		return false;
	}

	uintptr_t lastAddress = (uintptr_t)pAddress + length - 1;
	uintptr_t lastInRegion = (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize - 1;
	if (lastAddress <= lastInRegion)
		return true;

	// Start of this address range is executable. But what about subsequent regions?
	return BIsAddressRangeExecutable((const void*)(lastInRegion + 1), lastAddress - lastInRegion);
}

bool ParseOpcode(unsigned char* pOpcode, int& nLength, EOpCodeOffsetType& eOffsetType)
{
	for (int i = 0; i < sizeof(s_rgKnownOpCodes) / sizeof(s_rgKnownOpCodes[0]); i++)
	{
		const KnownOpCode_t& opcode = s_rgKnownOpCodes[i];

		if (pOpcode[0] == opcode.m_OpCodeB1)
		{
			if (opcode.m_cOpCodeBytesToMatch < 2 || pOpcode[1] == opcode.m_OpCodeB2)
			{
				if (opcode.m_cOpCodeBytesToMatch < 3 || pOpcode[2] == opcode.m_OpCodeB3)
				{
					if (opcode.m_cOpCodeBytesToMatch < 4 || pOpcode[3] == opcode.m_OpCodeB4)
					{
						nLength = opcode.m_TotalLength;
						eOffsetType = opcode.m_EOffsetType;
						return true;
					}
				}
			}
		}
	}

	return false;
}


BYTE* GetTrampolineRegionNearAddress(const void* pAddressToFindNear)
{
	g_TrampolineRegionMutex.BLock(1000);
	BYTE* pTrampolineAddress = NULL;

	std::vector<void*>::iterator iter;
	for (iter = g_vecTrampolineRegionsReady.begin(); iter != g_vecTrampolineRegionsReady.end(); ++iter)
	{
		int64_t qwAddress = (int64_t)(*iter);
		int64_t qwOffset = qwAddress - (int64_t)pAddressToFindNear;
		if (qwOffset < 0 && qwOffset > LONG_MIN || qwOffset > 0 && qwOffset + BYTES_FOR_TRAMPOLINE_ALLOCATION < LONG_MAX)
		{
			pTrampolineAddress = (BYTE*)qwAddress;
			g_vecTrampolineRegionsReady.erase(iter);
			break;
		}
	}

	g_TrampolineRegionMutex.Release();

	return pTrampolineAddress;
}

void AllocateNewTrampolineRegionsNearAddress(const void* pAddressToAllocNear)
{
	g_TrampolineRegionMutex.BLock(1000);

	if (g_setBlacklistedTrampolineSearchAddresses.find(pAddressToAllocNear) != g_setBlacklistedTrampolineSearchAddresses.end())
	{
		g_TrampolineRegionMutex.Release();
		return;
	}

	HANDLE hProc = GetCurrentProcess();
	DWORD dwSystemPageSize = GetSystemPageSize();

	BYTE* pTrampolineAddress = NULL;
	if (pAddressToAllocNear == NULL)
	{
		pTrampolineAddress = (BYTE*)VirtualAllocEx(hProc, NULL, dwSystemPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (pTrampolineAddress)
			g_vecTrampolinesAllocated.push_back(pTrampolineAddress);
	}
	else
	{
		int64_t qwPageToOffsetFrom = (int64_t)pAddressToAllocNear - ((int64_t)pAddressToAllocNear % dwSystemPageSize);

		int64_t qwPageToTryNegative = qwPageToOffsetFrom - dwSystemPageSize;
		int64_t qwPageToTryPositive = qwPageToOffsetFrom + dwSystemPageSize;

		bool bLoggedFailures = false;

		while (!pTrampolineAddress)
		{
			int64_t* pqwPageToTry;
			bool bDirectionPositive = false;
			if (qwPageToOffsetFrom - qwPageToTryNegative < qwPageToTryPositive - qwPageToOffsetFrom)
			{
				pqwPageToTry = &qwPageToTryNegative;
			}
			else
			{
				pqwPageToTry = &qwPageToTryPositive;
				bDirectionPositive = true;
			}

			MEMORY_BASIC_INFORMATION memInfo;
			if (!VirtualQuery((void*)(*pqwPageToTry), &memInfo, sizeof(memInfo)))
			{
				if (!bLoggedFailures)
					bLoggedFailures = true;
			}
			else
			{
				if (memInfo.State == MEM_FREE)
				{
					pTrampolineAddress = (BYTE*)VirtualAllocEx(hProc, (void*)(*pqwPageToTry), dwSystemPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
					if (!pTrampolineAddress)
					{
						if (bDirectionPositive)
							qwPageToTryPositive += dwSystemPageSize;
						else
							qwPageToTryNegative -= dwSystemPageSize;
						continue;
					}
					g_vecTrampolinesAllocated.push_back(pTrampolineAddress);

					break;
				}
			}

			if (bDirectionPositive)
				qwPageToTryPositive += memInfo.RegionSize;
			else
				qwPageToTryNegative -= memInfo.RegionSize;

			if (qwPageToTryPositive + dwSystemPageSize >= (int64_t)pAddressToAllocNear + LONG_MAX && qwPageToTryNegative <= (int64_t)pAddressToAllocNear - LONG_MIN)
			{
				g_setBlacklistedTrampolineSearchAddresses.insert(pAddressToAllocNear);
				break;
			}
		}
	}

	if (pTrampolineAddress)
	{
		BYTE* pNextTrampolineAddress = pTrampolineAddress;
		while (pNextTrampolineAddress <= pTrampolineAddress + dwSystemPageSize - BYTES_FOR_TRAMPOLINE_ALLOCATION)
		{
			g_vecTrampolineRegionsReady.push_back(pNextTrampolineAddress);
			pNextTrampolineAddress += BYTES_FOR_TRAMPOLINE_ALLOCATION;
		}
	}

	g_TrampolineRegionMutex.Release();
	return;
}

void cs_detour::UnhookFunc(BYTE* pRealFunctionAddr)
{
	if (!pRealFunctionAddr)
		return;

	HookData_t hookData;
	{
		GetLock getLock(g_mapLock);

		std::map<void*, HookData_t>::iterator iter;
		iter = g_mapHookedFunctions.find((void*)pRealFunctionAddr);

		if (iter == g_mapHookedFunctions.end())
		{
			return;
		}
		else
		{
			hookData = iter->second;
			g_mapHookedFunctions.erase(iter);
		}
	}

	DWORD dwSystemPageSize = GetSystemPageSize();
	HANDLE hProc = GetCurrentProcess();

	BYTE* pFuncToUnhook = hookData.m_pFuncHookedAddr;
	void* pLastHookByte = pFuncToUnhook + hookData.m_nOriginalPreambleLength - 1;
	bool bHookSpansTwoPages = ((uintptr_t)pFuncToUnhook / dwSystemPageSize != (uintptr_t)pLastHookByte / dwSystemPageSize);

	union
	{
		struct
		{
			uint8_t opcode;
			int8_t offset;
		} s;

		uint16_t u16;

	} smalljump;

	smalljump.s.opcode = 0xEB;
	smalljump.s.offset = (int8_t)(hookData.m_pTrampolineRealFunc - (hookData.m_pTrampolineEntryPoint + 2));

	*(UNALIGNED uint16_t*)hookData.m_pTrampolineEntryPoint = smalljump.u16;
	FlushInstructionCache(hProc, hookData.m_pTrampolineEntryPoint, 2);

	if (!BIsAddressCommited(pFuncToUnhook))
		return;

	if (*pFuncToUnhook != 0xE9)
		return;

	BYTE* pJumpTarget = pFuncToUnhook + 5 + *(UNALIGNED int32_t*)(pFuncToUnhook + 1);

	if (pJumpTarget != hookData.m_pTrampolineEntryPoint)
		return;

	DWORD dwOldProtectionLevel = 0;
	DWORD dwOldProtectionLevel2 = 0;
	DWORD dwIgnore;

	if (!VirtualProtect(pFuncToUnhook, hookData.m_nOriginalPreambleLength, PAGE_EXECUTE_READWRITE, &dwOldProtectionLevel))
		return;

	if (bHookSpansTwoPages && !VirtualProtect(pLastHookByte, 1, PAGE_EXECUTE_READWRITE, &dwOldProtectionLevel2))
	{
		VirtualProtect(pFuncToUnhook, 1, dwOldProtectionLevel, &dwIgnore);
		return;
	}

	memcpy(pFuncToUnhook, hookData.m_rgOriginalPreambleCode, hookData.m_nOriginalPreambleLength);
	FlushInstructionCache(hProc, pFuncToUnhook, hookData.m_nOriginalPreambleLength);

	if (bHookSpansTwoPages && dwOldProtectionLevel2 != PAGE_EXECUTE_READWRITE && dwOldProtectionLevel2 != PAGE_EXECUTE_WRITECOPY)
		VirtualProtect(pLastHookByte, 1, dwOldProtectionLevel2, &dwIgnore);

	if (dwOldProtectionLevel != PAGE_EXECUTE_READWRITE && dwOldProtectionLevel != PAGE_EXECUTE_WRITECOPY)
		VirtualProtect(pFuncToUnhook, 1, dwOldProtectionLevel, &dwIgnore);
};

bool cs_detour::HookFuncInternal(BYTE* pRealFunctionAddr, const BYTE* pHookFunctionAddr, void** ppRealFunctionAdr, BYTE** ppTrampolineAddressToReturn)
{
	if (!pRealFunctionAddr)
		return false;

	if (!pHookFunctionAddr)
		return false;

	UnhookFunc(pRealFunctionAddr);

	HANDLE hProc = GetCurrentProcess();
	BYTE* pFuncToHook = pRealFunctionAddr;

	BIsAddressRangeExecutable(pFuncToHook, sizeof(JumpCodeRelative_t));

	if ((BYTE)pFuncToHook[0] == 0xEB)
		return false;

	JumpCodeRelative_t sRelativeJumpCode;
	sRelativeJumpCode.m_JmpOpCode = 0xE9;

	JumpCodeDirectX64_t sDirectX64JumpCode;
	sDirectX64JumpCode.m_JmpOpCode[0] = 0xFF;
	sDirectX64JumpCode.m_JmpOpCode[1] = 0x25;
	sDirectX64JumpCode.m_JumpPtrOffset = 0;

	int32_t nHookCodeLength = 0;
	BYTE* pOpcode = pFuncToHook;
	bool bParsedRETOpcode = false;

	BYTE rgCopiedCode[MAX_HOOKED_FUNCTION_PREAMBLE_LENGTH];

	while (nHookCodeLength < sizeof(JumpCodeRelative_t))
	{
		int nLength;
		EOpCodeOffsetType eOffsetType;
		bool bKnown = ParseOpcode(pOpcode, nLength, eOffsetType);

		if (bKnown)
		{
			if (bParsedRETOpcode && *pOpcode != 0xCC && *pOpcode != 0x90)
				bKnown = false;

			if (*pOpcode == 0xC3 || *pOpcode == 0xC2)
				bParsedRETOpcode = true;
		}

		if (!bKnown || (eOffsetType != k_ENoRelativeOffsets && eOffsetType != k_EDWORDOffsetAtByteTwo && eOffsetType != k_EDWORDOffsetAtByteThree && eOffsetType != k_EBYTEOffsetAtByteTwo && eOffsetType != k_EDWORDOffsetAtByteFour))
			return false;

		if (sizeof(rgCopiedCode) - nHookCodeLength - nLength < 0)
			return false;

		memcpy(&rgCopiedCode[nHookCodeLength], pOpcode, nLength);

		pOpcode += nLength;
		nHookCodeLength += nLength;
	}

	if (nHookCodeLength > MAX_HOOKED_FUNCTION_PREAMBLE_LENGTH)
		return false;

	BYTE* pTrampolineAddress = GetTrampolineRegionNearAddress(pFuncToHook);
	if (!pTrampolineAddress)
	{
		AllocateNewTrampolineRegionsNearAddress(pFuncToHook);
		pTrampolineAddress = GetTrampolineRegionNearAddress(pFuncToHook);
	}

	if (!pTrampolineAddress)
		return false;

	*ppTrampolineAddressToReturn = pTrampolineAddress;

	HookData_t SavedData;
	memcpy(SavedData.m_rgOriginalPreambleCode, rgCopiedCode, MAX_HOOKED_FUNCTION_PREAMBLE_LENGTH);
	SavedData.m_nOriginalPreambleLength = nHookCodeLength;
	SavedData.m_pFuncHookedAddr = pFuncToHook;
	SavedData.m_pTrampolineRealFunc = NULL;
	SavedData.m_pTrampolineEntryPoint = NULL;

	int nFixupPosition = 0;
	while (nFixupPosition < nHookCodeLength)
	{
		int nLength;
		EOpCodeOffsetType eOffsetType;
		bool bKnown = ParseOpcode(&rgCopiedCode[nFixupPosition], nLength, eOffsetType);

		if (!bKnown || (eOffsetType != k_ENoRelativeOffsets && eOffsetType != k_EDWORDOffsetAtByteTwo && eOffsetType != k_EDWORDOffsetAtByteThree && eOffsetType != k_EBYTEOffsetAtByteTwo && eOffsetType != k_EDWORDOffsetAtByteFour))
			return false;

		int iPositionOfDWORDFixup = -1;
		switch (eOffsetType)
		{
		case k_ENoRelativeOffsets:
			break;

		case k_EDWORDOffsetAtByteTwo:
			iPositionOfDWORDFixup = 1;
			break;

		case k_EDWORDOffsetAtByteThree:
			iPositionOfDWORDFixup = 2;
			break;

		case k_EDWORDOffsetAtByteFour:
			iPositionOfDWORDFixup = 3;
			break;

		case k_EBYTEOffsetAtByteTwo:
			if ((BYTE)rgCopiedCode[nFixupPosition] == 0xEB && nLength == 2)
			{
				if (nHookCodeLength + 3 > MAX_HOOKED_FUNCTION_PREAMBLE_LENGTH)
					return false;

				rgCopiedCode[nFixupPosition] = 0xE9;
				memmove(&rgCopiedCode[nFixupPosition + 5], &rgCopiedCode[nFixupPosition + 2], nHookCodeLength - nFixupPosition - 2);

				int32_t iOffset = (int8_t)rgCopiedCode[nFixupPosition + 1] - 3;
				memcpy(&rgCopiedCode[nFixupPosition + 1], &iOffset, 4);
				iPositionOfDWORDFixup = 1;

				nLength += 3;
				nHookCodeLength += 3;
			}
			else
				return false;
			break;
		default:
			return false;
		}

		if (iPositionOfDWORDFixup != -1)
		{
			int32_t iOffset;
			memcpy(&iOffset, &rgCopiedCode[nFixupPosition + iPositionOfDWORDFixup], 4);

			intptr_t iNewOffset = iOffset + (intptr_t)pFuncToHook - (intptr_t)pTrampolineAddress;
			iOffset = (int32_t)iNewOffset;

			if (sizeof(intptr_t) > sizeof(int32_t) && (intptr_t)iOffset != iNewOffset)
				return false;

			memcpy(&rgCopiedCode[nFixupPosition + iPositionOfDWORDFixup], &iOffset, 4);
		}

		nFixupPosition += nLength;
	}

	BYTE* pBeginTrampoline = pTrampolineAddress;
	SavedData.m_pTrampolineRealFunc = pTrampolineAddress;

	memcpy(pTrampolineAddress, rgCopiedCode, nHookCodeLength);
	pTrampolineAddress += nHookCodeLength;

	intptr_t lJumpTarget = (intptr_t)pFuncToHook + nHookCodeLength;
	intptr_t lJumpInstruction = (intptr_t)pTrampolineAddress;
	intptr_t lJumpOffset = lJumpTarget - lJumpInstruction - sizeof(JumpCodeRelative_t);
	sRelativeJumpCode.m_JumpOffset = (int32_t)lJumpOffset;

	if (sizeof(intptr_t) > sizeof(int32_t) && (intptr_t)sRelativeJumpCode.m_JumpOffset != lJumpOffset)
	{
		// Use a direct 64-bit jump instead
		sDirectX64JumpCode.m_QWORDTarget = lJumpTarget;
		memcpy(pTrampolineAddress, &sDirectX64JumpCode, sizeof(JumpCodeDirectX64_t));
		pTrampolineAddress += sizeof(JumpCodeDirectX64_t);
	}
	else
	{
		memcpy(pTrampolineAddress, &sRelativeJumpCode, sizeof(JumpCodeRelative_t));
		pTrampolineAddress += sizeof(JumpCodeRelative_t);
	}

	SavedData.m_pTrampolineEntryPoint = pTrampolineAddress;
	BYTE* pIntermediateJumpLocation = pTrampolineAddress;

	lJumpTarget = (intptr_t)pHookFunctionAddr;
	lJumpInstruction = (intptr_t)pIntermediateJumpLocation;
	lJumpOffset = lJumpTarget - lJumpInstruction - sizeof(JumpCodeRelative_t);
	sRelativeJumpCode.m_JumpOffset = (int32_t)lJumpOffset;

	if (sizeof(intptr_t) > sizeof(int32_t) && (intptr_t)sRelativeJumpCode.m_JumpOffset != lJumpOffset)
	{
		sDirectX64JumpCode.m_QWORDTarget = lJumpTarget;
		memcpy(pTrampolineAddress, &sDirectX64JumpCode, sizeof(JumpCodeDirectX64_t));
		pTrampolineAddress += sizeof(JumpCodeDirectX64_t);
	}
	else
	{
		memcpy(pTrampolineAddress, &sRelativeJumpCode, sizeof(JumpCodeRelative_t));
		pTrampolineAddress += sizeof(JumpCodeRelative_t);
	}

	FlushInstructionCache(hProc, pBeginTrampoline, pTrampolineAddress - pBeginTrampoline);

	lJumpTarget = (intptr_t)pIntermediateJumpLocation;
	lJumpInstruction = (intptr_t)pFuncToHook;
	lJumpOffset = lJumpTarget - lJumpInstruction - sizeof(JumpCodeRelative_t);
	sRelativeJumpCode.m_JumpOffset = (int32_t)lJumpOffset;

	if (sizeof(intptr_t) > sizeof(int32_t) && (intptr_t)sRelativeJumpCode.m_JumpOffset != lJumpOffset)
		return false;

	DWORD dwSystemPageSize = GetSystemPageSize();

	void* pLastHookByte = pFuncToHook + sizeof(JumpCodeRelative_t) - 1;
	bool bHookSpansTwoPages = ((uintptr_t)pFuncToHook / dwSystemPageSize != (uintptr_t)pLastHookByte / dwSystemPageSize);

	DWORD dwOldProtectionLevel = 0;
	DWORD dwOldProtectionLevel2 = 0;
	DWORD dwIgnore;

	if (!VirtualProtect(pFuncToHook, 1, PAGE_EXECUTE_READWRITE, &dwOldProtectionLevel))
		return false;

	if (bHookSpansTwoPages && !VirtualProtect(pLastHookByte, 1, PAGE_EXECUTE_READWRITE, &dwOldProtectionLevel2))
	{
		VirtualProtect(pFuncToHook, 1, dwOldProtectionLevel, &dwIgnore);
		return false;
	}

	bool bSuccess = false;

	*ppRealFunctionAdr = pBeginTrampoline;

	SIZE_T cBytesWritten;
	if (WriteProcessMemory(hProc, (void*)pFuncToHook, &sRelativeJumpCode, sizeof(JumpCodeRelative_t), &cBytesWritten))
	{
		*ppTrampolineAddressToReturn = NULL;
		bSuccess = true;

		FlushInstructionCache(hProc, (void*)pFuncToHook, sizeof(JumpCodeRelative_t));
	}

	if (bHookSpansTwoPages && dwOldProtectionLevel2 != PAGE_EXECUTE_READWRITE && dwOldProtectionLevel2 != PAGE_EXECUTE_WRITECOPY)
		VirtualProtect(pLastHookByte, 1, dwOldProtectionLevel2, &dwIgnore);

	if (dwOldProtectionLevel != PAGE_EXECUTE_READWRITE && dwOldProtectionLevel != PAGE_EXECUTE_WRITECOPY)
		VirtualProtect(pFuncToHook, 1, dwOldProtectionLevel, &dwIgnore);

	if (bSuccess)
	{
		GetLock getLock(g_mapLock);
		g_mapHookedFunctions[(void*)pRealFunctionAddr] = SavedData;
	}

	return bSuccess;
}

bool cs_detour::HookFuncSafe(BYTE* pRealFunctionAddr, const BYTE* pHookFunctionAddr, void** ppRealFunctionAdr)
{
	BYTE* pTrampolineAddressToReturn = NULL;
	bool bRet = HookFuncInternal(pRealFunctionAddr, pHookFunctionAddr, ppRealFunctionAdr, &pTrampolineAddressToReturn);

	if (pTrampolineAddressToReturn)
	{
		g_TrampolineRegionMutex.BLock(1000);

		g_vecTrampolineRegionsReady.push_back(pTrampolineAddressToReturn);
		g_TrampolineRegionMutex.Release();
	}

	return bRet;
}