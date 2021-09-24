// SyscallNumberFinder.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "stdio.h"

#include "Header.h"

ulonglong ExtractSyscallNumberFromCode(uchar* pCode)
{
	if(pCode)
	{
		//assuming code has this pattern
		//"4C 8B D1 B8 8E 01 00 00 F6 04 25 08 03 FE 7F 01 75 03 0F 05 C3 CD 2E C3"
		ulong Syscall = *(ulong*)(&pCode[4]);
		return Syscall;
	}
	return -1;
}


bool IsSyscallPattern(uchar* pCode)
{
	if( memcmp(&pCode[0],"\x4C\x8B\xD1\xB8",4))
	{
		return false;
	}
	ulong Syscall_temp = *(ulong*)(&pCode[4]);
	if( memcmp(&pCode[8],"\xF6\x04\x25\x08\x03\xFE\x7F\x01\x75\x03\x0F\x05\xC3\xCD\x2E\xC3",16))
	{
		return false;
	}

	return true;
}

ulonglong GetBaseAndSizeOfCode(ulonglong PeHeader,ulong* pSizeOfCode)
{
	if(PeHeader)
	{
		_IMAGE_DOS_HEADER* pDos = (_IMAGE_DOS_HEADER*)PeHeader;

		ulong rva_nt = pDos->e_lfanew;

		_IMAGE_NT_HEADERS64* pNT64 = (_IMAGE_NT_HEADERS64*)(PeHeader + rva_nt);

		if(pSizeOfCode) *pSizeOfCode = pNT64->OptionalHeader.SizeOfCode;
		return pNT64->OptionalHeader.BaseOfCode;
	}
	return 0;
}

//returns 0 upon failure
char* GetExportedFunctionNameFromAddress(ulonglong PeHeader,uchar* Address)
{
	if(PeHeader)
	{
		_IMAGE_DOS_HEADER* pDos = (_IMAGE_DOS_HEADER*)PeHeader;

		ulong rva_nt = pDos->e_lfanew;

		_IMAGE_NT_HEADERS64* pNT64 = (_IMAGE_NT_HEADERS64*)(PeHeader + rva_nt);

		ulong rva_export = pNT64->OptionalHeader.DataDirectory[0].VirtualAddress;
		ulong sz_export  = pNT64->OptionalHeader.DataDirectory[0].Size;

		_IMAGE_EXPORT_DIRECTORY* pExport = (_IMAGE_EXPORT_DIRECTORY*)(PeHeader + rva_export);


		ulong NumFunctions = pExport->NumberOfFunctions;
		ulong NumNames = pExport->NumberOfNames;
		ulong BaseX = pExport->Base;
		printf("Base: %X\r\n",BaseX);

		ulong rva_AddressOfFunctions = pExport->AddressOfFunctions;
		ulong* pAddressOfFunctions = (ulong*)(PeHeader + rva_AddressOfFunctions);

		ulong rva_AddressOfNames = pExport->AddressOfNames;
		ulong* pAddressOfNames = (ulong*)(PeHeader + rva_AddressOfNames);

		ulong rva_AddressOfNameOrdinals = pExport->AddressOfNameOrdinals;
		ushort* pAddressOfNameOrdinals = (ushort*)(PeHeader + rva_AddressOfNameOrdinals);

		ulong rva = ((ulonglong)Address) - (PeHeader);

		for(ulong i=0;i<NumFunctions;i++)
		{
			if(pAddressOfFunctions[i] == rva)
			{
				for(ulong z=0;z<NumNames;z++)
				{
					if( pAddressOfNameOrdinals[z] == i)
					{
						uchar* ExportedName = (uchar*)( PeHeader + pAddressOfNames[z] );
						//printf("%s\r\n",ExportedName);
						return (char*)ExportedName;
					}
				}
			}
		}
	}
	return 0;
}


int _tmain(int argc, _TCHAR* argv[])
{
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");

	if(argc == 2)
	{
		wchar_t* pSyscallName_w = argv[1];

		ulong LenX = wcslen(pSyscallName_w);

		ulong szToAlloc = LenX + 1;
		char* pSyscallName = (char*)LocalAlloc(LMEM_ZEROINIT,szToAlloc);
		if(!pSyscallName)
		{
			printf("Error allocating memory\r\n");
			return -1;
		}

		WideCharToMultiByte(0,0,pSyscallName_w,LenX,pSyscallName,LenX,0,0);
		//printf("%s\r\n",pSyscallName);

		uchar* pAddrFunc = (uchar*)GetProcAddress(hNtdll,pSyscallName);
		if(!pAddrFunc)
		{
			printf("Syscall not found in ntdll.dll\r\n");
			return -2;
		}

		if(!IsSyscallPattern(pAddrFunc))
		{
			printf("This function is not a Syscall.\r\n");
			return -3;
		}

		ulong SyscallNumber = ExtractSyscallNumberFromCode(pAddrFunc);
		wprintf(L"%s: 0x%X (%d)\r\n",pSyscallName_w,SyscallNumber,SyscallNumber);

		return 0;
	}
	else if(argc == 3)
	{
		if( wcsicmp(argv[1],L"/Number") == 0)
		{
			ulong x = wcstoul(argv[2],0,0x10);
			//printf("%X\r\n",x);


			ulong szOfCode_ntdll = 0;
			ulong baseOfCode_ntdll = GetBaseAndSizeOfCode((ulonglong)hNtdll,&szOfCode_ntdll);
			printf("Base Of Code: %X, Size Of Code: %X\r\n",szOfCode_ntdll,szOfCode_ntdll);

			uchar* StartScanningAddr = ((uchar*)hNtdll) + baseOfCode_ntdll;
			uchar* EndScanningAddr = StartScanningAddr + szOfCode_ntdll;

			printf("Scanning Start: %I64X, End: %I64X\r\n",StartScanningAddr,EndScanningAddr);



			uchar* i = StartScanningAddr;
			while(i<EndScanningAddr)
			{
				//Assuming this pattern
				////"4C 8B D1 B8 8E 01 00 00 F6 04 25 08 03 FE 7F 01 75 03 0F 05 C3 CD 2E C3"

				if( memcmp(&i[0],"\x4C\x8B\xD1\xB8",4))
				{
					i++;
					continue;
				}

				ulong Syscall_temp = *(ulong*)(&i[4]);

				if( memcmp(&i[8],"\xF6\x04\x25\x08\x03\xFE\x7F\x01\x75\x03\x0F\x05\xC3\xCD\x2E\xC3",16))
				{
					i++;
					continue;
				}

				ulong Syscall = Syscall_temp;

				if(Syscall == x)
				{
					printf("Syscall: %X found at: %I64X\r\n",Syscall,i);

					char* pFuncName = 
						GetExportedFunctionNameFromAddress( (ulonglong)hNtdll,i);

					printf("Syscall Name: %s\r\n",pFuncName);
					return 0;
				}


				i += 24;
			}
		}
	}
	printf("Usage: SyscallNumberFinder.exe NtDelayExecution\r\n");
	printf("       SyscallNumberFinder.exe /Number 0x34\r\n");
	return -7;
}

