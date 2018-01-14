#include "pe_info.h"
#include <iostream>
#include <windows.h>
#include <algorithm>
#include <Dbghelp.h>

#pragma comment(lib,"imageHlp.lib")
using namespace std;

HANDLE ImageBase;
PIMAGE_DOS_HEADER pDH = NULL;
PIMAGE_NT_HEADERS pNTH = NULL;
PIMAGE_FILE_HEADER pFH = NULL;
PIMAGE_OPTIONAL_HEADER pOH = NULL;
PIMAGE_SECTION_HEADER pSH = NULL;
PIMAGE_IMPORT_DESCRIPTOR pID = NULL;
PIMAGE_EXPORT_DIRECTORY pED = NULL;
PIMAGE_THUNK_DATA dwThunk;
PIMAGE_IMPORT_BY_NAME pBN = NULL;

bool PE_info::Is_PE_file(LPTSTR lpFilePath) {
	HANDLE hFile;
	HANDLE hMapping;

	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNTH = NULL;
	hFile = CreateFile(lpFilePath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	if (!hFile) {
		return false;
	}//open failed
	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!hMapping) {
		CloseHandle(hFile);
		return false;
	}//create mapping failed
	ImageBase = MapViewOfFile(hMapping,FILE_MAP_READ,0,0,0);//use ImageBase to access the binary 
	if (!ImageBase) {
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return false;
	}//get the imagebase file
	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE) {
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return false;
	}
	pNTH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	if (pNTH->Signature != IMAGE_NT_SIGNATURE) {
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return false;
	}//check the NT signature
	return true;
}

void PE_info::SHOW_DOS_HEADER() {
	pDH = (PIMAGE_DOS_HEADER)ImageBase;
	cout << "-------------------IMAGE DOS HEADER-------------------" << endl;
	cout << "DOS header:" << endl;
	char OFF_nt[20];
	_itoa_s(pDH->e_lfanew,OFF_nt,16);
	cout << "           Offset to the NT header: " << OFF_nt << endl;
	cout << "-------------------END OF DOS HEADER------------------" << endl;
}

void PE_info::SHOW_NT_HEADER() {
	pNTH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	cout << endl;
	cout << "-------------------IMAGE NT HEADER--------------------" << endl;
	cout << "NT header:" << endl; 
	SHOW_FILE_HEADER();
	SHOW_OPTIONAL_HEADER();
	cout << "------------------END OF NT HEADER--------------------" << endl;
}

void PE_info::SHOW_FILE_HEADER() {
	pFH = &pNTH->FileHeader;
	if (!pFH) {
		return;
	}
	cout << endl;
	cout << "IMAGE FILE header:" << endl;

	//print the machine
	if (pFH->Machine == 332) {
		cout << "                  Machine: x86 " << endl;
	}
	else if (pFH->Machine == 512) {
		cout << "                  Machine: Intel Itanium " << endl;
	}
	else if (pFH->Machine == 34404) {
		cout << "                  Machine: x64 " << endl;
	}

	cout << "                  Number of Sections: " << hex << pFH->NumberOfSections << endl;
	cout << "                  TImeDateStamp: " << hex << pFH->TimeDateStamp << endl;
	cout << "                  SizeofOptionalHeader: " << hex << pFH->SizeOfOptionalHeader << endl;
	cout << "                  Characteristics: " << hex << pFH->Characteristics << endl;
}

void PE_info::SHOW_OPTIONAL_HEADER() {
	pOH = &pNTH->OptionalHeader;
	cout << endl;
	cout << "IMAGE OPTINAL header:" << endl;
	cout << "                  AddressofEntrypoint:" << hex << pOH->AddressOfEntryPoint << endl;
	cout << "                  BaseofCode:" << hex << pOH->BaseOfCode << endl;
	cout << "                  BaseofData:" << hex << pOH->BaseOfData << endl;
	cout << "                  ImageBase:" << hex << pOH->ImageBase << endl;
	cout << "                  SectionAlignment:" << hex << pOH->SectionAlignment << endl;
	cout << "                  FileAlignment:" << hex << pOH->FileAlignment << endl;
	cout << "                  MajorOperatingSystemVersion:" << hex << pOH->MajorOperatingSystemVersion << endl;
	cout << "                  MinorOperationSystemVersion:" << hex << pOH->MinorOperatingSystemVersion << endl;
	cout << "                  Subsystem:" << hex << pOH->Subsystem << endl;
	cout << "                  NumberofRvaAndSizes:" << hex << pOH->NumberOfRvaAndSizes << endl;
	SHOW_DATADIR_INFO();
}

void PE_info::SHOW_DATADIR_INFO() {
	cout << "                  Data Directory:" << endl;
	cout << "                                 Export table RVA:" << hex << pOH->DataDirectory[0].VirtualAddress << endl;
	cout << "                                 Export table size:" << hex << pOH->DataDirectory[0].Size << endl;
	cout << "                                 Import table RVA:" << hex << pOH->DataDirectory[1].VirtualAddress << endl;
	cout << "                                 Import table size:" << hex << pOH->DataDirectory[1].Size << endl;
	cout << "                                 Resource table RVA:" << hex << pOH->DataDirectory[2].VirtualAddress << endl;
	cout << "                                 Resource table size:" << hex << pOH->DataDirectory[2].Size << endl;
}

void PE_info::SHOW_SECTIONS() {
	pSH = IMAGE_FIRST_SECTION(pNTH);
	cout << endl;
	cout << "-------------------SECTION HEADER--------------------" << endl;
	for (int i = 0; i < pFH->NumberOfSections; i++) {
		cout << "Section name:" << pSH->Name << endl;
		cout << "             Virtual Size:" << pSH->Misc.VirtualSize << endl;
		cout << "             Virtual address:" << pSH->VirtualAddress << endl;
		cout << "             SizeofRawData:" << pSH->SizeOfRawData << endl;
		cout << "             PointertoRelocations:" << pSH->PointerToRelocations << endl;
		cout << "             Characteristics:" << pSH->Characteristics << endl;
		pSH++;
	}
	cout << "----------------END OF SECTION HEADER----------------" << endl;
}

void PE_info::SHOW_IMPORT_DIR_INFO() {
	DWORD dwDatastartRva;
	dwDatastartRva = pOH->DataDirectory[1].VirtualAddress;
	pID = (PIMAGE_IMPORT_DESCRIPTOR)ImageRvaToVa(pNTH,ImageBase,dwDatastartRva,NULL);
	if (!pID) {
		int error = GetLastError();
		if (error == 0) {
			cout << "This file is not included with Import table!" << endl;
		}
		else {
			cout << "Can't get Image Import Descriptor! error code: " << error << endl;
		}
		return;
	}
	cout << endl;
	cout << "------------------IMPORT DIR INFO-------------------" << endl;
	while (pID->FirstThunk) {
		cout << "NameRva: " << hex << pID->Name << endl;
		cout << "Name(String): " << hex << (char *)ImageRvaToVa(pNTH, ImageBase, pID->Name, NULL) << endl;
		cout << "OrinalFirstThunk: " << hex << pID->OriginalFirstThunk << endl;
		cout << "TimeDateStamp: " << hex << pID->TimeDateStamp << endl;
		cout << "FirstThunk: " << hex << pID->FirstThunk << endl;
		SHOW_IMPORT_FUNC();
		cout << endl;
		pID++;
	}
	cout << "---------------END OF IMPORT DIR INFO---------------" << endl;
}

void PE_info::SHOW_IMPORT_FUNC() {
	cout << "Function names:(IMAGE_IMPORT_BY_NAME) " << endl;
	dwThunk = (PIMAGE_THUNK_DATA)ImageRvaToVa(pNTH, ImageBase, pID->OriginalFirstThunk, NULL);
	while (dwThunk->u1.AddressOfData) {
		pBN = (PIMAGE_IMPORT_BY_NAME)ImageRvaToVa(pNTH, ImageBase, dwThunk->u1.AddressOfData, NULL);
		if (!pBN) {
			cout << "find Image Import by name failed! " << endl;
			return;
		}
		cout << "               " << pBN->Name << endl;
		dwThunk++;
	}
}

void PE_info::SHOW_EXPORT_DIR_INFO() {
	pED = (PIMAGE_EXPORT_DIRECTORY)ImageRvaToVa(pNTH, ImageBase, pOH->DataDirectory[0].VirtualAddress,NULL);
	if (!pED) {
		int error = GetLastError();
		if (error == 0) {
			cout << "This file is not included with Export table!" << endl;
		}
		else {
			cout << "Can't get Export Directory error code: " << error << endl;
		}
		return;
	}
	cout << endl;
	cout << "------------------EXPORT DIR INFO-------------------" << endl;
	cout << "Name: " << (char *)ImageRvaToVa(pNTH, ImageBase, pED->Name, NULL) << endl;
	cout << "TimeDateStamp: " << hex << pED->TimeDateStamp << endl;
	cout << "MajorVersion: " << hex << pED->MajorVersion << endl;
	cout << "MinorVersion: " << hex << pED->MinorVersion << endl;
	cout << "Base: " << hex << pED->Base << endl;
	cout << "NumberofFunctions: " << hex << pED->NumberOfFunctions << endl;
	cout << "NumberofNames: " << hex << pED->NumberOfNames << endl;
	cout << "AddressofNames: " << hex << pED->AddressOfNames << endl;
	cout << "AddressofFunctions: " << hex << pED->AddressOfFunctions << endl;
	cout << "AddressofNameOrdinals: " << hex << pED->AddressOfNameOrdinals << endl;
	SHOW_EXPORT_FUNC();
	cout << "---------------END OF EXPORT DIR INFO----------------" << endl;
}

void PE_info::SHOW_EXPORT_FUNC() {
	PDWORD pdwFuncs, pdwNames;
	PWORD pdwOrd;

	pdwOrd = (PWORD)ImageRvaToVa(pNTH,ImageBase,pED->AddressOfNameOrdinals,NULL);
	pdwFuncs = (PDWORD)ImageRvaToVa(pNTH, ImageBase,pED->AddressOfFunctions, NULL);
	pdwNames = (PDWORD)ImageRvaToVa(pNTH, ImageBase, pED->AddressOfNames, NULL);

	for (int i = 0; i < (pED->NumberOfFunctions); i++) {
		if (*pdwFuncs) { //there is a function
			for (int j = 0; j < (pED->NumberOfNames); j++) {
				if (i == pdwOrd[j]) { // the jth element in the NameOridinal table is i
					cout << (char *)ImageRvaToVa(pNTH, ImageBase, pdwNames[j], NULL) << endl;
				}
			}
		}
		pdwFuncs++;
	}
}