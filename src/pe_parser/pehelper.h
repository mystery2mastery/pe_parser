#pragma once

#include <windows.h>
#include <winnt.h>

// Define a macro to print a field with its name and format specifier
#define PRINT_PE_FIELD_TYPE(pHeader, field, type) printf(#field ": %" #type "\n", (pHeader)->field)
#define PRINT_PE_FIELD(pHeader, field) printf(#field ": 0x%.4X\n", (pHeader)->field)

// Union for IMAGE_NT_HEADERS
// what this means is: The largest of DWORD, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64 is allocated. So, a size of IMAGE_NT_HEADERS64 is allocated.
// Now, within the allocation:
// the full allocation size is interpreted as 'Signature'. So, we can access 'Signature' (DWORD = 4 bytes) only.
// the full allocation size is interpreted as 'NtHeaders32'. We can acess 'NtHeaders32'. Since NtHeaders32 itself is a structure, its first element is 'Signature'.
// the full allocation size is interpreted as 'NtHeaders64'. Similarly we can access 'NtHeaders64'. Since NtHeaders64 itself is a structure, its first element is 'Signature'.
// Why are we putting 'Signature' within the union when we can interpret the union as NtHeaders32 or NtHeaders64 and access the 'Signature' field and then

typedef union _IMAGE_NT_HEADERS_UNION {
	//DWORD Signature;
	IMAGE_NT_HEADERS32 NtHeader32;
	IMAGE_NT_HEADERS64 NtHeader64;
} IMAGE_NT_HEADERS_UNION, * PIMAGE_NT_HEADERS_UNION;

#ifdef __cplusplus
extern "C" {
#endif

	// all of your C code here
	void PrintDosHeader(PIMAGE_DOS_HEADER pDosHeader);



	void PrintNtHeader(PIMAGE_NT_HEADERS pNtHeader);

	void PrintFileHeader(PIMAGE_FILE_HEADER pFileHeader);

	void PrintOptionalHeader(PIMAGE_OPTIONAL_HEADER pOptHeader);

	void PrintDataDirectories(PIMAGE_OPTIONAL_HEADER pOptHeader);

	void PrintSectionHeaders(PIMAGE_NT_HEADERS pNtHeader, size_t szNoOfSections, BYTE * pbPEBase);

	void PrintSectionData(PIMAGE_SECTION_HEADER pSecHeader, BYTE * pbPEBase);

	BOOL VerifyDosSignature(PIMAGE_DOS_HEADER pDosHeader);

	BOOL VerifyNtSignature(PIMAGE_NT_HEADERS pNtHeader);

	BOOL IsValidPEFile(const char* szFilePath);




#ifdef __cplusplus
}
#endif