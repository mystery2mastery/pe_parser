#include "pehelper.h"

#include <stdio.h>

#include <windows.h>
#include <winnt.h>

#include "hexdump/hexdump.h"


/*
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
*/
void PrintDosHeader(PIMAGE_DOS_HEADER pDosHeader)
{
    printf("------------------DOS HEADER------------------\n");
    hexdump(pDosHeader, sizeof(IMAGE_DOS_HEADER), (size_t)pDosHeader);
    printf("\n");

    printf("e_magic: %x\n", pDosHeader->e_magic);
    PRINT_PE_FIELD(pDosHeader, e_cblp);
    PRINT_PE_FIELD(pDosHeader, e_cp);
    PRINT_PE_FIELD(pDosHeader, e_crlc);
    PRINT_PE_FIELD(pDosHeader, e_cparhdr);
    PRINT_PE_FIELD(pDosHeader, e_minalloc);
    PRINT_PE_FIELD(pDosHeader, e_maxalloc);
    PRINT_PE_FIELD(pDosHeader, e_ss);
    PRINT_PE_FIELD(pDosHeader, e_sp);
    PRINT_PE_FIELD(pDosHeader, e_csum);
    PRINT_PE_FIELD(pDosHeader, e_ip);
    PRINT_PE_FIELD(pDosHeader, e_cs);
    PRINT_PE_FIELD(pDosHeader, e_lfarlc);
    PRINT_PE_FIELD(pDosHeader, e_ovno);
    //PRINT_PE_FIELD(pDosHeader, e_res);
    PRINT_PE_FIELD(pDosHeader, e_oemid);
    PRINT_PE_FIELD(pDosHeader, e_oeminfo);
    //PRINT_PE_FIELD(pDosHeader, e_res2);
    PRINT_PE_FIELD(pDosHeader, e_lfanew);

    printf("---------------------------------------------\n");
};

/*
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;
*/

void PrintNtHeader(PIMAGE_NT_HEADERS pNtHeader)
{
    printf("------------------NT HEADER------------------\n");
    hexdump(pNtHeader, sizeof(IMAGE_NT_HEADERS), (size_t)pNtHeader);
    printf("\n");

    PRINT_PE_FIELD_TYPE(pNtHeader, Signature, .8X); // its a dword (4 bytes, 1 byte = 2 digits), so using 8 digits. X=> as hex   
    printf("pFileHeader: 0x%p\n", &(pNtHeader->FileHeader));
    printf("pOptHeader: 0x%p\n", &(pNtHeader->OptionalHeader));
};

/*
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

#define IMAGE_SIZEOF_FILE_HEADER             20
*/
void PrintFileHeader(PIMAGE_FILE_HEADER pFileHeader)
{
    printf("------------------FILE HEADER------------------\n");
    hexdump(pFileHeader, sizeof(IMAGE_FILE_HEADER), (size_t)pFileHeader);
    printf("\n");

    PRINT_PE_FIELD_TYPE(pFileHeader, Machine, .4X);
    PRINT_PE_FIELD_TYPE(pFileHeader, NumberOfSections, .4X);
    PRINT_PE_FIELD_TYPE(pFileHeader, TimeDateStamp, .8X);
    PRINT_PE_FIELD_TYPE(pFileHeader, PointerToSymbolTable, .8X);
    PRINT_PE_FIELD_TYPE(pFileHeader, NumberOfSymbols, .8X);
    PRINT_PE_FIELD_TYPE(pFileHeader, SizeOfOptionalHeader, .4X);
    PRINT_PE_FIELD_TYPE(pFileHeader, Characteristics, .4X);

};

/*
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b

*/
void PrintOptionalHeader(PIMAGE_OPTIONAL_HEADER pOptHeader)
{
    printf("------------------OPTIONAL HEADER------------------\n");
    hexdump(pOptHeader, sizeof(IMAGE_OPTIONAL_HEADER), (size_t)pOptHeader);
    printf("\n");

    PRINT_PE_FIELD_TYPE(pOptHeader, Magic, .4X);
    PRINT_PE_FIELD_TYPE(pOptHeader, MajorLinkerVersion, .2X);
    PRINT_PE_FIELD_TYPE(pOptHeader, MinorLinkerVersion, .2X);
    PRINT_PE_FIELD_TYPE(pOptHeader, SizeOfCode, .8X);
    PRINT_PE_FIELD_TYPE(pOptHeader, SizeOfInitializedData, .8X);
    PRINT_PE_FIELD_TYPE(pOptHeader, SizeOfUninitializedData, .8X);
    PRINT_PE_FIELD_TYPE(pOptHeader, AddressOfEntryPoint, .8X);
    PRINT_PE_FIELD_TYPE(pOptHeader, BaseOfCode, .8X);

#ifdef _WIN64
    PRINT_PE_FIELD_TYPE(pOptHeader, ImageBase, .16I64X);         
#else
    PRINT_PE_FIELD_TYPE(pOptHeader, BaseOfData, .8X);
    PRINT_PE_FIELD_TYPE(pOptHeader, ImageBase, .8X);
#endif // _WIN64   
    
    PRINT_PE_FIELD_TYPE(pOptHeader, SectionAlignment, .8X);
    PRINT_PE_FIELD_TYPE(pOptHeader, FileAlignment, .8X);
    PRINT_PE_FIELD_TYPE(pOptHeader, MajorOperatingSystemVersion, .4X);
    PRINT_PE_FIELD_TYPE(pOptHeader, MinorOperatingSystemVersion, .4X);
    PRINT_PE_FIELD_TYPE(pOptHeader, MajorImageVersion, .4X);
    PRINT_PE_FIELD_TYPE(pOptHeader, MinorImageVersion, .4X);
    PRINT_PE_FIELD_TYPE(pOptHeader, MajorSubsystemVersion, .4X);
    PRINT_PE_FIELD_TYPE(pOptHeader, MinorSubsystemVersion, .4X);
    PRINT_PE_FIELD_TYPE(pOptHeader, Win32VersionValue, .8X);
    PRINT_PE_FIELD_TYPE(pOptHeader, SizeOfImage, .8X);
    PRINT_PE_FIELD_TYPE(pOptHeader, SizeOfHeaders, .8X);
    PRINT_PE_FIELD_TYPE(pOptHeader, CheckSum, .8X);
    PRINT_PE_FIELD_TYPE(pOptHeader, Subsystem, .4X);
    PRINT_PE_FIELD_TYPE(pOptHeader, DllCharacteristics, .4X);


#ifdef _WIN64
    PRINT_PE_FIELD_TYPE(pOptHeader, SizeOfStackReserve, .16I64X);
    PRINT_PE_FIELD_TYPE(pOptHeader, SizeOfStackCommit, .16I64X);
    PRINT_PE_FIELD_TYPE(pOptHeader, SizeOfHeapReserve, .16I64X);
    PRINT_PE_FIELD_TYPE(pOptHeader, SizeOfHeapCommit, .16I64X);
#else
    PRINT_PE_FIELD_TYPE(pOptHeader, SizeOfStackReserve, .8X);
    PRINT_PE_FIELD_TYPE(pOptHeader, SizeOfStackCommit, .8X);
    PRINT_PE_FIELD_TYPE(pOptHeader, SizeOfHeapReserve, .8X);
    PRINT_PE_FIELD_TYPE(pOptHeader, SizeOfHeapCommit, .8X);
#endif // _WIN64

    PRINT_PE_FIELD_TYPE(pOptHeader, LoaderFlags, .8X);
    PRINT_PE_FIELD_TYPE(pOptHeader, NumberOfRvaAndSizes, .8X);

    PrintDataDirectories(pOptHeader);

    
};

void PrintDataDirectories(PIMAGE_OPTIONAL_HEADER pOptHeader)
{
    PIMAGE_DATA_DIRECTORY pDataDirectory;
    USHORT i = 0;

    while (i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    {
        printf("Data Directory: [%hd]\n", i);
        pDataDirectory =  &(pOptHeader->DataDirectory[i]);
        hexdump(pDataDirectory, sizeof(IMAGE_DATA_DIRECTORY), (size_t)pDataDirectory);
        PRINT_PE_FIELD_TYPE(pDataDirectory, VirtualAddress, .8X);
        PRINT_PE_FIELD_TYPE(pDataDirectory, Size, .8X);
        
        i++;
    }
}

/*
// IMAGE_FIRST_SECTION doesn't need 32/64 versions since the file header is the same either way.

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER          40

*/
void PrintSectionHeaders(PIMAGE_NT_HEADERS pNtHeader, size_t szNoOfSections, BYTE * pbPEBase)
{
    // Get section headers
    // PIMAGE_SECTION_HEADER pSecHeader
    PIMAGE_SECTION_HEADER pSecHeaders = (PIMAGE_SECTION_HEADER)((BYTE*)pNtHeader + sizeof(IMAGE_NT_HEADERS)); // section headers start from the end of NtHeader
    USHORT i = 0;

    printf("------------------------- SECTION HEADERS ----------------------\n");
    printf("\nNo. of sections: %zd\n\n", szNoOfSections);

    while (i < szNoOfSections)
    {
        PIMAGE_SECTION_HEADER pSecHeader = &pSecHeaders[i];
        printf("---- Section Header: [%hd] ----\n", i);
        hexdump(pSecHeader, sizeof(IMAGE_SECTION_HEADER), (size_t)pSecHeader);

        printf("\n");
        PRINT_PE_FIELD_TYPE(pSecHeader, Name, .8s);
        //PRINT_PE_FIELD_TYPE(pSecHeader, Misc.PhysicalAddress, .8X);
        printf("\n");
        PRINT_PE_FIELD_TYPE(pSecHeader, Misc.VirtualSize, .8X); // in memory
        PRINT_PE_FIELD_TYPE(pSecHeader, VirtualAddress, .8X);   // in memory
        printf("\n");
        PRINT_PE_FIELD_TYPE(pSecHeader, SizeOfRawData, .8X);    // on disk
        PRINT_PE_FIELD_TYPE(pSecHeader, PointerToRawData, .8X); // on disk
        printf("\n");
        PRINT_PE_FIELD_TYPE(pSecHeader, PointerToRelocations, .8X);
        PRINT_PE_FIELD_TYPE(pSecHeader, PointerToLinenumbers, .8X);
        PRINT_PE_FIELD_TYPE(pSecHeader, NumberOfRelocations, .4X);
        PRINT_PE_FIELD_TYPE(pSecHeader, NumberOfLinenumbers, .4X);
        printf("\n");
        PRINT_PE_FIELD_TYPE(pSecHeader, Characteristics, .8X);
        printf("\n");

        PrintSectionData(pSecHeader, pbPEBase);
        i++;
    }
};

void PrintSectionData(PIMAGE_SECTION_HEADER pSecHeader, BYTE * pbPEBase)
{
    //BYTE* inMemoryPointer;


    DWORD onDiskPointer_offset = pSecHeader->PointerToRawData;
    size_t onDiskSize = pSecHeader->SizeOfRawData;
    BYTE* sec_start = pbPEBase + onDiskPointer_offset;
    printf("Address of section: %p, Size of section: %zXh\n", sec_start, onDiskSize);
    //hexdump(sec_start, onDiskSize, (size_t)sec_start);
    //printf("\n");
};

BOOL VerifyDosSignature(PIMAGE_DOS_HEADER pDosHeader)
{
    if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
    {
        return TRUE;
    }

    return FALSE;
};

BOOL VerifyNtSignature(PIMAGE_NT_HEADERS pNtHeader)
{
    if (pNtHeader->Signature == IMAGE_NT_SIGNATURE)
    {
        return TRUE;
    }

    return FALSE;
};

BOOL IsValidPEFile(const char* szFilePath)
{
    // write logic to test if a file is PE or not without loading the full file.

    FILE* pfFile;
    errno_t err = fopen_s(&pfFile, szFilePath, "rb");
    if ( err != 0) {
        perror("Failed to open file");
        return 0;
    }

    // Read the DOS header
    IMAGE_DOS_HEADER idhDosHeader;
    if (fread(&idhDosHeader, sizeof(IMAGE_DOS_HEADER), 1, pfFile) != 1) {
        perror("Failed to read DOS header");
        fclose(pfFile);
        return 0;
    }

    // Check the DOS signature
    if (idhDosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        fclose(pfFile);
        return FALSE;
    }

    // Move to the PE header location
    if (fseek(pfFile, idhDosHeader.e_lfanew, SEEK_SET) != 0) {
        perror("Failed to seek to PE header");
        fclose(pfFile);
        return 0;
    }

    // Read the PE header
    IMAGE_NT_HEADERS inhNtHeaders;
    if (fread(&inhNtHeaders, sizeof(IMAGE_NT_HEADERS), 1, pfFile) != 1) {
        perror("Failed to read PE header");
        fclose(pfFile);
        return 0;
    }

    // Check the PE signature
    if (inhNtHeaders.Signature != IMAGE_NT_SIGNATURE) {
        fclose(pfFile);
        return FALSE;
    }

    fclose(pfFile);
    return TRUE;
}

void PrintExportDirectory(PIMAGE_OPTIONAL_HEADER pOptHeader, PBYTE pbPEBase)
{
    PIMAGE_DATA_DIRECTORY pExportDirectoryHeader = &(pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (pExportDirectoryHeader->VirtualAddress == 0) {
        printf("No export table found.\n");
        return;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDirectory = pExportDirectoryHeader->VirtualAddress;
    
    printf("---------------- Export Directory: ----------------\n");
    //PRINT_PE_FIELD_TYPE(pExportDirectory, , .8X);
    //pExportDirectory->
};

PVOID RVA2RAW()
{


}