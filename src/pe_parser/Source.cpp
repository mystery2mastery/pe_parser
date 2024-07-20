#include <stdio.h>

#include <windows.h>
#include <winnt.h>

#include "hexdump/hexdump.h"
#include "pehelper.h"



HANDLE OpenFileAndGetFileSize(const char* szFilename, DWORD* pdwFileSize);




int main(int argc, char* argv[])
{
    /* 
            Usage
    */ 
    if (argc != 2) {
        printf("Usage: %s <filepath>\n", argv[0]);
        return 1;
    }

    const char* szFilePath = argv[1];
    printf("Input file: %s\n", szFilePath);

    // check if it is PE file or not
    if (!IsValidPEFile(szFilePath))
    {
        printf("Not a valid PE file\n");
        return 1;
    }

    /*
            Get handle to the file
    */     
    DWORD dwFileSize;
    HANDLE hFile = OpenFileAndGetFileSize(szFilePath, &dwFileSize);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error opening file %s\n", szFilePath);
        return 1;
    }
    
    printf("File size: %lu bytes\n", dwFileSize);

    // Allocate memory for the file data
    BYTE* pbFileData;
    pbFileData = (BYTE*)malloc(dwFileSize);

    // Read the file data into memory
    DWORD dwBytesRead;
    if (!ReadFile(hFile, pbFileData, dwFileSize, &dwBytesRead, NULL)) {
        printf("Error reading file\n");
        free(pbFileData); // Free allocated memory on error
        CloseHandle(hFile);
        return 1;
    }
    printf("File successfully loaded into heap memory.\n");



    // Parsing PE file
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
    PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_OPTIONAL_HEADER pOptHeader;
    //PIMAGE_SECTION_HEADER pSecHeader;
    size_t szNoOfSections;
    /*
       ----------------------- DOS HEADER ----------------------
       #define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
    */
    pDosHeader = (PIMAGE_DOS_HEADER)pbFileData;
    printf("pDosHeader: %p\n", pDosHeader);
    PrintDosHeader(pDosHeader);

    /* 
        ---------------------- NT HEADER -----------------------
        #define IMAGE_NT_SIGNATURE                  0x00004550  // PE00
        
        #define IMAGE_FILE_MACHINE_I386              0x014c  // Intel 386.
        #define IMAGE_FILE_MACHINE_AMD64             0x8664  // AMD64 (K8)

        #define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b    // 32bit pe file
        #define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b    // 64bit pe file
    */

    pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)pDosHeader + pDosHeader->e_lfanew);

    //printf("Nt Signature: %.8X\n", pNtHeader->Signature); // print as 8 digits (DWORD) in hex
    
    if (pNtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        printf("32bit program\n");
    }
    else
    {
        printf("64bit program\n");
    }

    pFileHeader = &(pNtHeader->FileHeader);
    pOptHeader = &(pNtHeader->OptionalHeader);

    PrintNtHeader(pNtHeader);
    PrintFileHeader(pFileHeader);
    PrintOptionalHeader(pOptHeader);

    szNoOfSections = pFileHeader->NumberOfSections;

    BYTE* pbPEBase = pbFileData;
    PrintSectionHeaders(pNtHeader, szNoOfSections, pbPEBase); // print section headers and also print the section data.




    return 0;
}

// Function to open a file, get its size, and return the file handle
HANDLE OpenFileAndGetFileSize(const char* szFilename, DWORD* pdwFileSize) {
    HANDLE hFile = CreateFileA(szFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error opening file %s\n", szFilename);
        *pdwFileSize = 0; // Set size to 0 on failure
        return INVALID_HANDLE_VALUE;
    }

    *pdwFileSize = GetFileSize(hFile, NULL);
    if (*pdwFileSize == INVALID_FILE_SIZE) {
        printf("Error getting file size\n");
        CloseHandle(hFile);
        return INVALID_HANDLE_VALUE;
    }

    return hFile;
}

