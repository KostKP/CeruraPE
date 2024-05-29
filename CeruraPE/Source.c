#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#define PREFFIX "CeruraPE >"
#define VERSION "R1.0"
#define INVALID_ADDR -1

DWORD RVAddressToOffset(DWORD rva, PIMAGE_NT_HEADERS ntHeaders) {
    if (rva == 0)
        return 0;

    PIMAGE_SECTION_HEADER secHeader = IMAGE_FIRST_SECTION(ntHeaders); //Pointer to first section header

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (rva >= secHeader->VirtualAddress && rva < secHeader->VirtualAddress + secHeader->Misc.VirtualSize)
            break;
        secHeader++;
    }

    return (rva - secHeader->VirtualAddress + secHeader->PointerToRawData);
}

DWORD computeChecksum(BYTE* buffer, SIZE_T bufferSize, DWORD checksumOffset)
{
    if (!buffer || !bufferSize) return 0;

    WORD* wordsBuff = (WORD*)buffer;
    const SIZE_T wordsCount = bufferSize / sizeof(WORD);
    const SIZE_T remainingBytes = bufferSize % sizeof(WORD);

    DWORD checksumBgn = 0;
    DWORD checksumEnd = 0;
    if (checksumOffset != INVALID_ADDR) {
        checksumBgn = checksumOffset;
        checksumEnd = checksumBgn + sizeof(DWORD);
    }

    const DWORDLONG maxVal = ((DWORDLONG)1) << 32;
    DWORDLONG checksum = 0;

    for (int i = 0; i < wordsCount; i++) {
        WORD chunk = wordsBuff[i];

        SIZE_T bI = i * sizeof(WORD);
        if (checksumBgn != checksumEnd && bI >= checksumBgn && bI < checksumEnd) {
            SIZE_T mask = (checksumEnd - bI) % sizeof(WORD);
            SIZE_T shift = (sizeof(WORD) - mask) * 8;
            chunk = (chunk >> shift) << shift;
        }

        checksum = (checksum & 0xffffffff) + chunk + (checksum >> 32);
        if (checksum > maxVal) {
            checksum = (checksum & 0xffffffff) + (checksum >> 32);
        }
    }

    // Handle the remaining bytes
    if (remainingBytes > 0) {
        WORD chunk = 0;
        memcpy(&chunk, buffer + wordsCount * sizeof(WORD), remainingBytes);

        size_t bI = wordsCount * sizeof(WORD);
        if (checksumBgn != checksumEnd && bI >= checksumBgn && bI < checksumEnd) {
            size_t mask = (checksumEnd - bI) % sizeof(WORD);
            size_t shift = (sizeof(WORD) - mask) * 8;
            chunk = (chunk >> shift) << shift;
        }

        checksum = (checksum & 0xffffffff) + chunk + (checksum >> 32);
        if (checksum > maxVal) {
            checksum = (checksum & 0xffffffff) + (checksum >> 32);
        }
    }
    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum)+(checksum >> 16);
    checksum = checksum & 0xffff;
    checksum += bufferSize;
    return checksum;
}

int PatchStandartPE(const char* dllOriginalPath, char* dllName, const char* dllFunc, const char* dllPatchedPath) {
    HMODULE hModule = NULL;
    SIZE_T fileSize = 0;

    dllName[strlen(dllName) - 4] = '\0';

    {
        FILE* file = fopen(dllOriginalPath, "rb");

        if (file == NULL) {
            perror("Failed to load file into memory");
            return 2;
        }

        // Get the size of the DLL
        fseek(file, 0, SEEK_END);
        fileSize = ftell(file);
        fseek(file, 0, SEEK_SET);

        // Allocate memory for the DLL content
        hModule = (HMODULE)malloc(fileSize);

        if ((DWORD_PTR)hModule == NULL) {
            perror("Failed to allocate memory");
            fclose(file);
            free(hModule);
            return 1;
        }

        // Read the DLL content into memory
        fread((DWORD_PTR)hModule, 1, fileSize, file);
        fclose(file);
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    // Validate the DOS header
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Validating DOS header failed\n");
        free(hModule);
        return 1;
    }

    WORD machine = 0;
    {
        // Validate the NT header
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dosHeader + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            printf("Validating NT header failed\n");
            free(hModule);
            return 1;
        }
        machine = ntHeaders->FileHeader.Machine;
    }

    if (machine == IMAGE_FILE_MACHINE_AMD64) {
        printf("%s Processing AMD64 library...\n", PREFFIX);
    }
    else if (machine == IMAGE_FILE_MACHINE_I386) {
        printf("%s Processing I386 library...\n", PREFFIX);
    }
    else {
        printf("%s Unsupported library...\n", PREFFIX);
        free(hModule);
        return 1;
    }

    DWORD_PTR ntHeaders = (DWORD_PTR)dosHeader + dosHeader->e_lfanew;
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL; //Pointer to import descriptor
    PIMAGE_SECTION_HEADER secHeader = IMAGE_FIRST_SECTION((PIMAGE_NT_HEADERS)ntHeaders); //Pointer to first section header

    printf("Sections count: %d\n", ((PIMAGE_NT_HEADERS)ntHeaders)->FileHeader.NumberOfSections);
    printf("File sections headers table:\n");

    if (((PIMAGE_NT_HEADERS)ntHeaders)->FileHeader.NumberOfSections == 0) {
        printf("No sections found\n");
        free(hModule);
        return 1;
    }

    for (int i = 0; i < ((PIMAGE_NT_HEADERS)ntHeaders)->FileHeader.NumberOfSections; i++) {
        DWORD secaddress = RVAddressToOffset(secHeader, ntHeaders) - (DWORD_PTR)hModule;
        printf("  [%08x] %s at %08x -> %08x with size of %d -> %d bytes\n", secaddress, secHeader->Name, secHeader->PointerToRawData, secHeader->VirtualAddress, secHeader->SizeOfRawData, secHeader->Misc.VirtualSize);
        secHeader++;
    }
    secHeader--;

    SIZE_T importTableEntrys = 0;
    SIZE_T fileAlignment = 0;

    if (machine == IMAGE_FILE_MACHINE_AMD64) {
        if (((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
            printf("Library does not contain an import table\n");
            free(hModule);
            return 1;
        }
        importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hModule + \
            RVAddressToOffset(((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, ntHeaders));
        fileAlignment = ((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.FileAlignment;
        ((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
        ((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
    }
    else if (machine == IMAGE_FILE_MACHINE_I386) {
        if (((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
            printf("Library does not contain an import table\n");
            free(hModule);
            return 1;
        }
        importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hModule + \
            RVAddressToOffset(((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, ntHeaders));
        fileAlignment = ((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.FileAlignment;
        ((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
        ((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
    }

    printf("File offsets for import table:\n");
    while (importDescriptor->Name != NULL) // Walk until you reached an empty IMAGE_IMPORT_DESCRIPTOR
    {
        LPSTR libname = (PCHAR)((DWORD_PTR)hModule + RVAddressToOffset(importDescriptor->Name, ntHeaders));
        DWORD libaddress = RVAddressToOffset(importDescriptor, ntHeaders) - (DWORD_PTR)hModule;
        printf("  [%08x] %s\n", libaddress, libname);
        importTableEntrys++;
        importDescriptor++; //advance to next IMAGE_IMPORT_DESCRIPTOR
    }
    printf("Found %llu import entries, %llu bytes each, for a total size of %llu bytes\n", importTableEntrys, sizeof(IMAGE_IMPORT_DESCRIPTOR), importTableEntrys * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    printf("File alignment: %llu bytes\n", fileAlignment);
    printf("Rebuilding last section parameters (%s)\n", secHeader->Name);

    DWORD sizeOfImageOffset = (DWORD_PTR)&((PIMAGE_NT_HEADERS)ntHeaders)->OptionalHeader.SizeOfImage - (DWORD_PTR)hModule;
    DWORD checksumOffset = (DWORD_PTR)&((PIMAGE_NT_HEADERS)ntHeaders)->OptionalHeader.CheckSum - (DWORD_PTR)hModule;
    ((PIMAGE_NT_HEADERS)ntHeaders)->OptionalHeader.CheckSum = 0;

    {
        // Fix section flags
        PBYTE rweByte = (DWORD_PTR)&secHeader->Characteristics + sizeof(DWORD) - 1;

        // Skip IMAGE_SCN_MEM_WRITE
        if (*rweByte >= 0x80) {
            *rweByte -= 0x80;
        }

        // Skip IMAGE_SCN_MEM_READ
        if (*rweByte >= 0x40) {
            *rweByte -= 0x40;
        }

        *rweByte &= 0x0F;
        *rweByte |= (*rweByte >= 0x20) ? 0xE0 : 0xC0;
    }

    SIZE_T virtualExpandSize = (importTableEntrys + 2) * sizeof(IMAGE_IMPORT_DESCRIPTOR) + strlen(dllName) + strlen(dllFunc) + 2 + sizeof(WORD);

    if (machine == IMAGE_FILE_MACHINE_AMD64) {
        virtualExpandSize += sizeof(DWORDLONG) * 4;
    }
    else if (machine == IMAGE_FILE_MACHINE_I386) {
        virtualExpandSize += sizeof(DWORD) * 4;
    }

    while (secHeader->SizeOfRawData < secHeader->Misc.VirtualSize + virtualExpandSize) {
        secHeader->SizeOfRawData += fileAlignment;
    }

    IMAGE_IMPORT_DESCRIPTOR payloadImportDescriptor;
    payloadImportDescriptor.Characteristics = 0;
    payloadImportDescriptor.TimeDateStamp = 0; // Time and date stamp for this import data
    payloadImportDescriptor.ForwarderChain = 0; // Index to the first forwarder reference

    DWORD_PTR newSectionBytesData = (DWORD_PTR)calloc(secHeader->SizeOfRawData, sizeof(BYTE));
    memcpy(newSectionBytesData, (DWORD_PTR)hModule + secHeader->PointerToRawData, secHeader->Misc.VirtualSize);
    memcpy(newSectionBytesData + secHeader->Misc.VirtualSize, dllName, strlen(dllName));
    payloadImportDescriptor.Name = secHeader->VirtualAddress + secHeader->Misc.VirtualSize; // RVA to the ASCII string naming the imported DLL
    secHeader->Misc.VirtualSize += strlen(dllName) + 1; // dll name
    memcpy(newSectionBytesData + secHeader->Misc.VirtualSize + sizeof(WORD), dllFunc, strlen(dllFunc));
    DWORDLONG funcHintAddress = secHeader->VirtualAddress + secHeader->Misc.VirtualSize;
    secHeader->Misc.VirtualSize += strlen(dllFunc) + 1 + sizeof(WORD); // Function name + hint

    if (machine == IMAGE_FILE_MACHINE_AMD64) {
        memcpy(newSectionBytesData + secHeader->Misc.VirtualSize, &funcHintAddress, sizeof(DWORDLONG));
        payloadImportDescriptor.OriginalFirstThunk = secHeader->VirtualAddress + secHeader->Misc.VirtualSize; // The import lookup table RVA
        secHeader->Misc.VirtualSize += sizeof(DWORDLONG) * 2;
        memcpy(newSectionBytesData + secHeader->Misc.VirtualSize, &funcHintAddress, sizeof(DWORDLONG));
        payloadImportDescriptor.FirstThunk = secHeader->VirtualAddress + secHeader->Misc.VirtualSize; // RVA to the import address table
        secHeader->Misc.VirtualSize += sizeof(DWORDLONG) * 2;

        importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hModule + \
            RVAddressToOffset(((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, ntHeaders));

        ((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = secHeader->VirtualAddress + secHeader->Misc.VirtualSize;
        ((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (importTableEntrys + 2) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    else if (machine == IMAGE_FILE_MACHINE_I386) {
        memcpy(newSectionBytesData + secHeader->Misc.VirtualSize, &funcHintAddress, sizeof(DWORD));
        payloadImportDescriptor.OriginalFirstThunk = secHeader->VirtualAddress + secHeader->Misc.VirtualSize; // The import lookup table RVA
        secHeader->Misc.VirtualSize += sizeof(DWORD) * 2;
        memcpy(newSectionBytesData + secHeader->Misc.VirtualSize, &funcHintAddress, sizeof(DWORD));
        payloadImportDescriptor.FirstThunk = secHeader->VirtualAddress + secHeader->Misc.VirtualSize; // RVA to the import address table
        secHeader->Misc.VirtualSize += sizeof(DWORD) * 2;

        importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hModule + \
            RVAddressToOffset(((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, ntHeaders));

        ((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = secHeader->VirtualAddress + secHeader->Misc.VirtualSize;
        ((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (importTableEntrys + 2) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    memcpy(newSectionBytesData + secHeader->Misc.VirtualSize, (DWORD_PTR)importDescriptor, importTableEntrys * sizeof(IMAGE_IMPORT_DESCRIPTOR));

    secHeader->Misc.VirtualSize += importTableEntrys * sizeof(IMAGE_IMPORT_DESCRIPTOR);

    memcpy(newSectionBytesData + secHeader->Misc.VirtualSize, &payloadImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    secHeader->Misc.VirtualSize += sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;

    DWORD sizeOfImage = secHeader->VirtualAddress + secHeader->SizeOfRawData;

    FILE* file = fopen(dllPatchedPath, "wb+");

    if (file == NULL) {
        perror("Cannot write file to disk");
        free(newSectionBytesData);
        free(hModule);
        return 2;
    }

    fwrite(hModule, sizeof(BYTE), secHeader->PointerToRawData, file);
    fwrite(newSectionBytesData, sizeof(BYTE), secHeader->SizeOfRawData, file);

    free(newSectionBytesData);
    free(hModule);

    // Get the size of the DLL
    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for the DLL content
    hModule = (HMODULE)malloc(fileSize);

    if ((DWORD_PTR)hModule == NULL) {
        perror("Failed to allocate memory");
        fclose(file);
        return 1;
    }

    fseek(file, sizeOfImageOffset, SEEK_SET);
    if (fwrite(&sizeOfImage, sizeof(DWORD), 1, file) != 1) {
        perror("Failed to fix size of image");
        fclose(file);
        return 1;
    }

    fseek(file, 0, SEEK_SET);

    // Read the DLL content into memory
    fread((DWORD_PTR)hModule, 1, fileSize, file);

    DWORD checksum = computeChecksum((DWORD_PTR)hModule, fileSize, checksumOffset);
    fseek(file, checksumOffset, SEEK_SET);
    if (fwrite(&checksum, sizeof(DWORD), 1, file) != 1) {
        perror("Failed to fix dll checksum");
        fclose(file);
        return 1;
    }

    fclose(file);

    return 0;
}

#define IS_ACCEPTED_CHAR(c) ((((c)>=('a')&&(c)<=('z'))||((c)>=('A')&&(c)<=('Z'))||((c)>=('0')&&(c)<=('9')))?(1):(0))

int isDllNameCorrect(char str[]) {
    unsigned short i = 0;
    while (1) {
        if (str[i] == '.')
            return strcmp(&str[i], ".dll") == 0 ? (i > 0) : 0;
        if (i == 60)
            return 0;
        if (!IS_ACCEPTED_CHAR(str[i]))
            return 0;
        i++;
    }
}

int isFunctionNameCorrect(char str[]) {
    unsigned short i = 0;
    while (1) {
        if (str[i] == '\0')
            return i > 0;
        if (i == 63)
            return 0;
        if (!IS_ACCEPTED_CHAR(str[i]))
            return 0;
        i++;
    }
}

void displayHelp(HANDLE hConsole) {
    if (hConsole != INVALID_HANDLE_VALUE) {
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN);
    }

    printf("Cerura %s\n", VERSION);
    printf("Usage: cerura (PathToDll) (ImportDllName) (ImportFunctionName) [OutputPath]\n");
    printf("Example: cerura \"C:\\Windows\\version.dll\" \"payload.dll\" \"payload\" \"C:\\Windows\\evil-version.dll\"");
}

void displayWrongUsage(HANDLE hConsole) {
    if (hConsole != INVALID_HANDLE_VALUE) {
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
    }

    printf("%s Wrong usage. Use --help, -h, or -? for help", PREFFIX);
}

int main(int argc, char* argv[]) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    short currentColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE; // Default color

    if (hConsole != INVALID_HANDLE_VALUE) { // Getting current terminal color
        CONSOLE_SCREEN_BUFFER_INFO info;

        if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info)) {
            currentColor = info.wAttributes;
        }
    }

    if (argc == 1) {
        if (hConsole != INVALID_HANDLE_VALUE) {
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
        }

        printf("%s No arguments provided. Use --help, -h, or -? for help", PREFFIX);
    }
    else if (argc == 2) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "-?") == 0) {
            displayHelp(hConsole);
        }
        else {
            displayWrongUsage(hConsole);
        }
    }
    else if (argc == 4 || argc == 5) {
        if (!isDllNameCorrect(argv[2]) || !isFunctionNameCorrect(argv[3])) {
            displayWrongUsage(hConsole);
        }
        else {
            char* out;
            if (argc == 4) {
                out = calloc(strlen(argv[1]) + 2, sizeof(char));
                strcpy(out, argv[1]);
                out[strlen(argv[1])] = 'c';
            }
            else {
                out = argv[4];
            }
            if (PatchStandartPE(argv[1], argv[2], argv[3], out) == 0) {
                if (hConsole != INVALID_HANDLE_VALUE) {
                    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
                }
                printf("Corrected library is saved to disk!");
            }
            else {
                if (hConsole != INVALID_HANDLE_VALUE) {
                    SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
                }
                printf("Error processing library!");
            }
        }
    }
    
    if (hConsole != INVALID_HANDLE_VALUE) {
        SetConsoleTextAttribute(hConsole, currentColor);
    }

    return 0;
}