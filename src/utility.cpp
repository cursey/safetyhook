#include <Windows.h>

#include <safetyhook/utility.hpp>

namespace safetyhook {
bool is_page_executable(uint8_t* address) {
    MEMORY_BASIC_INFORMATION mbi;

    if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) {
        return false;
    }

    const auto executable_protect = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

    return (mbi.Protect & executable_protect) != 0;
}

bool is_executable(uint8_t* address) {
    LPVOID image_base_ptr;

    if (RtlPcToFileHeader(address, &image_base_ptr) == nullptr) {
        return is_page_executable(address);
    }

    // Just check if the section is executable.
    const auto* image_base = reinterpret_cast<uint8_t*>(image_base_ptr);
    const auto* dos_hdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);

    if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return is_page_executable(address);
    }

    const auto* nt_hdr = reinterpret_cast<const IMAGE_NT_HEADERS*>(image_base + dos_hdr->e_lfanew);

    if (nt_hdr->Signature != IMAGE_NT_SIGNATURE) {
        return is_page_executable(address);
    }

    const auto* section = IMAGE_FIRST_SECTION(nt_hdr);

    for (auto i = 0; i < nt_hdr->FileHeader.NumberOfSections; ++i, ++section) {
        if (address >= image_base + section->VirtualAddress &&
            address < image_base + section->VirtualAddress + section->Misc.VirtualSize) {
            return (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        }
    }

    return is_page_executable(address);
}
} // namespace safetyhook