#include "../../include/utils/Filesystem.h"
#include <print>
#include <algorithm>
#ifdef _WIN32
// useless but if I forgot, then here it is
#define NOMINMAX
#include <Windows.h>
#endif

// TODO : Known issue -> multiple open/close when one is only needed (exemple: erase_section), will be fix in the future, but not now 

namespace Filesystem {
    // ULL because if you want Go/GB, then you need ULL to prevent interger overflow 
    // The higher the "quicker" but the ceilling is already reached at around 32/64, why not UINT32_MAX because of the copy in the kernel so that the RAM consumption is lower (but more page fault)
    // -> hence the reason for SEQUENTIAL_SCAN
    // 
    // ~128 Mo/MB
#define READ_CHUNK 128ULL * 1024 * 1024

    // No real reason here just for the sake of consistancy
    // ~4 Go
#define WRITE_CHUNK UINT32_MAX

    bool file_exist(const std::filesystem::path& file_path) {
        return std::filesystem::exists(file_path) && std::filesystem::is_regular_file(file_path);
    }
    bool directory_exist(const std::filesystem::path& dir_path) {
        return std::filesystem::exists(dir_path) && std::filesystem::is_directory(dir_path);
    }
    bool has_file(const std::filesystem::path& dir_path) {
        if (!directory_exist(dir_path))
            return false;

        for (const auto& entry : std::filesystem::directory_iterator(dir_path)) {
            if (entry.is_regular_file())
                return true;
        }
        return false;
    }
    bool has_directory(const std::filesystem::path& dir_path) {
        if (!directory_exist(dir_path))
            return false;

        for (const auto& entry : std::filesystem::directory_iterator(dir_path)) {
            if (entry.is_directory())
                return true;
        }
        return false;
    }
    MetaData get_metadata(const std::filesystem::path& path) {
        if (!std::filesystem::exists(path)) {
            std::println("[-] get_metadata, path doesn't exists ({})", path.string());
        }

        MetaData meta;
        std::filesystem::file_time_type last_write = std::filesystem::last_write_time(path);
        meta.last_time_modified = last_write.time_since_epoch().count();

        return meta;
    }

    bool read_file(const std::filesystem::path& file_path, std::vector<uint8_t>& result, size_t offset, size_t offset_end) {
        std::error_code error_code; // fuck exception
        size_t file_size = std::filesystem::file_size(file_path, error_code);
        if (error_code) {
            std::println("[-] read_file, ({}) File doesn't exist", file_path.string());
            return false;
        }

        offset_end = offset_end == 0 ? file_size : offset_end;

        if (offset >= file_size) {
            std::println("[-] read_file, offset ({}) >= file_size ({})", offset, file_size);
            return false;
        }
        if (offset_end > file_size) {
            std::println("[-] read_file, offset_end ({}) > file_size ({})", offset_end, file_size);
            return false;
        }
        if (offset > offset_end) {
            std::println("[-] read_file, offset ({}) > offset_end ({})", offset, offset_end);
            return false;
        }

        result.clear();
        result.resize(offset_end - offset);
        return read_file(file_path, std::span<uint8_t>(result), offset, offset_end);
    }
    bool read_file(const std::filesystem::path& file_path, std::span<uint8_t> out, size_t offset, size_t offset_end) {
        std::error_code error_code; // fuck exception
        size_t file_size = std::filesystem::file_size(file_path, error_code);
        if (error_code) {
            std::println("[-] read_file, ({}) File doesn't exist", file_path.string());
            return false;
        }

        offset_end = offset_end == 0 ? file_size : offset_end;

        if (offset >= file_size) {
            std::println("[-] read_file, offset ({}) >= file_size ({})", offset, file_size);
            return false;
        }
        if (offset_end > file_size) {
            std::println("[-] read_file, offset_end ({}) > file_size ({})", offset_end, file_size);
            return false;
        }
        if (offset > offset_end) {
            std::println("[-] read_file, offset ({}) > offset_end ({})", offset, offset_end);
            return false;
        }

        size_t total_bytes_to_read = offset_end - offset;

        if (total_bytes_to_read > out.size()) {
            std::println("[-] read_file, bytes_to_read ({}) > out.size() ({})", total_bytes_to_read, out.size());
            return false;
        }

#ifdef _WIN32
        HANDLE hFile = CreateFileW(
            file_path.c_str(),
            GENERIC_READ,
            FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN,
            //FILE_FLAG_NO_BUFFERING,
            //FILE_FLAG_RANDOM_ACCESS,
            nullptr
        );
        if (hFile == INVALID_HANDLE_VALUE) {
            std::println("[!] read_file, CreateFileW failed");
            return false;
        }

        size_t written = 0;
        size_t remaining = total_bytes_to_read;
        size_t current_offset = offset;
        bool success = true;

        constexpr size_t CHUNK_SIZE = READ_CHUNK;
        while (remaining > 0 && success) {

            DWORD chunk = static_cast<DWORD>(std::min(remaining, CHUNK_SIZE));

            OVERLAPPED ov = {};
            ov.Offset = (DWORD)(current_offset & 0xFFFFFFFF);
            ov.OffsetHigh = (DWORD)(current_offset >> 32);

            DWORD bytes_read = 0;
            success = ReadFile(hFile, out.data() + written, chunk, &bytes_read, &ov);

            if (bytes_read != chunk) {
                std::println("[-] read_file, Read : {} | Expected : {}", bytes_read, chunk);
                success = false;
                break;
            }

            written += bytes_read;
            current_offset += bytes_read;
            remaining -= bytes_read;
        }

        CloseHandle(hFile);
        return success;

#else
        int fd = open(file_path.c_str(), O_RDONLY);
        if (fd == -1) {
            std::println("[!] read_file, open failed");
            return false;
        }

        ssize_t bytes_read = ::pread(fd, out.data(), total_bytes_to_read, (off_t)offset);
        close(fd);

        if (bytes_read != (ssize_t)total_bytes_to_read) {
            std::println("[-] read_file, Read : {} | Expected : {}", bytes_read, total_bytes_to_read);
            return false;
        }

        return true;
#endif
    }    

    bool write_file(const std::filesystem::path& file_path, std::span<const uint8_t> data_to_write, size_t offset) {
        std::error_code error_code; // fuck exception
        size_t file_size = std::filesystem::file_size(file_path, error_code);
        if (error_code) {
            std::println("[-] write_file, ({}) File doesn't exist", file_path.string());
            return false;
        }
        size_t bytes_to_write = data_to_write.size();
        
        if (file_size < offset) {
            std::println("[-] write_file, offset ({}) is bigger than the file_size ({})", offset, file_size);
            return false;
        }

#ifdef _WIN32
        HANDLE hFile = CreateFileW(
            file_path.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (hFile == INVALID_HANDLE_VALUE) {
            std::println("[!] write_file, CreateFileW failed");
            return false;
        }

        size_t written = 0;
        size_t remaining = bytes_to_write;
        size_t current_offset = offset;
        bool success = true;

        constexpr size_t CHUNK_SIZE = WRITE_CHUNK;
        while (remaining > 0 && success) {

            DWORD chunk = static_cast<DWORD>(std::min(remaining, CHUNK_SIZE));

            OVERLAPPED ov = {};
            ov.Offset = (DWORD)(current_offset & 0xFFFFFFFF);
            ov.OffsetHigh = (DWORD)(current_offset >> 32);

            DWORD bytes_written = 0;
            success = WriteFile(hFile, data_to_write.data() + written, chunk, &bytes_written, &ov);

            if (bytes_written != chunk) {
                std::println("[-] write_file, Read : {} | Expected : {}", bytes_written, chunk);
                success = false;
                break;
            }

            written += bytes_written;
            current_offset += bytes_written;
            remaining -= bytes_written;
        }

        CloseHandle(hFile);
        return success;
#else
        int fd = open(file_path.c_str(), O_WRONLY);
        if (fd == -1) { 
            std::println("[!] write_file, open failed");
            return false;
        }

        ssize_t written = pwrite(fd, data_to_write.data(), bytes_to_write, (off_t)offset);
        close(fd);
        return (written == (ssize_t)bytes_to_write);
#endif
    }
    bool resize_file(const std::filesystem::path& file_path, size_t size) {
#ifdef _WIN32
        HANDLE hFile = CreateFileW(
            file_path.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (hFile == INVALID_HANDLE_VALUE) {
            std::println("[!] resize_file, CreateFileW failed");
            return false;
        }
        LARGE_INTEGER pos;
        pos.QuadPart = size;
        if (!SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN)) {
            std::println("[!] resize_file, SetFilePointerEx failed");
            CloseHandle(hFile);
            return false;
        }
        if(!SetEndOfFile(hFile)) {
            std::println("[!] resize_file, SetEndOfFile failed");
            CloseHandle(hFile);
            return false;
        }
        CloseHandle(hFile);
        return true;
#else
        int fd = open(file_path.c_str(), O_WRONLY);
        if (fd == -1) {
            std::println("[!] resize_file, open failed");
            return false;
        }
        if (ftruncate(fd, (off_t)size) == -1) {
            close(fd);
            return false;
        }
        close(fd);
        return true;
#endif
    }

    bool erase_section(const std::filesystem::path& file_path, size_t offset, size_t offset_end) {
        std::error_code error_code; // fuck exception
        size_t file_size = std::filesystem::file_size(file_path, error_code);
        if (error_code) {
            std::println("[-] erase_section, ({}) File doesn't exist", file_path.string());
            return false;
        }

        offset_end = offset_end == 0 ? file_size : offset_end;

        if (offset >= file_size) {
            std::println("[-] erase_section, offset ({}) >= file_size ({})", offset, file_size);
            return false;
        }
        if (offset_end > file_size) {
            std::println("[-] erase_section, offset_end ({}) > file_size ({})", offset_end, file_size);
            return false;
        }
        if (offset > offset_end) {
            std::println("[-] erase_section, offset ({}) > offset_end ({})", offset, offset_end);
            return false;
        }

        // moving data
        if (offset_end != file_size) {
            std::vector<uint8_t> temp_data(READ_CHUNK * 8, 0); // On heap
            size_t read_offset = offset_end;
            size_t write_offset = offset;

            size_t remaining = file_size - offset_end;
            while (remaining > 0) {
                size_t chunk = std::min(remaining, READ_CHUNK * 8);

                if (!read_file(file_path, std::span<uint8_t>(temp_data.data(), chunk), read_offset, read_offset + chunk)) {
                    std::println("[-] erase_section, read_file failed");
                    return false;
                }
                if (!write_file(file_path, std::span<uint8_t>(temp_data.data(), chunk), write_offset)) {
                    std::println("[-] erase_section, write_file failed");
                    return false;
                }

                read_offset += chunk;
                write_offset += chunk;
                remaining -= chunk;
            }
        }


        // truncate
        size_t new_size = file_size - offset_end + offset;

        return Filesystem::resize_file(file_path, new_size); // ? Why does it need the Filesystem:: 
    }


    bool write_append(const std::filesystem::path& file_path, std::span<const uint8_t> data_to_write) {
        std::error_code error_code; // fuck exception
        size_t file_size = std::filesystem::file_size(file_path, error_code);
        if (error_code) {
            std::println("[-] append_file, ({}) File doesn't exist", file_path.string());
            return false;
        }
        
        return write_file(file_path, data_to_write, file_size);
    }

    bool write_insert(const std::filesystem::path& file_path, std::span<const uint8_t> data_to_write, size_t offset) {
        std::error_code error_code; // fuck exception
        size_t file_size = std::filesystem::file_size(file_path, error_code);
        if (error_code) {
            std::println("[-] write_insert, ({}) File doesn't exist", file_path.string());
            return false;
        }

        if (offset > file_size) {
            std::println("[-] write_insert, offset ({}) > file_size ({})", offset, file_size);
            return false;
        }

        size_t insert_size = data_to_write.size();

        std::vector<uint8_t> temp_data(READ_CHUNK * 8);
        size_t remaining = file_size - offset;
        size_t move_offset = file_size;

        while (remaining > 0) {
            size_t chunk = std::min(remaining, READ_CHUNK * 8);
            move_offset -= chunk;
            remaining -= chunk;

            if (!read_file(file_path, std::span<uint8_t>(temp_data.data(), chunk), move_offset, move_offset + chunk)) {
                std::println("[-] write_insert, read_file failed");
                return false;
            }
            if (!write_file(file_path, std::span<const uint8_t>(temp_data.data(), chunk), move_offset + insert_size)) {
                std::println("[-] write_insert, write_file failed");
                return false;
            }
        }

        if (!write_file(file_path, data_to_write, offset)) {
            std::println("[-] write_insert, write_file final failed");
            return false;
        }

        return true;
    }

    bool create_file(const std::filesystem::path& file_path) {
        if (!directory_exist(file_path.parent_path())) {
            std::println("[-] create_file, ({}) Directory doesn't exist", file_path.parent_path().string());
            return false;
        }
        if (std::filesystem::exists(file_path)) {
            std::println("[-] create_file, \"{}\" already exist", file_path.string());
            return false;
        }
#ifdef _WIN32
        HANDLE hFile = CreateFileW(
            file_path.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (hFile == INVALID_HANDLE_VALUE) {
            std::println("[!] read_file, CreateFileW failed");
            return false;
        }
        CloseHandle(hFile);
        return true;
#else
        int fd = open(file_path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd == -1) {
            return false;
        }
        close(fd);
        return true;
#endif
    }
    bool rename_file(const std::filesystem::path& file_path, std::string_view file_name) {
        if (!file_exist(file_path)) {
            std::println("[-] rename_file, \"{}\" doesn't exist or isn't a file", file_path.string());
            return false;
        }
        std::filesystem::path dst = file_path.parent_path() / file_name;
        if (std::filesystem::exists(dst)) {
            std::println("[-] rename_file, \"{}\" already exist", dst.string());
            return false;
        }
        std::error_code error_code;
        std::filesystem::rename(file_path, dst, error_code);
        if (error_code) {
            std::println("[-] rename_file, rename failed");
            return false;
        }

        return true;
    }
    bool delete_file(const std::filesystem::path& file_path) {
        if (!std::filesystem::is_regular_file(file_path)) {
            return false;
        }

        std::error_code error_code; // fuck exception
        std::filesystem::remove(file_path, error_code);
        if (error_code) {
            std::println("[-] delete_file, remove failed");
            return false;
        }
        return true;
    }
    bool copy_file(const std::filesystem::path& file_path, const std::filesystem::path& dir_path) {
        std::filesystem::path dst = dir_path / file_path.filename();
        if (!std::filesystem::is_regular_file(file_path)) {
            std::println("[-] copy_file, \"{}\" doesn't exist or isn't a file", file_path.string());
            return false;
        }
        if (!directory_exist(dir_path)) {
            std::println("[-] copy_file, ({}) Directory doesn't exist", dir_path.string());
            return false;
        }

        std::error_code error_code; // fuck exception
        std::filesystem::copy_file(file_path, dst, std::filesystem::copy_options::none, error_code);    // failed if already existing
        if (error_code) {
            std::println("[-] copy_file, copy_file failed");
            return false;
        }
        return true;
    }
    bool copy_file_overwrite(const std::filesystem::path& file_path, const std::filesystem::path& dir_path) {
        std::filesystem::path dst = dir_path / file_path.filename();
        if (!std::filesystem::is_regular_file(file_path)) {
            std::println("[-] copy_file_overwrite, \"{}\" doesn't exist or isn't a file", file_path.string());
            return false;
        }
        if (!directory_exist(dir_path)) {
            std::println("[-] copy_file_overwrite, ({}) Directory doesn't exist", dir_path.string());
            return false;
        }
        
        std::error_code error_code; // fuck exception
        std::filesystem::copy_file(file_path, dst, std::filesystem::copy_options::overwrite_existing, error_code);
        if (error_code) {
            std::println("[-] copy_file_overwrite, copy_file failed");
            return false;
        }
        return true;
    }
    bool move_file(const std::filesystem::path& file_path, const std::filesystem::path& dir_path) {
        std::filesystem::path dst = dir_path / file_path.filename();

        if (!file_exist(file_path)) {
            std::println("[-] move_file, \"{}\" doesn't exist", file_path.string());
            return false;
        }
        if (file_exist(dst)) {
            std::println("[-] move_file, \"{}\" already exist", dst.string());
            return false;
        }
        if (!directory_exist(dir_path)) {
            std::println("[-] move_file, ({}) Directory doesn't exist", dir_path.string());
            return false;
        }

        std::error_code error_code; // fuck exception
        std::filesystem::rename(file_path, dst, error_code);
        if (error_code) {
            std::println("[-] move_file, rename failed");
            return false;
        }
        return true;
    }
    bool create_directory(const std::filesystem::path& dir_path) {
        if (!directory_exist(dir_path.parent_path())) {
            std::println("[-] create_directory, ({}) Directory doesn't exist", dir_path.parent_path().string());
            return false;
        }
        if (directory_exist(dir_path)) {
            std::println("[-] create_directory, ({}) Directory already exist", dir_path.string());
            return false;
        }

        std::error_code error_code; // fuck exception
        std::filesystem::create_directory(dir_path, error_code);
        if (error_code) {
            std::println("[-] create_directory, create_directory failed");
            return false;
        }
        return true;
    }
    bool delete_directory(const std::filesystem::path& dir_path) {
        if (has_file(dir_path)) {
            std::println("[-] delete_directory, ({}) Directory have a file in it", dir_path.parent_path().string());
            return false;
        }
        if (has_directory(dir_path)) {
            std::println("[-] delete_directory, ({}) Directory have a directory in it", dir_path.parent_path().string());
            return false;
        }
        else {
            std::error_code error_code; // fuck exception
            std::filesystem::remove(dir_path, error_code);
            if (error_code) {
                std::println("[-] delete_directory, remove failed");
                return false;
            }
            return true;
        }
    }
};
