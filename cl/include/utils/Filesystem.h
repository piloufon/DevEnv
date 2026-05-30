#pragma once
#include <filesystem>
#include <span>

namespace Filesystem {
	struct MetaData {
		uint64_t last_time_modified = 0;
	};
	bool file_exist(const std::filesystem::path& file_path);
	bool directory_exist(const std::filesystem::path& dir_path);
	bool has_file(const std::filesystem::path& dir_path);
	bool has_directory(const std::filesystem::path& dir_path);
	MetaData get_metadata(const std::filesystem::path& path);

	bool read_file(const std::filesystem::path& file_path, std::vector<uint8_t>& result, size_t offset = 0, size_t offset_end = 0);
	bool read_file(const std::filesystem::path&, std::span<uint8_t> out, size_t offset = 0, size_t offset_end = 0); // Pre-allocated buffer

	bool write_file(const std::filesystem::path& file_path, std::span<const uint8_t> data_to_write, size_t offset);
	bool resize_file(const std::filesystem::path& file_path, size_t size);
	
	bool write_append(const std::filesystem::path& file_path, std::span<const uint8_t> data_to_write);
	bool write_insert(const std::filesystem::path& file_path, std::span<const uint8_t> data_to_write, size_t offset);
	bool erase_section(const std::filesystem::path& file_path, size_t offset, size_t offset_end = 0);

	bool create_file(const std::filesystem::path& file_path);
	bool delete_file(const std::filesystem::path& file_path);
	bool rename_file(const std::filesystem::path& file_path, std::string_view file_name);
	bool copy_file(const std::filesystem::path& file_path, const std::filesystem::path& dir_path);
	bool copy_file_overwrite(const std::filesystem::path& file_path, const std::filesystem::path& dir_path);
	bool move_file(const std::filesystem::path& file_path, const std::filesystem::path& dir_path);
	bool create_directory(const std::filesystem::path& dir_path);
	bool delete_directory(const std::filesystem::path& dir_path);

	bool list_files(const std::filesystem::path& dir_path, std::vector<std::filesystem::path>& files_path);
	bool list_files_recursive(const std::filesystem::path& dir_path, std::vector<std::filesystem::path>& files_path, std::string_view ext = "");
	bool list_directories(const std::filesystem::path& dir_path, std::vector<std::filesystem::path>& directories_path);

	class Watcher {
	public:
		enum class Event : uint8_t {
			Modified,
			Created,
			Deleted,
			Renamed
		};

	};
};
