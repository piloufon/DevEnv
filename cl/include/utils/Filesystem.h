#pragma once
#include <filesystem>
#include <span>

namespace Filesystem {
	struct MetaData {
		uint64_t last_time_modified = 0;
		// more later
	};
	bool file_exist(const std::filesystem::path& file_path);
	bool directory_exist(const std::filesystem::path& dir_path);
	bool has_file(const std::filesystem::path& dir_path);
	MetaData get_metadata(const std::filesystem::path& path);

	bool read_file(const std::filesystem::path& file_path, std::vector<uint8_t>& result, size_t offset = 0, size_t offset_end = 0);
	bool read_file(const std::filesystem::path&, std::span<uint8_t> out, size_t offset = 0, size_t offset_end = 0); // Pre-allocated buffer

	bool write_file(const std::filesystem::path& file_path, std::span<const uint8_t> data_to_write, size_t offset);
	bool resize_file(const std::filesystem::path& file_path, size_t size);
	
	bool append_file(const std::filesystem::path& file_path, std::span<const uint8_t> data_to_write);
	bool write_insert(const std::filesystem::path& file_path, std::span<const uint8_t> data_to_write, size_t offset);
	bool erase_section(const std::filesystem::path& file_path, size_t offset, size_t offset_end = 0);

	


	bool create_file(std::filesystem::path& dir_path, std::filesystem::path& name);
	bool delete_file(const std::filesystem::path& file_path);
	bool rename_file(const std::filesystem::path& src, std::string_view dst);
	bool copy_file(const std::filesystem::path& src, const std::filesystem::path& dst);
	bool move_file(const std::filesystem::path& src, const std::filesystem::path& dst);
	bool create_directory(const std::filesystem::path& dir_path, const std::filesystem::path& dir_name);
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
