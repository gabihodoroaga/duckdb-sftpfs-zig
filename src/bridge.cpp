#include "include/bridge.h"

#include "duckdb.h"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_opener.hpp"
#include "duckdb/main/config.hpp"
#include "include/bridge.hpp"

#include <cstdio>
#include <ctime>

extern "C" {

// implemented in zig
bool sftpfs_init_ext(char **err_msg);
size_t file_handle_create(const char *path, void *username, char **err_msg);
void file_handle_close(size_t handle);
void file_handle_seek(size_t handle, idx_t location);
uint64_t file_handle_seek_position(size_t handle);
bool file_handle_get_file_size(size_t handle, int64_t *file_size, char **err_msg);
bool file_handle_get_last_modified(size_t handle, long *last_modified, char **err_msg);
bool file_handle_read(size_t handle, void *buffer, int64_t nr_bytes, int64_t *n_read, char **err_msg);
bool file_handle_read_location(size_t handle, void *buffer, int64_t nr_bytes, idx_t location, int64_t *n_read,
                               char **err_msg);

// called by duckdb cli using the convention {extension_name}_init(db)
DUCKDB_EXTENSION_API void sftpfs_init(duckdb::DatabaseInstance &db) {
	duckdb::DuckDB db_wrapper(db);
	db_wrapper.LoadExtension<duckdb::SftpfsExtension>();
}

// called by duckdb cli using the convention {extension_name}_version()
DUCKDB_EXTENSION_API const char *sftpfs_version() {
	return duckdb::DuckDB::LibraryVersion();
}
};

namespace duckdb {
static void LoadInternal(DatabaseInstance &instance) {
	// register the file system here
	auto &fs = instance.GetFileSystem();
	fs.RegisterSubSystem(make_uniq<SFTPFileSystem>());

	auto &config = DBConfig::GetConfig(instance);
	config.AddExtensionOption("sftp_identity_file", "Identity file path to be used for ssh authentication",
	                          LogicalType::VARCHAR);
	config.AddExtensionOption("sftp_private_key", "The private key to be used for ssh authentication",
	                          LogicalType::VARCHAR);
	config.AddExtensionOption("sftp_private_key_password", "The password used to decrypt the private key",
	                          LogicalType::VARCHAR);
	config.AddExtensionOption("sftp_username", "User name to be used to authenticate all sftp requests",
	                          LogicalType::VARCHAR);
	config.AddExtensionOption("sftp_password", "Password used to be used to authenticate all sftp requests",
	                          LogicalType::VARCHAR);
}

SftpException::SftpException(const string &msg) : Exception(ExceptionType::UNKNOWN_TYPE, msg) {
}

void SftpfsExtension::Load(DuckDB &db) {
	LoadInternal(*db.instance);
	char *err_msg;
	if (!sftpfs_init_ext(&err_msg)) {
		throw SftpException("Failed to load extension: %s", err_msg);
	};
}

std::string SftpfsExtension::Name() {
	return "sftpfs";
}

// SFTPFileHandle implementation

SFTPFileHandle::SFTPFileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags, size_t handle)
    : FileHandle(fs, file.path, flags), ext_handle(handle) {
}

void SFTPFileHandle::Close() {
}

SFTPFileHandle::~SFTPFileHandle() {
	file_handle_close(ext_handle);
}

// SFTPFileSystem implementation

void SFTPFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	auto &sfh = handle.Cast<SFTPFileHandle>();

	fprintf(stderr, "direct io is %d\n", sfh.flags.DirectIO());

	char *err_msg;
	int64_t n_read;
	if (!file_handle_read_location(sfh.ext_handle, buffer, nr_bytes, location, &n_read, &err_msg)) {
		throw SftpException("Failed to read file %s: %s", sfh.path, err_msg);
	}
}

int64_t SFTPFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes) {
	auto &sfh = handle.Cast<SFTPFileHandle>();
	char *err_msg;
	int64_t n_read;
	if (!file_handle_read(sfh.ext_handle, buffer, nr_bytes, &n_read, &err_msg)) {
		throw SftpException("Failed to read file %s: %s", sfh.path, err_msg);
	}
	return n_read;
}

void SFTPFileSystem::Write(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	throw NotImplementedException("SFTP Write not implemented");
}

int64_t SFTPFileSystem::Write(FileHandle &handle, void *buffer, int64_t nr_bytes) {
	throw NotImplementedException("SFTP Write not implemented");
}

void SFTPFileSystem::FileSync(FileHandle &handle) {
	throw NotImplementedException("SFTP FileSync not implemented");
}

int64_t SFTPFileSystem::GetFileSize(FileHandle &handle) {
	auto &sfh = handle.Cast<SFTPFileHandle>();
	char *err_msg;
	int64_t file_size;
	if (!file_handle_get_file_size(sfh.ext_handle, &file_size, &err_msg)) {
		throw SftpException("Failed to get the size for file %s: %s", sfh.path, err_msg);
	}
	return file_size;
}

time_t SFTPFileSystem::GetLastModifiedTime(FileHandle &handle) {
	auto &sfh = handle.Cast<SFTPFileHandle>();
	char *err_msg;
	time_t last_modified;
	if (!file_handle_get_last_modified(sfh.ext_handle, &last_modified, &err_msg)) {
		throw SftpException("Failed to get the last modified time for file %s: %s", sfh.path, err_msg);
	}
	return last_modified;
}

bool SFTPFileSystem::FileExists(const string &filename, optional_ptr<FileOpener> opener) {
	throw NotImplementedException("FileExists not implemented");
}

void SFTPFileSystem::Seek(FileHandle &handle, idx_t location) {
	auto &sfh = handle.Cast<SFTPFileHandle>();
	file_handle_seek(sfh.ext_handle, location);
}

idx_t SFTPFileSystem::SeekPosition(FileHandle &handle) {
	auto &sfh = handle.Cast<SFTPFileHandle>();
	return file_handle_seek_position(sfh.ext_handle);
}

bool SFTPFileSystem::CanHandleFile(const string &fpath) {
	return fpath.rfind("sftp://", 0) == 0;
}

unique_ptr<FileHandle> SFTPFileSystem::OpenFileExtended(const OpenFileInfo &file, FileOpenFlags flags,
                                                        optional_ptr<FileOpener> opener) {

	FileOpenerInfo info;
	info.file_path = file.path;
	string username, password, identity_file, private_key, private_key_password;
	FileOpener::TryGetCurrentSetting(opener, "sftp_username", username, info);
	FileOpener::TryGetCurrentSetting(opener, "sftp_password", password, info);
	FileOpener::TryGetCurrentSetting(opener, "sftp_identity_file", identity_file, info);
	FileOpener::TryGetCurrentSetting(opener, "sftp_private_key", private_key, info);
	FileOpener::TryGetCurrentSetting(opener, "sftp_private_key_password", private_key_password, info);

	duckdb_settings settings = duckdb_settings {username.c_str(), password.c_str(), identity_file.c_str(),
	                                            private_key.c_str(), private_key_password.c_str()};
	char *err_msg;
	auto ext_handle = file_handle_create(file.path.c_str(), &settings, &err_msg);
	if (ext_handle == 0) {
		throw ConnectionException("Failed to create file handle for file %s: %s", file.path, err_msg);
	}

	auto handle = duckdb::make_uniq<SFTPFileHandle>(*this, file, flags, ext_handle);
	return std::move(handle);
}

// SFTPFileSystem implementation

} // namespace duckdb
