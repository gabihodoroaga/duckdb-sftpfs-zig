#pragma once

#include "duckdb.hpp"

namespace duckdb {
class SftpException : public Exception {
public:
	DUCKDB_API explicit SftpException(const string &msg);

	template <typename... ARGS>
	explicit SftpException(const string &msg, ARGS... params) : SftpException(ConstructMessage(msg, params...)) {
	}
};

class SftpfsExtension : public Extension {
public:
	void Load(DuckDB &db) override;
	std::string Name() override;
};

class SFTPFileHandle : public FileHandle {

public:
	SFTPFileHandle(FileSystem &fs, const OpenFileInfo &file, FileOpenFlags flags, size_t handle);

	size_t ext_handle;

public:
	~SFTPFileHandle() override;
	void Close() override;
};

class SFTPFileSystem : public FileSystem {
public:
	vector<OpenFileInfo> Glob(const string &path, FileOpener *opener = nullptr) override {
		return {path}; // FIXME
	}

	void Read(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) override;
	int64_t Read(FileHandle &handle, void *buffer, int64_t nr_bytes) override;
	void Write(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) override;
	int64_t Write(FileHandle &handle, void *buffer, int64_t nr_bytes) override;
	void FileSync(FileHandle &handle) override;
	int64_t GetFileSize(FileHandle &handle) override;
	time_t GetLastModifiedTime(FileHandle &handle) override;
	string GetVersionTag(FileHandle &handle) override {
		return "";
	};
	bool FileExists(const string &filename, optional_ptr<FileOpener> opener) override;
	void Seek(FileHandle &handle, idx_t location) override;
	idx_t SeekPosition(FileHandle &handle) override;
	bool CanHandleFile(const string &fpath) override;
	bool CanSeek() override {
		return true;
	}
	bool OnDiskFile(FileHandle &handle) override {
		return false;
	}
	bool IsPipe(const string &filename, optional_ptr<FileOpener> opener) override {
		return false;
	}
	string GetName() const override {
		return "SFTPFileSystem";
	}
	string PathSeparator(const string &path) override {
		return "/";
	}

protected:
	unique_ptr<FileHandle> OpenFileExtended(const OpenFileInfo &file, FileOpenFlags flags,
	                                        optional_ptr<FileOpener> opener) override;
	bool SupportsOpenFileExtended() const override {
		return true;
	}
};

} // namespace duckdb
