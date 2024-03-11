// linuxfile.h - support for Linux files
extern "C" {
#include <sys/stat.h>
}

#pragma once

#include <memory>
#include <span>
#include <string_view>

#include "junction/base/error.h"
#include "junction/bindings/log.h"
#include "junction/kernel/file.h"
#include "junction/kernel/ksys.h"
#include "junction/snapshot/cereal.h"

namespace junction {

class LinuxFile : public File {
  class Token {
    // https://abseil.io/tips/134
   private:
    explicit Token() = default;
    friend LinuxFile;
  };

 public:
  LinuxFile(Token, int fd, int flags, mode_t mode,
            std::string &&pathname) noexcept;
  LinuxFile(Token, int fd, int flags, mode_t mode,
            std::string_view pathname) noexcept;
  virtual ~LinuxFile();

  static std::shared_ptr<LinuxFile> Open(std::string_view pathname, int flags,
                                         mode_t mode);
  virtual Status<size_t> Read(std::span<std::byte> buf, off_t *off) override;
  virtual Status<size_t> Write(std::span<const std::byte> buf,
                               off_t *off) override;
  virtual Status<off_t> Seek(off_t off, SeekFrom origin) override;
  virtual Status<void *> MMap(void *addr, size_t length, int prot, int flags,
                              off_t off);
  virtual Status<void> Stat(struct stat *statbuf, int flags) override;
  virtual Status<int> GetDents(void *dirp, unsigned int count) override;
  virtual Status<int> GetDents64(void *dirp, unsigned int count) override;
  virtual Status<void> Ioctl(unsigned long request, char *argp) override;

  [[nodiscard]] int get_fd() const { return fd_; }

  // Hacky get_size, calls fstatat and then caches the result
  [[nodiscard]] size_t get_size() {
    if (size_ != -1) return size_;
    struct stat buf;
    Status<void> ret = Stat(&buf, AT_EMPTY_PATH);
    if (unlikely(!ret)) throw std::runtime_error("bad stat");
    size_ = buf.st_size;
    return size_;
  }

 private:
  friend class cereal::access;

  template <class Archive>
  void save(Archive &ar) const {
    ar(get_filename(), get_flags(), get_mode(), cereal::base_class<File>(this));
  }

  template <class Archive>
  static void load_and_construct(Archive &ar,
                                 cereal::construct<LinuxFile> &construct) {
    std::string filename;
    int flags;
    mode_t mode;
    ar(filename, flags, mode);

    int fd = ksys_open(filename.data(), flags, mode);
    if (unlikely(fd < 0)) {
      LOG(ERR) << "failed to re-open linux file " << filename;
      BUG();
    }
    construct(Token{}, fd, flags, mode, std::move(filename));
    ar(cereal::base_class<File>(construct.ptr()));
  }

  int fd_{-1};
  ssize_t size_{-1};
};

}  // namespace junction

CEREAL_REGISTER_TYPE(junction::LinuxFile);
