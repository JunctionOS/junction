// core.cc - core file system support

#include <algorithm>

#include "junction/base/string.h"
#include "junction/fs/fs.h"

namespace junction {

namespace {

constexpr bool NameIsValid(std::string_view name) {
  return std::none_of(std::begin(name), std::end(name),
                      [](char c) { return c == '/' || c == '\0'; });
}

Status<std::shared_ptr<Inode>> LookupInode(
    std::shared_ptr<Inode> pos, const std::vector<std::string_view> &spath) {
  for (std::string_view v : spath) {
    if (pos->get_type() != kTypeDirectory) return MakeError(ENOTDIR);
    auto &dir = static_cast<IDir &>(*pos);
    if (v == ".") continue;
    if (v == "..") {
      pos = dir.get_parent();
      continue;
    }
    Status<std::shared_ptr<Inode>> ret = dir.Lookup(v);
    if (!ret) return MakeError(ret);
    pos = std::move(*ret);
  }

  return pos;
}

Status<std::tuple<std::shared_ptr<IDir>, std::string_view>> LookupIDir(
    std::shared_ptr<Inode> pos, std::string_view path) {
  std::vector<std::string_view> spath = split(path, '/');
  if (spath.empty()) return MakeError(EINVAL);

  std::string_view name = spath.back();
  spath.pop_back();
  if (!NameIsValid(name)) return MakeError(EINVAL);

  Status<std::shared_ptr<Inode>> ret = LookupInode(pos, spath);
  if (!ret) return MakeError(ret);
  if ((*ret)->get_type() != kTypeDirectory) return MakeError(ENOTDIR);
  return std::make_tuple(std::static_pointer_cast<IDir>(std::move(*ret)), name);
}

Status<std::tuple<std::shared_ptr<IDir>, std::string_view>> LookupIDir(
    const FSRoot &root, std::string_view path) {
  std::shared_ptr<IDir> pos = path[0] == '/' ? root.get_root() : root.get_cwd();
  return LookupIDir(pos, path);
}

}  // namespace

//
// System call implementations
//

#if 0
int usys_mknod(const char *path, mode_t mode, dev_t dev) {
  FSRoot root;

  // Find the directory
  auto ret = LookupIDir(root, path);
  if (!ret) return MakeCError(ret);
  auto [idir, name] = *ret;

  // Do mknod
  if (auto ret = idir->MkNod(name, mode, dev); !ret) return MakeCError(ret);
  return 0;
}
#endif

}  // namespace junction
