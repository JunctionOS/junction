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

Status<std::shared_ptr<Inode>> LookupPath(std::shared_ptr<Inode> pos,
                                          std::string_view path) {
  std::vector<std::string_view> spath = split(path, '/');
  if (spath.size() == 0) return MakeError(EINVAL);

  for (std::string_view v : spath) {
    if (pos->get_type() != kFlagDirectory) return MakeError(ENOTDIR);
    auto dir = std::static_pointer_cast<IDir>(pos);
    if (v == ".") continue;
    if (v == "..") {
      pos = dir->get_parent();
      continue;
    }
    Status<std::shared_ptr<Inode>> ret = dir->Lookup(v);
    if (!ret) return MakeError(ret);
    pos = std::move(*ret);
  }

  return pos;
}

}  // namespace

Status<std::shared_ptr<Inode>> FSLookup(const FSRoot &root,
                                        std::string_view path) {
  std::shared_ptr<IDir> pos = path[0] == '/' ? root.get_root() : root.get_cwd();
  Status<std::shared_ptr<Inode>> ret = LookupPath(pos, path);
  return LookupPath(pos, path);
}

}  // namespace junction
