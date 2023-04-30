// core.cc - core file system support

#include "junction/fs/fs.h"

namespace junction {

Status<std::shared_ptr<Inode>> FSLookup(const FSRoot &root,
                                        std::string_view path) {
  return {};
}

}  // namespace junction
