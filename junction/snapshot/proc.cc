#include <cstdio>

extern "C" {
#include <fcntl.h>
}

#include "junction/base/error.h"
#include "junction/kernel/ksys.h"
#include "junction/snapshot/proc.h"

namespace junction {
// Read and Deserialize the ProcessMetadata
Status<ProcessMetadata> ReadProcessMetadata(std::string const &path) {
  struct stat stat;
  Status<void> ret = KernelStat(path.c_str(), &stat);
  if (unlikely(!ret)) {
    return MakeError(ret);
  }

  auto metadata_file = KernelFile::Open(path, O_RDONLY, 0);
  if (unlikely(!metadata_file)) {
    return MakeError(metadata_file);
  }

  std::vector<std::byte> serialized(stat.st_size);
  Status<size_t> written =
      (*metadata_file).Read(std::as_writable_bytes(std::span(serialized)));
  if (!written) {
    return MakeError(written);
  }

  assert(*written == static_cast<size_t>(stat.st_size));

  return ProcessMetadata::FromBytes(std::span(serialized));
}

}  // namespace junction
