#pragma once

#include <boost/program_options.hpp>

#include "junction/base/error.h"

#ifndef CUSTOM_GLIBC_INTERPRETER_PATH
#define CUSTOM_GLIBC_INTERPRETER_PATH
#endif

#ifndef CUSTOM_GLIBC_DIR
#define CUSTOM_GLIBC_DIR
#endif

#ifndef CUSTOM_GLIBC_PRELOAD
#define CUSTOM_GLIBC_PRELOAD
#endif

namespace junction {

class JunctionCfg {
 public:
  using program_options = boost::program_options::options_description;

  [[nodiscard]] const std::string_view get_interp_path() const {
    return interp_path;
  }

  [[nodiscard]] const std::string_view get_ld_path() const { return ld_path; }

  [[nodiscard]] const std::string_view get_preload_path() const {
    return preload_path;
  }

  [[nodiscard]] program_options GetOptions();
  Status<void> FillFromArgs(int argc, char *argv[]);
  void Print();

 private:
  std::string interp_path{CUSTOM_GLIBC_INTERPRETER_PATH};
  std::string ld_path{CUSTOM_GLIBC_DIR};
  std::string preload_path{CUSTOM_GLIBC_PRELOAD};
};

JunctionCfg &GetCfg();

Status<void> init();

}  // namespace junction
