/*
 * Copyright (c) 2016 PLUMgrid, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "exported_files.h"

using std::map;
using std::string;

namespace ebpf {

// c++11 feature for including raw string literals
// see http://www.stroustrup.com/C++11FAQ.html#raw-strings

map<string, const char *> ExportedFiles::headers_ = {
  {
    "/virtual/include/bcc/bpf.h",
    #include "compat/linux/virtual_bpf.h"
  },
  {
    "/virtual/include/bcc/proto.h",
    #include "export/proto.h"
  },
  {
    "/virtual/include/bcc/helpers.h",
    #include "export/helpers.h"
  },
  {
    "/virtual/lib/clang/include/stdarg.h",
    #include "clang/include/stdarg.h"
  },
};

map<string, const char *> ExportedFiles::footers_ = {
  {
    "/virtual/include/bcc/footer.h",
    #include "export/footer.h"
  },
};

}
