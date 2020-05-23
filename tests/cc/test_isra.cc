/*
 * Copyright (c) 2020 Evan Klitzke
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

#include <string>

#include "BPF.h"
#include "catch.hpp"

TEST_CASE("test isra", "find") {
  const std::string kallsyms = R"(
0000000000000000 A fixed_percpu_data
0000000000000000 A __per_cpu_start
0000000000000000 A cpu_debug_store
0000000000000000 A irq_stack_backing_store
0000000000000000 A cpu_tss_rw
0000000000000000 A gdt_page
0000000000000000 A gdt_page.isra.0
0000000000000000 t _rs_collect_tx_data.constprop.0.isra.0	[iwlmvm]
0000000000000000 t sof_suspend.isra.0	[snd_sof]
0000000000000000 t sof_suspend.isra.0.cold	[snd_sof]
0000000000000000 t sof_resume.isra.0	[snd_sof]
0000000000000000 t sof_resume.isra.0.cold	[snd_sof]
0000000000000000 t skl_free.isra.0	[snd_soc_skl]
0000000000000000 t skl_decoupled_trigger.isra.0	[snd_soc_skl]
0000000000000000 t skl_setup_out_format.isra.0	[snd_soc_skl]
0000000000000000 t skl_set_base_module_format.isra.0	[snd_soc_skl]
0000000000000000 t skl_get_mconfig_cap_cpr.isra.0	[snd_soc_skl]
0000000000000000 t skl_get_mconfig_pb_cpr.isra.0	[snd_soc_skl]
0000000000000000 t skl_tplg_fill_dma_id.isra.0	[snd_soc_skl]
0000000000000000 t skl_tplg_set_module_bind_params.isra.0	[snd_soc_skl]
0000000000000000 t fuse_fh_to_parent	[fuse]
0000000000000000 t fuse_show_options	[fuse]
)";

  ebpf::Isra isra;
  std::istringstream in(kallsyms);
  isra.init(in);

  // This should be null because it's not a symbol of type "t"
  REQUIRE(isra.find("gdt_page.isra.0") == nullptr);

  // This should be null because it's not an isra symbol
  REQUIRE(isra.find("fuse_show_options") == nullptr);

  // This should be null because it's not an isra symbol
  const std::string *p = isra.find("skl_free");
  REQUIRE(p != nullptr);
  REQUIRE(*p == "skl_free.isra.0");

  // We should get the first lexicographical match for this one
  p = isra.find("sof_suspend");
  REQUIRE(p != nullptr);
  REQUIRE(*p == "sof_suspend.isra.0");

  // It needs to be a real match, not a partial match
  REQUIRE(isra.find("sof_") == nullptr);
}
