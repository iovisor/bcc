/*
 * Copyright (c) 2016 GitHub, Inc.
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
#include <iostream>
#include <string>

#include "catch.hpp"
#include "usdt.h"

using std::experimental::optional;
using std::experimental::nullopt;

static void verify_register(USDT::ArgumentParser_x64 &parser, int arg_size,
                            int constant) {
  USDT::Argument arg;
  REQUIRE(parser.parse(&arg));
  REQUIRE(arg.arg_size() == arg_size);

  REQUIRE(arg.constant());
  REQUIRE(arg.constant() == constant);
}

static void verify_register(USDT::ArgumentParser_x64 &parser, int arg_size,
                            const std::string &regname,
                            optional<int> deref_offset = nullopt,
                            optional<std::string> deref_ident = nullopt) {
  USDT::Argument arg;
  REQUIRE(parser.parse(&arg));
  REQUIRE(arg.arg_size() == arg_size);

  REQUIRE(arg.register_name());
  REQUIRE(arg.register_name() == regname);

  REQUIRE(arg.deref_offset() == deref_offset);
  REQUIRE(arg.deref_ident() == deref_ident);
}

TEST_CASE("test usdt argument parsing", "[usdt]") {
  SECTION("argument examples from the Python implementation") {
    USDT::ArgumentParser_x64 parser(
        "-4@$0 8@$1234 %rdi %rax %rsi "
        "-8@%rbx 4@%r12 8@-8(%rbp) 4@(%rax) "
        "-4@global_max_action(%rip) "
        "8@24+mp_(%rip) ");

    verify_register(parser, -4, 0);
    verify_register(parser, 8, 1234);

    verify_register(parser, 8, "di");
    verify_register(parser, 8, "ax");
    verify_register(parser, 8, "si");
    verify_register(parser, -8, "bx");
    verify_register(parser, 4, "r12");

    verify_register(parser, 8, "bp", -8);
    verify_register(parser, 4, "ax", 0);

    verify_register(parser, -4, "ip", 0, std::string("global_max_action"));
    verify_register(parser, 8, "ip", 24, std::string("mp_"));

    REQUIRE(parser.done());
  }
}
