#include <string>
#include "catch.hpp"
#include "usdt.h"

static void verify_register(USDT::ArgumentParser_x64 &parser, int arg_size,
                            const std::string &register_name, int constant,
                            int deref_offset, const std::string &deref_ident) {
  USDT::Argument arg;
  REQUIRE(parser.parse(arg));
  REQUIRE(arg.arg_size == arg_size);
  REQUIRE(arg.register_name == register_name);
  REQUIRE(arg.constant == constant);
  REQUIRE(arg.deref_offset == deref_offset);
  REQUIRE(arg.deref_ident == deref_ident);
}

TEST_CASE("test usdt argument parsing", "[usdt]") {
  SECTION("argument examples from the Python implementation") {
    USDT::ArgumentParser_x64 parser(
        "-4@$0 8@$1234 %rdi %rax %rsi "
        "-8@%rbx 4@%r12 8@-8(%rbp) 4@(%rax) "
        "-4@global_max_action(%rip) "
        "8@24+mp_(%rip) ");

    verify_register(parser, -4, "", 0, 0, "");
    verify_register(parser, 8, "", 1234, 0, "");
    verify_register(parser, 8, "%rdi", 0, 0, "");
    verify_register(parser, 8, "%rax", 0, 0, "");
    verify_register(parser, 8, "%rsi", 0, 0, "");
    verify_register(parser, -8, "%rbx", 0, 0, "");
    verify_register(parser, 4, "%r12", 0, 0, "");
    verify_register(parser, 8, "%rbp", 0, -8, "");
    verify_register(parser, 4, "%rax", 0, 0, "");
    verify_register(parser, -4, "%rip", 0, 0, "global_max_action");
    verify_register(parser, 8, "%rip", 0, 24, "mp_");

    REQUIRE(parser.done());
  }
}
