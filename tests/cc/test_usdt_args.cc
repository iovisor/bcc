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

    verify_register(parser, 8, "%rdi");
    verify_register(parser, 8, "%rax");
    verify_register(parser, 8, "%rsi");
    verify_register(parser, -8, "%rbx");
    verify_register(parser, 4, "%r12");

    verify_register(parser, 8, "%rbp", -8);
    verify_register(parser, 4, "%rax", 0);

    verify_register(parser, -4, "%rip", 0, std::string("global_max_action"));
    verify_register(parser, 8, "%rip", 24, std::string("mp_"));

    REQUIRE(parser.done());
  }
}
