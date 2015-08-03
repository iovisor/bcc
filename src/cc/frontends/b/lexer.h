/*
 * Copyright (c) 2015 PLUMgrid, Inc.
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

#pragma once

#ifndef yyFlexLexerOnce
#undef yyFlexLexer
#define yyFlexLexer ebpfccFlexLexer
#include <FlexLexer.h>
#endif

#undef YY_DECL
#define YY_DECL int ebpf::cc::Lexer::yylex()

#include <iostream> // NOLINT
#include <list>
#include "parser.yy.hh"

namespace ebpf {
namespace cc {

typedef BisonParser::token::yytokentype Tok;

class Lexer : public yyFlexLexer {
 public:
  explicit Lexer(std::istream* in)
      : yyFlexLexer(in), prev_tok_(Tok::TSEMI), lines_({""}), yylval_(NULL), yylloc_(NULL) {
    if (!in || !*in)
      fprintf(stderr, "Unable to open input stream\n");
  }
  int yylex(BisonParser::semantic_type *lval, BisonParser::location_type *lloc) {
    yylval_ = lval;
    yylloc_ = lloc;
    return yylex();
  }
  std::string text(const BisonParser::location_type& loc) const {
    return text(loc.begin, loc.end);
  }
  std::string text(const position& begin, const position& end) const {
    std::string result;
    for (size_t i = begin.line; i <= end.line; ++i) {
      if (i == begin.line && i == end.line) {
        result += lines_.at(i - 1).substr(begin.column - 1, end.column - begin.column);
      } else if (i == begin.line && i < end.line) {
        result += lines_.at(i - 1).substr(begin.column - 1);
      } else if (i > begin.line && i == end.line) {
        result += lines_.at(i - 1).substr(0, end.column);
      } else if (i > begin.line && i == end.line) {
        result += lines_.at(i - 1);
      }
    }
    return result;
  }
 private:

  // true if a semicolon should be replaced here
  bool next_line() {
    lines_.push_back("");
    yylloc_->lines();
    yylloc_->step();
    switch (prev_tok_) {
    case Tok::TIDENTIFIER:
    case Tok::TINTEGER:
    case Tok::THEXINTEGER:
    case Tok::TRBRACE:
    case Tok::TRPAREN:
    case Tok::TRBRACK:
    case Tok::TTRUE:
    case Tok::TFALSE:
      // uncomment to add implicit semicolons
      //return true;
    default:
      break;
    }
    return false;
  }

  Tok save(Tok tok, bool ignore_text = false) {
    if (!ignore_text) {
      save_text();
    }

    switch (tok) {
    case Tok::TIDENTIFIER:
    case Tok::TINTEGER:
    case Tok::THEXINTEGER:
      yylval_->string = new std::string(yytext, yyleng);
      break;
    default:
      yylval_->token = tok;
    }
    prev_tok_ = tok;
    return tok;
  }

  /*
  std::string * alloc_string(const char *c, size_t len) {
    strings_.push_back(std::unique_ptr<std::string>(new std::string(c, len)));
    return strings_.back().get();
  }

  std::string * alloc_string(const std::string &s) {
    strings_.push_back(std::unique_ptr<std::string>(new std::string(s)));
    return strings_.back().get();
  }
  */

  void save_text() {
    lines_.back().append(yytext, yyleng);
    yylloc_->columns(yyleng);
  }

  int yylex();
  Tok prev_tok_;
  std::vector<std::string> lines_;
  //std::list<std::unique_ptr<std::string>> strings_;
  BisonParser::semantic_type *yylval_;
  BisonParser::location_type *yylloc_;
};

}  // namespace cc
}  // namespace ebpf
