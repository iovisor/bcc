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

%{
#include "lexer.h"
%}

%option yylineno nodefault yyclass="Lexer" noyywrap c++ prefix="ebpfcc"
%option never-interactive
%{
#include <string>
#include "parser.yy.hh"
std::string tmp_str_cc;
%}

%x STRING_
%%

\"                      {BEGIN STRING_;}
<STRING_>\"             { BEGIN 0;
                        yylval_->string = new std::string(tmp_str_cc);
                        tmp_str_cc = "";
                        return Tok::TSTRING;
                        }
<STRING_>\\n            {tmp_str_cc += "\n"; }
<STRING_>.              {tmp_str_cc += *yytext; }



[ \t]+                  { save_text(); }
\n                      { if (next_line()) { return save(Tok::TSEMI, true); } }
"//".*\n                { if (next_line()) { return save(Tok::TSEMI, true); } }
^"#"                    return save(Tok::TPRAGMA);
"="                     return save(Tok::TEQUAL);
"=="                    return save(Tok::TCEQ);
"!="                    return save(Tok::TCNE);
"<"                     return save(Tok::TCLT);
"<="                    return save(Tok::TCLE);
">"                     return save(Tok::TCGT);
">="                    return save(Tok::TCGE);
"("                     return save(Tok::TLPAREN);
")"                     return save(Tok::TRPAREN);
"{"                     return save(Tok::TLBRACE);
"}"                     return save(Tok::TRBRACE);
"["                     return save(Tok::TLBRACK);
"]"                     return save(Tok::TRBRACK);
"->"                    return save(Tok::TARROW);
"."                     return save(Tok::TDOT);
","                     return save(Tok::TCOMMA);
"+"                     return save(Tok::TPLUS);
"++"                    return save(Tok::TINCR);
"-"                     return save(Tok::TMINUS);
"--"                    return save(Tok::TDECR);
"*"                     return save(Tok::TMUL);
"/"                     return save(Tok::TDIV);
"%"                     return save(Tok::TMOD);
"^"                     return save(Tok::TXOR);
"$"                     return save(Tok::TDOLLAR);
"!"                     return save(Tok::TNOT);
"~"                     return save(Tok::TCMPL);
":"                     return save(Tok::TCOLON);
"::"                    return save(Tok::TSCOPE);
";"                     return save(Tok::TSEMI);
"&&"                    return save(Tok::TAND);
"||"                    return save(Tok::TOR);
"&"                     return save(Tok::TLAND);
"|"                     return save(Tok::TLOR);
"@"                     return save(Tok::TAT);

"case"                  return save(Tok::TCASE);
"continue"              return save(Tok::TCONTINUE);
"else"                  return save(Tok::TELSE);
"false"                 return save(Tok::TFALSE);
"goto"                  return save(Tok::TGOTO);
"if"                    return save(Tok::TIF);
"next"                  return save(Tok::TNEXT);
"on_match"              return save(Tok::TMATCH);
"on_miss"               return save(Tok::TMISS);
"on_failure"            return save(Tok::TFAILURE);
"on_valid"              return save(Tok::TVALID);
"return"                return save(Tok::TRETURN);
"state"                 return save(Tok::TSTATE);
"struct"                return save(Tok::TSTRUCT);
"switch"                return save(Tok::TSWITCH);
"true"                  return save(Tok::TTRUE);
"u8"                    return save(Tok::TU8);
"u16"                   return save(Tok::TU16);
"u32"                   return save(Tok::TU32);
"u64"                   return save(Tok::TU64);

[a-zA-Z_][a-zA-Z0-9_]*  return save(Tok::TIDENTIFIER);
[0-9]+                  return save(Tok::TINTEGER);
0x[0-9a-fA-F]+          return save(Tok::THEXINTEGER);

.                       printf("Unknown token \"%s\"\n", yytext); yyterminate();

%%
