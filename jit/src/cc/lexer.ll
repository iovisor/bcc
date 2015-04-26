/*
 * =====================================================================
 * Copyright (c) 2012, PLUMgrid, http://plumgrid.com
 *
 * This source is subject to the PLUMgrid License.
 * All rights reserved.
 *
 * THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF
 * ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * PLUMgrid confidential information, delete if you are not the
 * intended recipient.
 *
 * =====================================================================
 */

%{
#include "cc/lexer.h"
%}

%option yylineno nodefault yyclass="Lexer" noyywrap c++ prefix="ebpfcc"
%option never-interactive
%{
#include <string>
#include "cc/parser.yy.hh"
std::string tmp_str_cc;
%}

%x STRING_
%%

\'                      {BEGIN STRING_;}
<STRING_>\'             { BEGIN 0;
                        yylval_->string = new std::string(tmp_str_cc);
                        tmp_str_cc = "";
                        return Tok::TSTRING;
                        }
<STRING_>.              {tmp_str_cc += *yytext; }
<STRING_>\n              {tmp_str_cc += "\n"; }



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
"."                     return save(Tok::TDOT);
","                     return save(Tok::TCOMMA);
"+"                     return save(Tok::TPLUS);
"-"                     return save(Tok::TMINUS);
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

"const"                 return save(Tok::TCONST);
"struct"                return save(Tok::TSTRUCT);
"var"                   return save(Tok::TVAR);
"state"                 return save(Tok::TSTATE);
"timer"                 return save(Tok::TTIMER);
"goto"                  return save(Tok::TGOTO);
"continue"              return save(Tok::TCONTINUE);
"next"                  return save(Tok::TNEXT);
"on_match"              return save(Tok::TMATCH);
"on_miss"               return save(Tok::TMISS);
"on_failure"            return save(Tok::TFAILURE);
"on_valid"              return save(Tok::TVALID);
"true"                  return save(Tok::TTRUE);
"false"                 return save(Tok::TFALSE);
"if"                    return save(Tok::TIF);
"else"                  return save(Tok::TELSE);
"switch"                return save(Tok::TSWITCH);
"case"                  return save(Tok::TCASE);
"return"                return save(Tok::TRETURN);

[a-zA-Z][a-zA-Z0-9_]*   return save(Tok::TIDENTIFIER);
[0-9]+                  return save(Tok::TINTEGER);
0x[0-9a-fA-F]+          return save(Tok::THEXINTEGER);

.                       printf("Unknown token\n"); yyterminate();

%%
