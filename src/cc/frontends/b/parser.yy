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

%skeleton "lalr1.cc"
%defines
%define namespace "ebpf::cc"
%define parser_class_name "BisonParser"
%parse-param { ebpf::cc::Lexer &lexer }
%parse-param { ebpf::cc::Parser &parser }
%lex-param { ebpf::cc::Lexer &lexer }
%locations

%code requires {
    #include <memory>
    #include <vector>
    #include <string>
    #include "node.h"
    // forward declaration
    namespace ebpf { namespace cc {
        class Lexer;
        class Parser;
    } }
}

%code {
    static int yylex(ebpf::cc::BisonParser::semantic_type *yylval,
                     ebpf::cc::BisonParser::location_type *yylloc,
                     ebpf::cc::Lexer &lexer);
}

%{
    #include "node.h"
    #include "parser.h"
    using std::unique_ptr;
    using std::vector;
    using std::string;
    using std::move;
%}

%union {
    Scopes::StateScope *state_scope;
    Scopes::VarScope *var_scope;
    BlockStmtNode *block;
    ExprNode *expr;
    MethodCallExprNode *call;
    StmtNode *stmt;
    IdentExprNode *ident;
    IntegerExprNode *numeric;
    BitopExprNode *bitop;
    ExprNodeList *args;
    IdentExprNodeList *ident_args;
    StmtNodeList *stmts;
    FormalList *formals;
    VariableDeclStmtNode *decl;
    StructVariableDeclStmtNode *type_decl;
    TableIndexExprNode *table_index;
    std::vector<int> *type_specifiers;
    std::string* string;
    int token;
}

/* Define the terminal symbols. */
%token <string> TIDENTIFIER TINTEGER THEXINTEGER TPRAGMA TSTRING
%token <token> TU8 TU16 TU32 TU64
%token <token> TEQUAL TCEQ TCNE TCLT TCLE TCGT TCGE TAND TOR
%token <token> TLPAREN TRPAREN TLBRACE TRBRACE TLBRACK TRBRACK
%token <token> TDOT TARROW TCOMMA TPLUS TMINUS TMUL TDIV TMOD TXOR TDOLLAR TCOLON TSCOPE TNOT TSEMI TCMPL TLAND TLOR
%token <token> TSTRUCT TSTATE TFUNC TGOTO TCONTINUE TNEXT TTRUE TFALSE TRETURN
%token <token> TIF TELSE TSWITCH TCASE
%token <token> TMATCH TMISS TFAILURE TVALID
%token <token> TAT

/* Define non-terminal symbols as defined in the above union */
%type <ident> ident scoped_ident dotted_ident any_ident
%type <expr> expr assign_expr return_expr init_arg_kv
%type <numeric> numeric
%type <bitop> bitop
%type <args> call_args /*init_args*/ init_args_kv
%type <ident_args> table_decl_args
%type <formals> struct_decl_stmts formals
%type <block> program block prog_decls
%type <decl> decl_stmt int_decl ref_stmt
%type <type_decl> type_decl ptr_decl
%type <stmt> stmt prog_decl var_decl struct_decl state_decl func_decl
%type <stmt> table_decl table_result_stmt if_stmt switch_stmt case_stmt onvalid_stmt
%type <var_scope> enter_varscope exit_varscope
%type <state_scope> enter_statescope exit_statescope
%type <stmts> stmts table_result_stmts case_stmts
%type <call> call_expr
%type <table_index> table_index_expr
%type <type_specifiers> type_specifiers
%type <stmt> pragma_decl
%type <token> type_specifier

/* taken from C++ operator precedence wiki page */
%nonassoc TSCOPE
%left TDOT TLBRACK TLBRACE TLPAREN TINCR TDECR
%right TNOT TCMPL
%left TMUL
%left TDIV
%left TMOD
%left TPLUS
%left TMINUS
%left TCLT TCLE TCGT TCGE
%left TCEQ
%left TCNE
%left TXOR
%left TAND
%left TOR
%left TLAND
%left TLOR
%right TEQUAL

%start program

%%

program
  : enter_statescope enter_varscope prog_decls exit_varscope exit_statescope
    { parser.root_node_ = $3; $3->scope_ = $2; }
  ;

/* program is a list of declarations */
prog_decls
  : prog_decl
    { $$ = new BlockStmtNode; $$->stmts_.push_back(StmtNode::Ptr($1)); }
  | prog_decls prog_decl
    { $1->stmts_.push_back(StmtNode::Ptr($2)); }
  ;

/*
 possible program declarations are:
  "struct {}"
  "state|on_miss|on_match|on_valid {}"
  "var <var_decl>"
  "Table <...> <ident>(size)"
 */
prog_decl
  : var_decl TSEMI
  | struct_decl TSEMI
  | state_decl
  | table_decl TSEMI
  | pragma_decl
  | func_decl
  ;

pragma_decl
  : TPRAGMA TIDENTIFIER TIDENTIFIER
    { $$ = new BlockStmtNode; parser.add_pragma(*$2, *$3); delete $2; delete $3; }
  | TPRAGMA TIDENTIFIER TSTRING
    { $$ = new BlockStmtNode; parser.add_pragma(*$2, *$3); delete $2; delete $3; }
  ;

stmts
  : stmt
    { $$ = new StmtNodeList; $$->push_back(StmtNode::Ptr($1)); }
  | stmts stmt
    { $1->push_back(StmtNode::Ptr($2)); }
  ;

stmt
  : expr TSEMI
    { $$ = new ExprStmtNode(ExprNode::Ptr($1));
      parser.set_loc($$, @$); }
  | assign_expr TSEMI
    { $$ = new ExprStmtNode(ExprNode::Ptr($1));
      parser.set_loc($$, @$); }
  | return_expr TSEMI
    { $$ = new ExprStmtNode(ExprNode::Ptr($1));
      parser.set_loc($$, @$); }
  | call_expr TLBRACE enter_varscope table_result_stmts exit_varscope TRBRACE TSEMI
    { $$ = new ExprStmtNode(ExprNode::Ptr($1));
      $1->block_->stmts_ = move(*$4); delete $4;
      $1->block_->scope_ = $3;
      parser.set_loc($$, @$); }
  | call_expr TLBRACE TRBRACE TSEMI  // support empty curly braces
    { $$ = new ExprStmtNode(ExprNode::Ptr($1));
      parser.set_loc($$, @$); }
  | if_stmt
  | switch_stmt
  | var_decl TSEMI
    { $$ = $1; }
  | state_decl
  | onvalid_stmt
  ;

call_expr
  : any_ident TLPAREN call_args TRPAREN
    { $$ = new MethodCallExprNode(IdentExprNode::Ptr($1), move(*$3), lexer.lineno()); delete $3;
      parser.set_loc($$, @$); }
  ;

block
  : TLBRACE stmts TRBRACE
    { $$ = new BlockStmtNode; $$->stmts_ = move(*$2); delete $2;
      parser.set_loc($$, @$); }
  | TLBRACE TRBRACE
    { $$ = new BlockStmtNode;
      parser.set_loc($$, @$); }
  ;

enter_varscope : /* empty */ { $$ = parser.scopes_->enter_var_scope(); } ;
exit_varscope : /* emtpy */ { $$ = parser.scopes_->exit_var_scope(); } ;
enter_statescope : /* empty */ { $$ = parser.scopes_->enter_state_scope(); } ;
exit_statescope : /* emtpy */ { $$ = parser.scopes_->exit_state_scope(); } ;

struct_decl
  : TSTRUCT ident TLBRACE struct_decl_stmts TRBRACE
    { $$ = parser.struct_add($2, $4); delete $4;
      parser.set_loc($$, @$); }
  ;

struct_decl_stmts
  : type_specifiers decl_stmt TSEMI
    { $$ = new FormalList; $$->push_back(VariableDeclStmtNode::Ptr($2)); }
  | struct_decl_stmts type_specifiers decl_stmt TSEMI
    { $1->push_back(VariableDeclStmtNode::Ptr($3)); }
  ;

table_decl
  : ident TCLT table_decl_args TCGT ident TLPAREN TINTEGER TRPAREN
    { $$ = parser.table_add($1, $3, $5, $7); delete $3;
      parser.set_loc($$, @$); }
  ;

table_decl_args
  : ident
    { $$ = new IdentExprNodeList; $$->push_back(IdentExprNode::Ptr($1)); }
  | table_decl_args TCOMMA ident
    { $$->push_back(IdentExprNode::Ptr($3)); }
  ;

state_decl
  : TSTATE scoped_ident enter_statescope enter_varscope block exit_varscope exit_statescope
    { $$ = parser.state_add($3, $2, $5); $5->scope_ = $4;
      if (!$$) YYERROR;
      parser.set_loc($$, @$); }
  | TSTATE scoped_ident TCOMMA TMUL enter_statescope enter_varscope block exit_varscope exit_statescope
    { $$ = parser.state_add($5, $2, new IdentExprNode(""), $7); $7->scope_ = $6;
      if (!$$) YYERROR;
      parser.set_loc($$, @$); }
  | TSTATE scoped_ident TCOMMA scoped_ident enter_statescope enter_varscope block exit_varscope exit_statescope
    { $$ = parser.state_add($5, $2, $4, $7); $7->scope_ = $6;
      if (!$$) YYERROR;
      parser.set_loc($$, @$); }
  ;

func_decl
  : type_specifiers ident enter_statescope enter_varscope TLPAREN formals TRPAREN block exit_varscope exit_statescope
    { $$ = parser.func_add($1, $3, $2, $6, $8); $8->scope_ = $4;
      if (!$$) YYERROR;
      parser.set_loc($$, @$); }
  ;

table_result_stmts
  : table_result_stmt
    { $$ = new StmtNodeList; $$->push_back(StmtNode::Ptr($1)); }
  | table_result_stmts table_result_stmt
    { $$->push_back(StmtNode::Ptr($2)); }
  ;

table_result_stmt
  : TMATCH ident enter_varscope TLPAREN formals TRPAREN block exit_varscope TSEMI
    { $$ = parser.result_add($1, $2, $5, $7); delete $5; $7->scope_ = $3;
      if (!$$) YYERROR;
      parser.set_loc($$, @$); }
  | TMISS ident enter_varscope TLPAREN TRPAREN block exit_varscope TSEMI
    { $$ = parser.result_add($1, $2, new FormalList, $6); $6->scope_ = $3;
      if (!$$) YYERROR;
      parser.set_loc($$, @$); }
  | TFAILURE ident enter_varscope TLPAREN formals TRPAREN block exit_varscope TSEMI
    { $$ = parser.result_add($1, $2, $5, $7); delete $5; $7->scope_ = $3;
      if (!$$) YYERROR;
      parser.set_loc($$, @$); }
  ;

formals
  : TSTRUCT ptr_decl
    { $$ = new FormalList; $$->push_back(VariableDeclStmtNode::Ptr(parser.variable_add(nullptr, $2))); }
  | formals TCOMMA TSTRUCT ptr_decl
    { $1->push_back(VariableDeclStmtNode::Ptr(parser.variable_add(nullptr, $4))); }
  ;

type_specifier
  : TU8
  | TU16
  | TU32
  | TU64
  ;

type_specifiers
  : type_specifier { $$ = new std::vector<int>; $$->push_back($1); }
  | type_specifiers type_specifier { $$->push_back($2); }
  ;

var_decl
  : type_specifiers decl_stmt
    { $$ = parser.variable_add($1, $2);
      if (!$$) YYERROR;
      parser.set_loc($$, @$); }
  | type_specifiers int_decl TEQUAL expr
    { $$ = parser.variable_add($1, $2, $4);
      if (!$$) YYERROR;
      parser.set_loc($$, @$); }
  | TSTRUCT type_decl TEQUAL TLBRACE init_args_kv TRBRACE
    { $$ = parser.variable_add($2, $5, true);
      if (!$$) YYERROR;
      parser.set_loc($$, @$); }
  /*| TSTRUCT type_decl TEQUAL TLBRACE init_args TRBRACE
    { $$ = parser.variable_add($2, $5, false);
      parser.set_loc($$, @$); }*/
  | TSTRUCT ref_stmt
    { $$ = parser.variable_add(nullptr, $2);
      if (!$$) YYERROR;
      parser.set_loc($$, @$); }
  ;

/* "id":"bitsize" or "type" "id" */
decl_stmt : int_decl { $$ = $1; } | type_decl { $$ = $1; };
int_decl : ident TCOLON TINTEGER
    { $$ = new IntegerVariableDeclStmtNode(IdentExprNode::Ptr($1), *$3); delete $3;
      parser.set_loc($$, @$); }
  ;

type_decl : scoped_ident ident
    { $$ = new StructVariableDeclStmtNode(IdentExprNode::Ptr($1), IdentExprNode::Ptr($2));
      parser.set_loc($$, @$); }
  ;

/* "type" "*" "id" */
ref_stmt : ptr_decl { $$ = $1; };
ptr_decl : scoped_ident TMUL ident
    { $$ = new StructVariableDeclStmtNode(IdentExprNode::Ptr($1), IdentExprNode::Ptr($3),
                                          VariableDeclStmtNode::STRUCT_REFERENCE);
      parser.set_loc($$, @$); }
  ;

/* normal initializer */
/* init_args
  : expr { $$ = new ExprNodeList; $$->push_back(ExprNode::Ptr($1)); }
  | init_args TCOMMA expr { $$->push_back(ExprNode::Ptr($3)); }
  ;*/

/* one or more of "field" = "expr" */
init_args_kv
  : init_arg_kv { $$ = new ExprNodeList; $$->push_back(ExprNode::Ptr($1)); }
  | init_args_kv TCOMMA init_arg_kv { $$->push_back(ExprNode::Ptr($3)); }
  ;
init_arg_kv
  : TDOT ident TEQUAL expr
    { $$ = new AssignExprNode(IdentExprNode::Ptr($2), ExprNode::Ptr($4));
      parser.set_loc($$, @$); }
  | TDOT ident bitop TEQUAL expr
    { $$ = new AssignExprNode(IdentExprNode::Ptr($2), ExprNode::Ptr($5)); $$->bitop_ = BitopExprNode::Ptr($3);
      parser.set_loc($$, @$); }
  ;

if_stmt
  : TIF expr enter_varscope block exit_varscope
    { $$ = new IfStmtNode(ExprNode::Ptr($2), StmtNode::Ptr($4));
      $4->scope_ = $3;
      parser.set_loc($$, @$); }
  | TIF expr enter_varscope block exit_varscope TELSE enter_varscope block exit_varscope
    { $$ = new IfStmtNode(ExprNode::Ptr($2), StmtNode::Ptr($4), StmtNode::Ptr($8));
      $4->scope_ = $3; $8->scope_ = $7;
      parser.set_loc($$, @$); }
  | TIF expr enter_varscope block exit_varscope TELSE if_stmt
    { $$ = new IfStmtNode(ExprNode::Ptr($2), StmtNode::Ptr($4), StmtNode::Ptr($7));
      $4->scope_ = $3;
      parser.set_loc($$, @$); }
  ;

onvalid_stmt
  : TVALID TLPAREN ident TRPAREN enter_varscope block exit_varscope
    { $$ = new OnValidStmtNode(IdentExprNode::Ptr($3), StmtNode::Ptr($6));
      $6->scope_ = $5;
      parser.set_loc($$, @$); }
  | TVALID TLPAREN ident TRPAREN enter_varscope block exit_varscope TELSE enter_varscope block exit_varscope
    { $$ = new OnValidStmtNode(IdentExprNode::Ptr($3), StmtNode::Ptr($6), StmtNode::Ptr($10));
      $6->scope_ = $5; $10->scope_ = $9;
      parser.set_loc($$, @$); }
  ;

switch_stmt
  : TSWITCH expr TLBRACE case_stmts TRBRACE
    { $$ = new SwitchStmtNode(ExprNode::Ptr($2), make_unique<BlockStmtNode>(move(*$4))); delete $4;
      parser.set_loc($$, @$); }
  ;

case_stmts
  : case_stmt
    { $$ = new StmtNodeList; $$->push_back(StmtNode::Ptr($1)); }
  | case_stmts case_stmt
    { $$->push_back(StmtNode::Ptr($2)); }
  ;

case_stmt
  : TCASE numeric block TSEMI
    { $$ = new CaseStmtNode(IntegerExprNode::Ptr($2), BlockStmtNode::Ptr($3));
      parser.set_loc($$, @$); }
  | TCASE TMUL block TSEMI
    { $$ = new CaseStmtNode(BlockStmtNode::Ptr($3));
      parser.set_loc($$, @$); }
  ;

numeric
  : TINTEGER
    { $$ = new IntegerExprNode($1);
      parser.set_loc($$, @$); }
  | THEXINTEGER
    { $$ = new IntegerExprNode($1);
      parser.set_loc($$, @$); }
  | TINTEGER TCOLON TINTEGER
    { $$ = new IntegerExprNode($1, $3);
      parser.set_loc($$, @$); }
  | THEXINTEGER TCOLON TINTEGER
    { $$ = new IntegerExprNode($1, $3);
      parser.set_loc($$, @$); }
  | TTRUE
    { $$ = new IntegerExprNode(new string("1"), new string("1"));
      parser.set_loc($$, @$); }
  | TFALSE
    { $$ = new IntegerExprNode(new string("0"), new string("1"));
      parser.set_loc($$, @$); }
  ;

assign_expr
  : expr TEQUAL expr
    { $$ = new AssignExprNode(ExprNode::Ptr($1), ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  /* The below has a reduce/reduce conflict.
     TODO: ensure the above is handled in the type check properly */
  /*| dotted_ident TEQUAL expr
    { $$ = new AssignExprNode(IdentExprNode::Ptr($1), ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | dotted_ident bitop TEQUAL expr
    { $$ = new AssignExprNode(IdentExprNode::Ptr($1), ExprNode::Ptr($4)); $$->bitop_ = BitopExprNode::Ptr($2);
      parser.set_loc($$, @$); }*/
  ;

return_expr
  : TRETURN expr
    { $$ = new ReturnExprNode(ExprNode::Ptr($2));
      parser.set_loc($$, @$); }
  ;

expr
  : call_expr
    { $$ = $1; }
  | call_expr bitop
    { $$ = $1; $$->bitop_ = BitopExprNode::Ptr($2); }
  | table_index_expr
    { $$ = $1; }
  | table_index_expr TDOT ident
    { $$ = $1; $1->sub_ = IdentExprNode::Ptr($3); }
  | any_ident
    { $$ = $1; }
  | TAT dotted_ident
    { $$ = new PacketExprNode(IdentExprNode::Ptr($2));
      $$->flags_[ExprNode::IS_REF] = true;
      parser.set_loc($$, @$); }
  | TDOLLAR dotted_ident
    { $$ = new PacketExprNode(IdentExprNode::Ptr($2));
      $$->flags_[ExprNode::IS_PKT] = true;
      parser.set_loc($$, @$); }
  | TDOLLAR dotted_ident bitop
    { $$ = new PacketExprNode(IdentExprNode::Ptr($2)); $$->bitop_ = BitopExprNode::Ptr($3);
      $$->flags_[ExprNode::IS_PKT] = true;
      parser.set_loc($$, @$); }
  | TGOTO scoped_ident
    { $$ = new GotoExprNode(IdentExprNode::Ptr($2), false);
      parser.set_loc($$, @$); }
  | TNEXT scoped_ident
    { $$ = new GotoExprNode(IdentExprNode::Ptr($2), false);
      parser.set_loc($$, @$); }
  | TCONTINUE scoped_ident
    { $$ = new GotoExprNode(IdentExprNode::Ptr($2), true);
      parser.set_loc($$, @$); }
  | TLPAREN expr TRPAREN
    { $$ = $2; }
  | TLPAREN expr TRPAREN bitop
    { $$ = $2; $$->bitop_ = BitopExprNode::Ptr($4); }
  | TSTRING
    { $$ = new StringExprNode($1);
      parser.set_loc($$, @$); }
  | numeric
    { $$ = $1; }
  | numeric bitop
    { $$ = $1; $$->bitop_ = BitopExprNode::Ptr($2); }
  | expr TCLT expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | expr TCGT expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | expr TCGE expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | expr TCLE expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | expr TCNE expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | expr TCEQ expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | expr TPLUS expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | expr TMINUS expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | expr TMUL expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | expr TDIV expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | expr TMOD expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | expr TXOR expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | expr TAND expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | expr TOR expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | expr TLAND expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  | expr TLOR expr
    { $$ = new BinopExprNode(ExprNode::Ptr($1), $2, ExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  /*| expr bitop
    { $$ = $1; $$->bitop_ = BitopExprNode::Ptr($2); }*/
  | TNOT expr
    { $$ = new UnopExprNode($1, ExprNode::Ptr($2));
      parser.set_loc($$, @$); }
  | TCMPL expr
    { $$ = new UnopExprNode($1, ExprNode::Ptr($2));
      parser.set_loc($$, @$); }
  ;

call_args
  : /* empty */
    { $$ = new ExprNodeList; }
  | expr
    { $$ = new ExprNodeList; $$->push_back(ExprNode::Ptr($1)); }
  | call_args TCOMMA expr
    { $$->push_back(ExprNode::Ptr($3)); }
  ;

bitop
  : TLBRACK TCOLON TPLUS TINTEGER TRBRACK
    { $$ = new BitopExprNode(string("0"), *$4); delete $4;
      parser.set_loc($$, @$); }
  | TLBRACK TINTEGER TCOLON TPLUS TINTEGER TRBRACK
    { $$ = new BitopExprNode(*$2, *$5); delete $2; delete $5;
      parser.set_loc($$, @$); }
  ;

table_index_expr
  : dotted_ident TLBRACK ident TRBRACK
    { $$ = new TableIndexExprNode(IdentExprNode::Ptr($1), IdentExprNode::Ptr($3));
      parser.set_loc($$, @$); }
  ;

scoped_ident
  : ident
    { $$ = $1; }
  | scoped_ident TSCOPE TIDENTIFIER
    { $$->append_scope(*$3); delete $3; }
  ;

dotted_ident
  : ident
    { $$ = $1; }
  | dotted_ident TDOT TIDENTIFIER
    { $$->append_dot(*$3); delete $3; }
  ;

any_ident
  : ident
    { $$ = $1; }
  | dotted_ident TARROW TIDENTIFIER
    { $$->append_dot(*$3); delete $3; }
  | dotted_ident TDOT TIDENTIFIER
    { $$->append_dot(*$3); delete $3; }
  | scoped_ident TSCOPE TIDENTIFIER
    { $$->append_scope(*$3); delete $3; }
  ;

ident
  : TIDENTIFIER
    { $$ = new IdentExprNode(*$1); delete $1;
      parser.set_loc($$, @$); }
  ;

%%

void ebpf::cc::BisonParser::error(const ebpf::cc::BisonParser::location_type &loc,
                            const string& msg) {
    std::cerr << "Error: " << loc << " " << msg << std::endl;
}

#include "lexer.h"
static int yylex(ebpf::cc::BisonParser::semantic_type *yylval,
                 ebpf::cc::BisonParser::location_type *yylloc,
                 ebpf::cc::Lexer &lexer) {
    return lexer.yylex(yylval, yylloc);
}

