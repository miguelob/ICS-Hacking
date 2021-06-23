/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     PT_QUOTE = 258,
     PT_LPAREN = 259,
     PT_RPAREN = 260,
     PT_LBRACKET = 261,
     PT_RBRACKET = 262,
     PT_LCURLY = 263,
     PT_RCURLY = 264,
     PT_EQUAL = 265,
     PT_NOTEQUAL = 266,
     PT_NOTEQUAL2 = 267,
     PT_GEQUAL = 268,
     PT_LEQUAL = 269,
     PT_ASSIGN_PLUS = 270,
     PT_ASSIGN = 271,
     PT_PLUS = 272,
     PT_MINUS = 273,
     PT_MULTIPLY = 274,
     PT_DIV = 275,
     PT_LOGIC_OR = 276,
     PT_OR = 277,
     PT_LOGIC_AND = 278,
     PT_AND = 279,
     PT_NOT = 280,
     PT_NEG = 281,
     PT_XOR = 282,
     PT_SHL = 283,
     PT_SHR = 284,
     PT_PERCENT = 285,
     PT_DOLLAR = 286,
     PT_COND = 287,
     PT_SEMICOLON = 288,
     PT_DOT = 289,
     PT_COMMA = 290,
     PT_COLON = 291,
     PT_LESS = 292,
     PT_GREATER = 293,
     PT_OPTIONAL = 294,
     PT_REQUIRED = 295,
     PT_OPTION = 296,
     PT_PACKAGE = 297,
     PT_PUBLIC = 298,
     PT_WEAK = 299,
     PT_IMPORT = 300,
     PT_SYNTAX = 301,
     PT_EXTENSIONS = 302,
     PT_EXTEND = 303,
     PT_GROUP = 304,
     PT_ENUM = 305,
     PT_RESERVED = 306,
     PT_MAP = 307,
     PT_ONEOF = 308,
     PT_REPEATED = 309,
     PT_STRLIT = 310,
     PT_IDENT = 311,
     PT_PROTO3 = 312,
     PT_PROTO2 = 313,
     PT_TO = 314,
     PT_RETURNS = 315,
     PT_STREAM = 316,
     PT_RPC = 317,
     PT_SERVICE = 318,
     PT_MESSAGE = 319,
     PT_DECIMALLIT = 320,
     PT_OCTALLIT = 321,
     PT_HEXLIT = 322
   };
#endif
/* Tokens.  */
#define PT_QUOTE 258
#define PT_LPAREN 259
#define PT_RPAREN 260
#define PT_LBRACKET 261
#define PT_RBRACKET 262
#define PT_LCURLY 263
#define PT_RCURLY 264
#define PT_EQUAL 265
#define PT_NOTEQUAL 266
#define PT_NOTEQUAL2 267
#define PT_GEQUAL 268
#define PT_LEQUAL 269
#define PT_ASSIGN_PLUS 270
#define PT_ASSIGN 271
#define PT_PLUS 272
#define PT_MINUS 273
#define PT_MULTIPLY 274
#define PT_DIV 275
#define PT_LOGIC_OR 276
#define PT_OR 277
#define PT_LOGIC_AND 278
#define PT_AND 279
#define PT_NOT 280
#define PT_NEG 281
#define PT_XOR 282
#define PT_SHL 283
#define PT_SHR 284
#define PT_PERCENT 285
#define PT_DOLLAR 286
#define PT_COND 287
#define PT_SEMICOLON 288
#define PT_DOT 289
#define PT_COMMA 290
#define PT_COLON 291
#define PT_LESS 292
#define PT_GREATER 293
#define PT_OPTIONAL 294
#define PT_REQUIRED 295
#define PT_OPTION 296
#define PT_PACKAGE 297
#define PT_PUBLIC 298
#define PT_WEAK 299
#define PT_IMPORT 300
#define PT_SYNTAX 301
#define PT_EXTENSIONS 302
#define PT_EXTEND 303
#define PT_GROUP 304
#define PT_ENUM 305
#define PT_RESERVED 306
#define PT_MAP 307
#define PT_ONEOF 308
#define PT_REPEATED 309
#define PT_STRLIT 310
#define PT_IDENT 311
#define PT_PROTO3 312
#define PT_PROTO2 313
#define PT_TO 314
#define PT_RETURNS 315
#define PT_STREAM 316
#define PT_RPC 317
#define PT_SERVICE 318
#define PT_MESSAGE 319
#define PT_DECIMALLIT 320
#define PT_OCTALLIT 321
#define PT_HEXLIT 322




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 91 "/Users/miguel/Downloads/make/epan/protobuf_lang.y"
{
    char* sval;
    pbl_node_t* node;
    int ival;
    guint64 u64val;
}
/* Line 1529 of yacc.c.  */
#line 190 "/Users/miguel/Downloads/make/epan/protobuf_lang.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



