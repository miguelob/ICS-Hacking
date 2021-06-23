/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C

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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.3"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Using locations.  */
#define YYLSP_NEEDED 0

/* Substitute the variable and function names.  */
#define yyparse ascendparse
#define yylex   ascendlex
#define yyerror ascenderror
#define yylval  ascendlval
#define yychar  ascendchar
#define yydebug ascenddebug
#define yynerrs ascendnerrs


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     STRING = 258,
     KEYWORD = 259,
     WDD_DATE = 260,
     WDD_CHUNK = 261,
     COUNTER = 262,
     SLASH_SUFFIX = 263,
     WDS_PREFIX = 264,
     ISDN_PREFIX = 265,
     ETHER_PREFIX = 266,
     DECNUM = 267,
     HEXNUM = 268,
     HEXBYTE = 269
   };
#endif
/* Tokens.  */
#define STRING 258
#define KEYWORD 259
#define WDD_DATE 260
#define WDD_CHUNK 261
#define COUNTER 262
#define SLASH_SUFFIX 263
#define WDS_PREFIX 264
#define ISDN_PREFIX 265
#define ETHER_PREFIX 266
#define DECNUM 267
#define HEXNUM 268
#define HEXBYTE 269




/* Copy the first part of user declarations.  */
#line 30 "/Users/miguel/Downloads/make/wiretap/ascend.y"

/* ascend.y
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
    Example 'pridisp' output data - one paragraph/frame:

PRI-XMIT-27: (task "l1Task" at 0x10216fe0, time: 560194.01) 4 octets @ 0x1027c5b0
  [0000]: 00 01 01 a9                                         ....
PRI-RCV-27: (task "idle task" at 0x10123570, time: 560194.01) 4 octets @ 0x1027fb00
  [0000]: 00 01 01 dd

    Example 'pridisp' output data - two paragraphs/frame for XMIT case only:

PRI-XMIT-19/1:  (task "l1Task" at 0x10216840, time: 274759.98) 4 octets @ 0x1027f230
  [0000]: 00 01 30 d8                                         ..0.
PRI-XMIT-19/2 (task "l1Task" at 0x10216840, time: 274759.98) 11 octets @ 0x1027f234
  [0000]: 08 02 8c bf 02 18 04 e9  82 83 8f                   ........ ...

    Example 'ether-disp' output data:

ETHER3ND RECV: (task "_sarTask" at 0x802c6eb0, time: 259848.03) 775 octets @ 0xa8fb2020
  [0000]: 00 d0 52 04 e7 1e 08 00  20 ae 51 b5 08 00 45 00    ..R..... .Q...E.
  [0010]: 02 f9 05 e6 40 00 3f 11  6e 39 87 fe c4 95 3c 3c    ....@.?.  n9....<<
  [0020]: 3c 05 13 c4 13 c4 02 e5  ef ed 49 4e 56 49 54 45    <.......  ..INVITE
  [0030]: 20 73 69 70 3a 35 32 30  37 33 40 36 30 2e 36 30     sip:520 73@60.60
  [0040]: 2e 36 30 2e 35 20 53 49  50 2f 32 2e 30 0d 0a 56    .60.5 SI P/2.0..V
  [0050]: 69 61 3a 20 53 49 50 2f  32 2e 30 2f 55 44 50 20    ia: SIP/ 2.0/UDP
  [0060]: 31 33 35 2e                                         135.

    Example 'wandsess' output data:

RECV-iguana:241:(task: B02614C0, time: 1975432.85) 49 octets @ 8003BD94
  [0000]: FF 03 00 3D C0 06 CA 22 2F 45 00 00 28 6A 3B 40
  [0010]: 00 3F 03 D7 37 CE 41 62 12 CF 00 FB 08 20 27 00
  [0020]: 50 E4 08 DD D7 7C 4C 71 92 50 10 7D 78 67 C8 00
  [0030]: 00
XMIT-iguana:241:(task: B04E12C0, time: 1975432.85) 53 octets @ 8009EB16
  [0000]: FF 03 00 3D C0 09 1E 31 21 45 00 00 2C 2D BD 40
  [0010]: 00 7A 06 D8 B1 CF 00 FB 08 CE 41 62 12 00 50 20
  [0020]: 29 7C 4C 71 9C 9A 6A 93 A4 60 12 22 38 3F 10 00
  [0030]: 00 02 04 05 B4

    Example 'wdd' output data:

Date: 01/12/1990.  Time: 12:22:33
Cause an attempt to place call to 14082750382
WD_DIALOUT_DISP: chunk 2515EE type IP.
(task: 251790, time: 994953.28) 44 octets @ 2782B8
  [0000]: 00 C0 7B 71 45 6C 00 60 08 16 AA 51 08 00 45 00
  [0010]: 00 2C 66 1C 40 00 80 06 53 F6 AC 14 00 18 CC 47
  [0020]: C8 45 0A 31 00 50 3B D9 5B 75 00 00

    The following output comes from a MAX with Software 7.2.3:

RECV-187:(task: B050B480, time: 18042248.03) 100 octets @ 800012C0
  [0000]: FF 03 00 21 45 00 00 60 E3 49 00 00 7F 11 FD 7B
  [0010]: C0 A8 F7 05 8A C8 18 51 00 89 00 89 00 4C C7 C1
  [0020]: CC 8E 40 00 00 01 00 00 00 00 00 01 20 45 4A 45
  [0030]: 42 45 43 45 48 43 4E 46 43 46 41 43 41 43 41 43
  [0040]: 41 43 41 43 41 43 41 43 41 43 41 42 4E 00 00 20
  [0050]: 00 01 C0 0C 00 20 00 01 00 04 93 E0 00 06 60 00
  [0060]: C0 A8 F7 05
XMIT-187:(task: B0292CA0, time: 18042248.04) 60 octets @ 800AD576
  [0000]: FF 03 00 21 45 00 00 38 D7 EE 00 00 0F 01 11 2B
  [0010]: 0A FF FF FE C0 A8 F7 05 03 0D 33 D3 00 00 00 00
  [0020]: 45 00 00 60 E3 49 00 00 7E 11 FE 7B C0 A8 F7 05
  [0030]: 8A C8 18 51 00 89 00 89 00 4C C7 C1
RECV-187:(task: B0292CA0, time: 18042251.92) 16 octets @ 800018E8
  [0000]: FF 03 C0 21 09 01 00 0C DE 61 96 4B 00 30 94 92

  In TAOS 8.0, Lucent slightly changed the format as follows:

    Example 'wandisp' output data (TAOS 8.0.3): (same format is used
    for 'wanopen' and 'wannext' command)

RECV-14: (task "idle task" at 0xb05e6e00, time: 1279.01) 29 octets @ 0x8000e0fc
  [0000]: ff 03 c0 21 01 01 00 19  01 04 05 f4 11 04 05 f4    ...!.... ........
  [0010]: 13 09 03 00 c0 7b 9a 9f  2d 17 04 10 00             .....{.. -....
XMIT-14: (task "idle task" at 0xb05e6e00, time: 1279.02) 38 octets @ 0x8007fd56
  [0000]: ff 03 c0 21 01 01 00 22  00 04 00 00 01 04 05 f4    ...!..." ........
  [0010]: 03 05 c2 23 05 11 04 05  f4 13 09 03 00 c0 7b 80    ...#.... ......{.
  [0020]: 7c ef 17 04 0e 00                                   |.....
XMIT-14: (task "idle task" at 0xb05e6e00, time: 1279.02) 29 octets @ 0x8007fa36
  [0000]: ff 03 c0 21 02 01 00 19  01 04 05 f4 11 04 05 f4    ...!.... ........
  [0010]: 13 09 03 00 c0 7b 9a 9f  2d 17 04 10 00             .....{.. -....

    Example 'wandsess' output data (TAOS 8.0.3):

RECV-Max7:20: (task "_brouterControlTask" at 0xb094ac20, time: 1481.50) 20 octets @ 0x8000d198
  [0000]: ff 03 00 3d c0 00 00 04  80 fd 02 01 00 0a 11 06    ...=.... ........
  [0010]: 00 01 01 03                                         ....
XMIT-Max7:20: (task "_brouterControlTask" at 0xb094ac20, time: 1481.51) 26 octets @ 0x800806b6
  [0000]: ff 03 00 3d c0 00 00 00  80 21 01 01 00 10 02 06    ...=.... .!......
  [0010]: 00 2d 0f 01 03 06 89 64  03 08                      .-.....d ..
XMIT-Max7:20: (task "_brouterControlTask" at 0xb094ac20, time: 1481.51) 20 octets @ 0x8007f716
  [0000]: ff 03 00 3d c0 00 00 01  80 fd 01 01 00 0a 11 06    ...=.... ........
  [0010]: 00 01 01 03                                         ....

  The changes since TAOS 7.X are:

    1) White space is added before "(task".
    2) Task has a name, indicated by a subsequent string surrounded by a
       double-quote.
    3) Address expressed in hex number has a preceding "0x".
    4) Hex numbers are in lower case.
    5) There is a character display corresponding to hex data in each line.

 */

#include "config.h"

#if defined(_MSC_VER) && !defined(__STDC_VERSION__)
  /*
   * MSVC doesn't, by default, define __STDC_VERSION__, which
   * means that the code generated by newer versions of winflexbison3's
   * Bison end up defining YYPTRDIFF_T as long, which is wrong on
   * 64-bit Windows, as that's an LLP64 platform, not an LP64 platform,
   * and causes warnings to be generated.  Those warnings turn into
   * errors.
   *
   * With MSVC, if __STDC_VERSION__ isn't defined, Forcibly include
   * <stdint.h> here to work around that.
   */
  #include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "wtap-int.h"
#include <wsutil/buffer.h>
#include "ascendtext.h"
#include "ascend-int.h"
DIAG_OFF_BYACC
#include "ascend.h"
#include "ascend_scanner_lex.h"
DIAG_ON_BYACC
#include "file_wrappers.h"

#define NO_USER "<none>"

extern void yyerror (void *yyscanner, ascend_state_t *state, FILE_T fh _U_, const char *s);

DIAG_OFF_BYACC


/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif

#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 181 "/Users/miguel/Downloads/make/wiretap/ascend.y"
{
gchar  *s;
guint32 d;
guint8  b;
}
/* Line 193 of yacc.c.  */
#line 289 "/Users/miguel/Downloads/make/wiretap/ascend.c"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 216 of yacc.c.  */
#line 302 "/Users/miguel/Downloads/make/wiretap/ascend.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int i)
#else
static int
YYID (i)
    int i;
#endif
{
  return i;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  23
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   141

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  15
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  21
/* YYNRULES -- Number of rules.  */
#define YYNRULES  52
/* YYNRULES -- Number of states.  */
#define YYNSTATES  153

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   269

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,     7,    12,    15,    18,    21,    24,
      27,    31,    34,    36,    38,    40,    42,    44,    46,    60,
      73,    86,    98,   112,   123,   136,   147,   159,   161,   163,
     166,   170,   175,   181,   188,   196,   205,   215,   226,   238,
     251,   265,   280,   296,   313,   316,   318,   321,   325,   330,
     336,   343,   351
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      16,     0,    -1,    -1,    25,    35,    -1,    23,    35,    23,
      35,    -1,    24,    35,    -1,    26,    35,    -1,    27,    35,
      -1,    28,    35,    -1,    29,    35,    -1,    30,    31,    35,
      -1,    31,    35,    -1,    10,    -1,    11,    -1,     9,    -1,
       3,    -1,    12,    -1,    13,    -1,    17,    21,     8,     4,
      20,     4,    22,     4,    21,    21,    21,     4,    13,    -1,
      17,    21,     4,    20,     4,    22,     4,    21,    21,    21,
       4,    13,    -1,    18,    20,     4,    20,     4,    22,     4,
      21,    21,    21,     4,    13,    -1,    19,    20,    21,     4,
      22,     4,    21,    21,    21,     4,    13,    -1,    19,    20,
      21,     4,    20,     4,    22,     4,    21,    21,    21,     4,
      13,    -1,    19,    21,     4,    22,     4,    21,    21,    21,
       4,    13,    -1,    19,    21,     4,    20,     4,    22,     4,
      21,    21,    21,     4,    13,    -1,     5,    21,    21,    21,
       4,    21,    21,    21,     4,    20,    -1,     6,    22,     4,
       4,    22,     4,    21,    21,    21,     4,    13,    -1,    14,
      -1,    32,    -1,    32,    32,    -1,    32,    32,    32,    -1,
      32,    32,    32,    32,    -1,    32,    32,    32,    32,    32,
      -1,    32,    32,    32,    32,    32,    32,    -1,    32,    32,
      32,    32,    32,    32,    32,    -1,    32,    32,    32,    32,
      32,    32,    32,    32,    -1,    32,    32,    32,    32,    32,
      32,    32,    32,    32,    -1,    32,    32,    32,    32,    32,
      32,    32,    32,    32,    32,    -1,    32,    32,    32,    32,
      32,    32,    32,    32,    32,    32,    32,    -1,    32,    32,
      32,    32,    32,    32,    32,    32,    32,    32,    32,    32,
      -1,    32,    32,    32,    32,    32,    32,    32,    32,    32,
      32,    32,    32,    32,    -1,    32,    32,    32,    32,    32,
      32,    32,    32,    32,    32,    32,    32,    32,    32,    -1,
      32,    32,    32,    32,    32,    32,    32,    32,    32,    32,
      32,    32,    32,    32,    32,    -1,    32,    32,    32,    32,
      32,    32,    32,    32,    32,    32,    32,    32,    32,    32,
      32,    32,    -1,     7,    33,    -1,    34,    -1,    34,    34,
      -1,    34,    34,    34,    -1,    34,    34,    34,    34,    -1,
      34,    34,    34,    34,    34,    -1,    34,    34,    34,    34,
      34,    34,    -1,    34,    34,    34,    34,    34,    34,    34,
      -1,    34,    34,    34,    34,    34,    34,    34,    34,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   199,   199,   200,   201,   202,   203,   204,   205,   206,
     207,   208,   211,   213,   215,   217,   219,   221,   235,   256,
     275,   291,   308,   325,   342,   362,   387,   402,   422,   423,
     424,   425,   426,   427,   428,   429,   430,   431,   432,   433,
     434,   435,   436,   437,   440,   442,   443,   444,   445,   446,
     447,   448,   449
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "STRING", "KEYWORD", "WDD_DATE",
  "WDD_CHUNK", "COUNTER", "SLASH_SUFFIX", "WDS_PREFIX", "ISDN_PREFIX",
  "ETHER_PREFIX", "DECNUM", "HEXNUM", "HEXBYTE", "$accept", "data_packet",
  "isdn_prefix", "ether_prefix", "wds_prefix", "string", "decnum",
  "hexnum", "deferred_isdn_hdr", "isdn_hdr", "ether_hdr", "wds_hdr",
  "wds8_hdr", "wdp7_hdr", "wdp8_hdr", "wdd_date", "wdd_hdr", "byte",
  "bytegroup", "dataln", "datagroup", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    15,    16,    16,    16,    16,    16,    16,    16,    16,
      16,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    33,
      33,    33,    33,    33,    33,    33,    33,    33,    33,    33,
      33,    33,    33,    33,    34,    35,    35,    35,    35,    35,
      35,    35,    35
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     4,     2,     2,     2,     2,     2,
       3,     2,     1,     1,     1,     1,     1,     1,    13,    12,
      12,    11,    13,    10,    12,    10,    11,     1,     1,     2,
       3,     4,     5,     6,     7,     8,     9,    10,    11,    12,
      13,    14,    15,    16,     2,     1,     2,     3,     4,     5,
       6,     7,     8
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     0,    14,    12,    13,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    16,
       0,    17,     0,     1,     0,    15,     0,     0,     0,     0,
      45,     0,     5,     3,     6,     7,     8,     9,     0,    11,
       0,     0,     0,     0,     0,     0,     0,    27,    28,    44,
      46,     0,     0,    10,     0,     0,     0,     0,     0,     0,
       0,     0,    29,    47,     0,     4,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    30,    48,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    31,    49,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    32,    50,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    33,    51,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    34,
      52,    25,     0,     0,     0,     0,     0,     0,     0,    23,
      35,    26,     0,     0,     0,     0,    21,     0,    36,    19,
       0,    20,     0,    24,    37,    18,    22,    38,    39,    40,
      41,    42,    43
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
      -1,     6,     7,     8,     9,    26,    20,    22,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    48,    49,    30,
      31
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -18
static const yytype_int8 yypact[] =
{
      18,   -11,    -9,   -18,   -18,   -18,     6,   -11,    14,    13,
      11,    11,    11,    11,    11,    11,    11,    15,    11,   -18,
     -11,   -18,    22,   -18,    33,   -18,    28,   -11,    31,     5,
      11,    36,   -18,   -18,   -18,   -18,   -18,   -18,    11,   -18,
     -11,    43,    14,    45,    14,    46,     2,   -18,     5,   -18,
      11,   -11,    11,   -18,    52,    -9,    56,    14,    57,     2,
      58,    59,     5,    11,    64,   -18,   -11,    61,    -9,    69,
      -9,    70,    71,    -9,   -11,     5,    11,   -11,   -11,    73,
      -9,    80,    -9,   -11,    82,   -11,     5,    11,   -11,   -11,
     -11,    88,   -11,    96,   -11,   -11,   -11,     5,    11,    99,
     -11,   -11,   -11,   -11,   -11,   -11,   -11,   105,     5,    11,
      14,   107,   -11,   -11,   -11,   -11,   108,   -11,   101,     5,
     -18,   -18,   102,   112,   -11,   114,   -11,   109,   116,   -18,
       5,   -18,   110,   120,   113,   121,   -18,   115,     5,   -18,
     122,   -18,   123,   -18,     5,   -18,   -18,     5,     5,     5,
       5,     5,   -18
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -18,   -18,    98,   -18,   -18,    -6,    -7,   -16,   106,   -18,
     -18,   -18,   -18,   -18,   -18,   -18,   124,   -17,   -18,    -8,
      -4
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const yytype_uint8 yytable[] =
{
      24,    19,    28,    27,    21,    25,    23,    32,    33,    34,
      35,    36,    37,    40,    39,    21,    25,    25,    29,    47,
      45,     2,    50,     1,     2,    19,    41,     3,     4,     5,
      61,    62,    44,    54,    53,    46,    56,    42,    58,    67,
      60,    43,    63,    72,    64,    75,     4,    55,    65,    57,
      59,    69,    79,    71,    81,    76,    66,    84,    86,    77,
      68,    70,    73,    74,    91,    78,    93,    85,    87,    97,
      88,    89,    43,    80,    82,    83,    94,    90,    96,    98,
     108,    99,   100,   101,    92,   103,    95,   105,   106,   107,
     109,   119,   102,   111,   112,   113,   114,   115,   116,   117,
     104,   120,   130,   110,   121,   123,   124,   125,   126,   118,
     128,   122,   127,   138,   129,   131,   132,   133,   134,   135,
     137,   144,   136,   139,   140,   142,   141,   147,   143,    51,
     148,   149,   150,   151,   152,   145,   146,    52,     0,     0,
       0,    38
};

static const yytype_int16 yycheck[] =
{
       7,    12,     9,     9,    13,     3,     0,    11,    12,    13,
      14,    15,    16,    20,    18,    13,     3,     3,     7,    14,
      27,     6,    30,     5,     6,    12,     4,     9,    10,    11,
      46,    48,     4,    40,    38,     4,    42,     4,    44,    55,
      46,     8,    50,    59,    51,    62,    10,     4,    52,     4,
       4,    57,    68,    59,    70,    63,     4,    73,    75,    66,
       4,     4,     4,     4,    80,     4,    82,    74,    76,    86,
      77,    78,     8,     4,     4,     4,    83,     4,    85,    87,
      97,    88,    89,    90,     4,    92,     4,    94,    95,    96,
      98,   108,     4,   100,   101,   102,   103,   104,   105,   106,
       4,   109,   119,     4,   110,   112,   113,   114,   115,     4,
     117,     4,     4,   130,    13,    13,     4,   124,     4,   126,
       4,   138,    13,    13,     4,     4,    13,   144,    13,    31,
     147,   148,   149,   150,   151,    13,    13,    31,    -1,    -1,
      -1,    17
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,     5,     6,     9,    10,    11,    16,    17,    18,    19,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    12,
      21,    13,    22,     0,    21,     3,    20,    20,    21,     7,
      34,    35,    35,    35,    35,    35,    35,    35,    31,    35,
      21,     4,     4,     8,     4,    21,     4,    14,    32,    33,
      34,    17,    23,    35,    21,     4,    20,     4,    20,     4,
      20,    22,    32,    34,    21,    35,     4,    22,     4,    20,
       4,    20,    22,     4,     4,    32,    34,    21,     4,    22,
       4,    22,     4,     4,    22,    21,    32,    34,    21,    21,
       4,    22,     4,    22,    21,     4,    21,    32,    34,    21,
      21,    21,     4,    21,     4,    21,    21,    21,    32,    34,
       4,    21,    21,    21,    21,    21,    21,    21,     4,    32,
      34,    20,     4,    21,    21,    21,    21,     4,    21,    13,
      32,    13,     4,    21,     4,    21,    13,     4,    32,    13,
       4,    13,     4,    13,    32,    13,    13,    32,    32,    32,
      32,    32,    32
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (yyscanner, parser_state, fh, YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (&yylval, YYLEX_PARAM)
#else
# define YYLEX yylex (&yylval, yyscanner)
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value, yyscanner, parser_state, fh); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *yyscanner, ascend_state_t *parser_state, FILE_T fh)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep, yyscanner, parser_state, fh)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    void *yyscanner;
    ascend_state_t *parser_state;
    FILE_T fh;
#endif
{
  if (!yyvaluep)
    return;
  YYUSE (yyscanner);
  YYUSE (parser_state);
  YYUSE (fh);
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *yyscanner, ascend_state_t *parser_state, FILE_T fh)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep, yyscanner, parser_state, fh)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    void *yyscanner;
    ascend_state_t *parser_state;
    FILE_T fh;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep, yyscanner, parser_state, fh);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *bottom, yytype_int16 *top)
#else
static void
yy_stack_print (bottom, top)
    yytype_int16 *bottom;
    yytype_int16 *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule, void *yyscanner, ascend_state_t *parser_state, FILE_T fh)
#else
static void
yy_reduce_print (yyvsp, yyrule, yyscanner, parser_state, fh)
    YYSTYPE *yyvsp;
    int yyrule;
    void *yyscanner;
    ascend_state_t *parser_state;
    FILE_T fh;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      fprintf (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       , yyscanner, parser_state, fh);
      fprintf (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule, yyscanner, parser_state, fh); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, void *yyscanner, ascend_state_t *parser_state, FILE_T fh)
#else
static void
yydestruct (yymsg, yytype, yyvaluep, yyscanner, parser_state, fh)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
    void *yyscanner;
    ascend_state_t *parser_state;
    FILE_T fh;
#endif
{
  YYUSE (yyvaluep);
  YYUSE (yyscanner);
  YYUSE (parser_state);
  YYUSE (fh);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
	break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (void *yyscanner, ascend_state_t *parser_state, FILE_T fh);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */






/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *yyscanner, ascend_state_t *parser_state, FILE_T fh)
#else
int
yyparse (yyscanner, parser_state, fh)
    void *yyscanner;
    ascend_state_t *parser_state;
    FILE_T fh;
#endif
#endif
{
  /* The look-ahead symbol.  */
int yychar;

/* The semantic value of the look-ahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;

  int yystate;
  int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Look-ahead token as an internal (translated) token number.  */
  int yytoken = 0;
#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  yytype_int16 yyssa[YYINITDEPTH];
  yytype_int16 *yyss = yyssa;
  yytype_int16 *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  YYSTYPE *yyvsp;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;


      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     look-ahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to look-ahead token.  */
  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a look-ahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid look-ahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the look-ahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 18:
#line 235 "/Users/miguel/Downloads/make/wiretap/ascend.y"
    {
  parser_state->wirelen += (yyvsp[(11) - (13)].d);
  parser_state->secs = (yyvsp[(9) - (13)].d);
  parser_state->usecs = (yyvsp[(10) - (13)].d);
  if (parser_state->pseudo_header != NULL) {
    parser_state->pseudo_header->type = (yyvsp[(1) - (13)].d);
    parser_state->pseudo_header->sess = (yyvsp[(2) - (13)].d);
    parser_state->pseudo_header->call_num[0] = '\0';
    parser_state->pseudo_header->chunk = 0;
    parser_state->pseudo_header->task = (yyvsp[(7) - (13)].d);
  }
  /* because we have two data groups */
  parser_state->first_hexbyte = 0;
;}
    break;

  case 19:
#line 256 "/Users/miguel/Downloads/make/wiretap/ascend.y"
    {
  parser_state->wirelen = (yyvsp[(10) - (12)].d);
  parser_state->secs = (yyvsp[(8) - (12)].d);
  parser_state->usecs = (yyvsp[(9) - (12)].d);
  if (parser_state->pseudo_header != NULL) {
    parser_state->pseudo_header->type = (yyvsp[(1) - (12)].d);
    parser_state->pseudo_header->sess = (yyvsp[(2) - (12)].d);
    parser_state->pseudo_header->call_num[0] = '\0';
    parser_state->pseudo_header->chunk = 0;
    parser_state->pseudo_header->task = (yyvsp[(6) - (12)].d);
  }
  parser_state->first_hexbyte = 0;
;}
    break;

  case 20:
#line 276 "/Users/miguel/Downloads/make/wiretap/ascend.y"
    {
  parser_state->wirelen = (yyvsp[(10) - (12)].d);
  parser_state->secs = (yyvsp[(8) - (12)].d);
  parser_state->usecs = (yyvsp[(9) - (12)].d);
  if (parser_state->pseudo_header != NULL) {
    parser_state->pseudo_header->type = (yyvsp[(1) - (12)].d);
    parser_state->pseudo_header->call_num[0] = '\0';
    parser_state->pseudo_header->chunk = 0;
    parser_state->pseudo_header->task = (yyvsp[(6) - (12)].d);
  }
;}
    break;

  case 21:
#line 291 "/Users/miguel/Downloads/make/wiretap/ascend.y"
    {
  parser_state->wirelen = (yyvsp[(9) - (11)].d);
  parser_state->secs = (yyvsp[(7) - (11)].d);
  parser_state->usecs = (yyvsp[(8) - (11)].d);
  if (parser_state->pseudo_header != NULL) {
    /* parser_state->pseudo_header->user is set in ascend_scanner.l */
    parser_state->pseudo_header->type = (yyvsp[(1) - (11)].d);
    parser_state->pseudo_header->sess = (yyvsp[(3) - (11)].d);
    parser_state->pseudo_header->call_num[0] = '\0';
    parser_state->pseudo_header->chunk = 0;
    parser_state->pseudo_header->task = (yyvsp[(5) - (11)].d);
  }
;}
    break;

  case 22:
#line 308 "/Users/miguel/Downloads/make/wiretap/ascend.y"
    {
  parser_state->wirelen = (yyvsp[(11) - (13)].d);
  parser_state->secs = (yyvsp[(9) - (13)].d);
  parser_state->usecs = (yyvsp[(10) - (13)].d);
  if (parser_state->pseudo_header != NULL) {
    /* parser_state->pseudo_header->user is set in ascend_scanner.l */
    parser_state->pseudo_header->type = (yyvsp[(1) - (13)].d);
    parser_state->pseudo_header->sess = (yyvsp[(3) - (13)].d);
    parser_state->pseudo_header->call_num[0] = '\0';
    parser_state->pseudo_header->chunk = 0;
    parser_state->pseudo_header->task = (yyvsp[(7) - (13)].d);
  }
;}
    break;

  case 23:
#line 325 "/Users/miguel/Downloads/make/wiretap/ascend.y"
    {
  parser_state->wirelen = (yyvsp[(8) - (10)].d);
  parser_state->secs = (yyvsp[(6) - (10)].d);
  parser_state->usecs = (yyvsp[(7) - (10)].d);
  if (parser_state->pseudo_header != NULL) {
    /* parser_state->pseudo_header->user is set in ascend_scanner.l */
    parser_state->pseudo_header->type = (yyvsp[(1) - (10)].d);
    parser_state->pseudo_header->sess = (yyvsp[(2) - (10)].d);
    parser_state->pseudo_header->call_num[0] = '\0';
    parser_state->pseudo_header->chunk = 0;
    parser_state->pseudo_header->task = (yyvsp[(4) - (10)].d);
  }
;}
    break;

  case 24:
#line 342 "/Users/miguel/Downloads/make/wiretap/ascend.y"
    {
  parser_state->wirelen = (yyvsp[(10) - (12)].d);
  parser_state->secs = (yyvsp[(8) - (12)].d);
  parser_state->usecs = (yyvsp[(9) - (12)].d);
  if (parser_state->pseudo_header != NULL) {
    /* parser_state->pseudo_header->user is set in ascend_scanner.l */
    parser_state->pseudo_header->type = (yyvsp[(1) - (12)].d);
    parser_state->pseudo_header->sess = (yyvsp[(2) - (12)].d);
    parser_state->pseudo_header->call_num[0] = '\0';
    parser_state->pseudo_header->chunk = 0;
    parser_state->pseudo_header->task = (yyvsp[(6) - (12)].d);
  }
;}
    break;

  case 25:
#line 362 "/Users/miguel/Downloads/make/wiretap/ascend.y"
    {
  /*
   * Supply the date/time value to the code above us; it will use the
   * first date/time value supplied as the capture start date/time.
   */
  struct tm wddt;

  wddt.tm_sec  = (yyvsp[(8) - (10)].d);
  wddt.tm_min  = (yyvsp[(7) - (10)].d);
  wddt.tm_hour = (yyvsp[(6) - (10)].d);
  wddt.tm_mday = (yyvsp[(3) - (10)].d);
  wddt.tm_mon  = (yyvsp[(2) - (10)].d) - 1;
  wddt.tm_year = ((yyvsp[(4) - (10)].d) > 1970) ? (yyvsp[(4) - (10)].d) - 1900 : 70;
  wddt.tm_isdst = -1;

  parser_state->timestamp = (guint32) mktime(&wddt);
  parser_state->saw_timestamp = TRUE;
;}
    break;

  case 26:
#line 387 "/Users/miguel/Downloads/make/wiretap/ascend.y"
    {
  parser_state->wirelen = (yyvsp[(9) - (11)].d);
  parser_state->secs = (yyvsp[(7) - (11)].d);
  parser_state->usecs = (yyvsp[(8) - (11)].d);
  if (parser_state->pseudo_header != NULL) {
    /* parser_state->pseudo_header->call_num is set in ascend_scanner.l */
    parser_state->pseudo_header->type = ASCEND_PFX_WDD;
    parser_state->pseudo_header->user[0] = '\0';
    parser_state->pseudo_header->sess = 0;
    parser_state->pseudo_header->chunk = (yyvsp[(2) - (11)].d);
    parser_state->pseudo_header->task = (yyvsp[(5) - (11)].d);
  }
;}
    break;

  case 27:
#line 402 "/Users/miguel/Downloads/make/wiretap/ascend.y"
    {
  /* remember the position of the data group in the trace, to tip off
     ascend_find_next_packet() as to where to look for the next header. */
  if (parser_state->first_hexbyte == 0)
    parser_state->first_hexbyte = file_tell(fh);

  /* XXX - if this test fails, it means that we parsed more bytes than
     the header claimed there were. */
  if (parser_state->caplen < parser_state->wirelen) {
    parser_state->pkt_data[parser_state->caplen] = (yyvsp[(1) - (1)].b);
    parser_state->caplen++;
  }

  /* arbitrary safety maximum... */
  if (parser_state->caplen >= ASCEND_MAX_PKT_LEN)
    YYACCEPT;
;}
    break;


/* Line 1267 of yacc.c.  */
#line 1818 "/Users/miguel/Downloads/make/wiretap/ascend.c"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;


  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (yyscanner, parser_state, fh, YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (yyscanner, parser_state, fh, yymsg);
	  }
	else
	  {
	    yyerror (yyscanner, parser_state, fh, YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse look-ahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval, yyscanner, parser_state, fh);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse look-ahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp, yyscanner, parser_state, fh);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  *++yyvsp = yylval;


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (yyscanner, parser_state, fh, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEOF && yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval, yyscanner, parser_state, fh);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp, yyscanner, parser_state, fh);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}


#line 452 "/Users/miguel/Downloads/make/wiretap/ascend.y"


DIAG_ON_BYACC

/* Run the parser. */
int
run_ascend_parser(FILE_T fh, wtap_rec *rec, guint8 *pd,
                  ascend_state_t *parser_state, int *err, gchar **err_info)
{
  yyscan_t scanner = NULL;
  int status;

  if (ascendlex_init(&scanner) != 0) {
    /* errno is set if this fails */
    *err = errno;
    *err_info = NULL;
    return 1;
  }
  /* Associate the parser state with the lexical analyzer state */
  ascendset_extra(parser_state, scanner);
  parser_state->fh = fh;
  parser_state->ascend_parse_error = NULL;
  parser_state->err = 0;
  parser_state->err_info = NULL;
  parser_state->pseudo_header = &rec->rec_header.packet_header.pseudo_header.ascend;
  parser_state->pkt_data = pd;

  /*
   * We haven't seen a time stamp yet.
   */
  parser_state->saw_timestamp = FALSE;
  parser_state->timestamp = 0;

  parser_state->first_hexbyte = 0;
  parser_state->caplen = 0;
  parser_state->wirelen = 0;

  parser_state->secs = 0;
  parser_state->usecs = 0;

  /*
   * Not all packets in a "wdd" dump necessarily have a "Cause an
   * attempt to place call to" header (I presume this can happen if
   * there was a call in progress when the packet was sent or
   * received), so we won't necessarily have the phone number for
   * the packet.
   *
   * XXX - we could assume, in the sequential pass, that it's the
   * phone number from the last call, and remember that for use
   * when doing random access.
   */
  parser_state->pseudo_header->call_num[0] = '\0';

  status = yyparse(scanner, parser_state, fh);
  ascendlex_destroy(scanner);

  *err = parser_state->err;
  *err_info = parser_state->err_info;
  return status;
}

void
yyerror (void *yyscanner, ascend_state_t *state _U_, FILE_T fh _U_, const char *s)
{
  ascendget_extra(yyscanner)->ascend_parse_error = s;
}

DIAG_OFF_BYACC

