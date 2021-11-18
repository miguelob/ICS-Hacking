/*
** 2000-05-29
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
** Driver template for the LEMON parser generator.
**
** The "lemon" program processes an LALR(1) input grammar file, then uses
** this template to construct a parser.  The "lemon" program inserts text
** at each "%%" line.  Also, any "P-a-r-s-e" identifer prefix (without the
** interstitial "-" characters) contained in this template is changed into
** the value of the %name directive from the grammar.  Otherwise, the content
** of this template is copied straight through into the generate parser
** source file.
**
** The following is the concatenation of all %include directives from the
** input grammar file:
*/
#include <stdio.h>
/************ Begin %include sections from the grammar ************************/
#line 1 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"


/* busmaster_parser.lemon
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for Busmaster log file format
 * Copyright (c) 2019 by Maksim Salau <maksim.salau@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <assert.h>
#include <string.h>
#include <wiretap/file_wrappers.h>
#include "busmaster_priv.h"

extern void *BusmasterParserAlloc(void *(*mallocProc)(size_t));
extern void BusmasterParser(void *yyp, int yymajor, token_t yyminor, busmaster_state_t *state);
extern void BusmasterParserFree(void *p, void (*freeProc)(void*));

#if defined(BUSMASTER_DEBUG) || defined(BUSMASTER_PARSER_TRACE)
extern void BusmasterParserTrace(FILE *TraceFILE, char *zTracePrompt);
#undef NDEBUG
#endif

static void merge_msg_data(msg_data_t *dst, const msg_data_t *a, const msg_data_t *b)
{
    dst->length = a->length + b->length;
    memcpy(&dst->data[0], &a->data[0], a->length);
    memcpy(&dst->data[a->length], &b->data[0], b->length);
}

DIAG_OFF(unreachable-code)

#line 66 "./busmaster_parser.c"
/**************** End of %include directives **********************************/
/* These constants specify the various numeric values for terminal symbols
** in a format understandable to "makeheaders".  This section is blank unless
** "lemon" is run with the "-m" command-line option.
***************** Begin makeheaders token definitions *************************/
/**************** End makeheaders token definitions ***************************/

/* The next sections is a series of control #defines.
** various aspects of the generated parser.
**    YYCODETYPE         is the data type used to store the integer codes
**                       that represent terminal and non-terminal symbols.
**                       "unsigned char" is used if there are fewer than
**                       256 symbols.  Larger types otherwise.
**    YYNOCODE           is a number of type YYCODETYPE that is not used for
**                       any terminal or nonterminal symbol.
**    YYFALLBACK         If defined, this indicates that one or more tokens
**                       (also known as: "terminal symbols") have fall-back
**                       values which should be used if the original symbol
**                       would not parse.  This permits keywords to sometimes
**                       be used as identifiers, for example.
**    YYACTIONTYPE       is the data type used for "action codes" - numbers
**                       that indicate what to do in response to the next
**                       token.
**    BusmasterParserTOKENTYPE     is the data type used for minor type for terminal
**                       symbols.  Background: A "minor type" is a semantic
**                       value associated with a terminal or non-terminal
**                       symbols.  For example, for an "ID" terminal symbol,
**                       the minor type might be the name of the identifier.
**                       Each non-terminal can have a different minor type.
**                       Terminal symbols all have the same minor type, though.
**                       This macros defines the minor type for terminal
**                       symbols.
**    YYMINORTYPE        is the data type used for all minor types.
**                       This is typically a union of many types, one of
**                       which is BusmasterParserTOKENTYPE.  The entry in the union
**                       for terminal symbols is called "yy0".
**    YYSTACKDEPTH       is the maximum depth of the parser's stack.  If
**                       zero the stack is dynamically sized using realloc()
**    BusmasterParserARG_SDECL     A static variable declaration for the %extra_argument
**    BusmasterParserARG_PDECL     A parameter declaration for the %extra_argument
**    BusmasterParserARG_PARAM     Code to pass %extra_argument as a subroutine parameter
**    BusmasterParserARG_STORE     Code to store %extra_argument into yypParser
**    BusmasterParserARG_FETCH     Code to extract %extra_argument from yypParser
**    BusmasterParserCTX_*         As BusmasterParserARG_ except for %extra_context
**    YYERRORSYMBOL      is the code number of the error symbol.  If not
**                       defined, then do no error processing.
**    YYNSTATE           the combined number of states.
**    YYNRULE            the number of rules in the grammar
**    YYNTOKEN           Number of terminal symbols
**    YY_MAX_SHIFT       Maximum value for shift actions
**    YY_MIN_SHIFTREDUCE Minimum value for shift-reduce actions
**    YY_MAX_SHIFTREDUCE Maximum value for shift-reduce actions
**    YY_ERROR_ACTION    The yy_action[] code for syntax error
**    YY_ACCEPT_ACTION   The yy_action[] code for accept
**    YY_NO_ACTION       The yy_action[] code for no-op
**    YY_MIN_REDUCE      Minimum value for reduce actions
**    YY_MAX_REDUCE      Maximum value for reduce actions
*/
#ifndef INTERFACE
# define INTERFACE 1
#endif
/************* Begin control #defines *****************************************/
#define YYCODETYPE unsigned char
#define YYNOCODE 59
#define YYACTIONTYPE unsigned char
#define BusmasterParserTOKENTYPE  token_t 
typedef union {
  int yyinit;
  BusmasterParserTOKENTYPE yy0;
  guint yy2;
  msg_type_t yy32;
  msg_data_t yy48;
  msg_time_t yy63;
  guint8 yy72;
  msg_date_t yy74;
  msg_date_time_t yy80;
  guint32 yy113;
} YYMINORTYPE;
#ifndef YYSTACKDEPTH
#define YYSTACKDEPTH 100
#endif
#define BusmasterParserARG_SDECL  busmaster_state_t* state ;
#define BusmasterParserARG_PDECL , busmaster_state_t* state 
#define BusmasterParserARG_PARAM ,state 
#define BusmasterParserARG_FETCH  busmaster_state_t* state =yypParser->state ;
#define BusmasterParserARG_STORE yypParser->state =state ;
#define BusmasterParserCTX_SDECL
#define BusmasterParserCTX_PDECL
#define BusmasterParserCTX_PARAM
#define BusmasterParserCTX_FETCH
#define BusmasterParserCTX_STORE
#define YYNSTATE             78
#define YYNRULE              64
#define YYNTOKEN             20
#define YY_MAX_SHIFT         77
#define YY_MIN_SHIFTREDUCE   117
#define YY_MAX_SHIFTREDUCE   180
#define YY_ERROR_ACTION      181
#define YY_ACCEPT_ACTION     182
#define YY_NO_ACTION         183
#define YY_MIN_REDUCE        184
#define YY_MAX_REDUCE        247
/************* End control #defines *******************************************/
#define YY_NLOOKAHEAD ((int)(sizeof(yy_lookahead)/sizeof(yy_lookahead[0])))

/* Define the yytestcase() macro to be a no-op if is not already defined
** otherwise.
**
** Applications can choose to define yytestcase() in the %include section
** to a macro that can assist in verifying code coverage.  For production
** code the yytestcase() macro should be turned off.  But it is useful
** for testing.
*/
#ifndef yytestcase
# define yytestcase(X)
#endif


/* Next are the tables used to determine what action to take based on the
** current state and lookahead token.  These tables are used to implement
** functions that take a state number and lookahead value and return an
** action integer.
**
** Suppose the action integer is N.  Then the action is determined as
** follows
**
**   0 <= N <= YY_MAX_SHIFT             Shift N.  That is, push the lookahead
**                                      token onto the stack and goto state N.
**
**   N between YY_MIN_SHIFTREDUCE       Shift to an arbitrary state then
**     and YY_MAX_SHIFTREDUCE           reduce by rule N-YY_MIN_SHIFTREDUCE.
**
**   N == YY_ERROR_ACTION               A syntax error has occurred.
**
**   N == YY_ACCEPT_ACTION              The parser accepts its input.
**
**   N == YY_NO_ACTION                  No such action.  Denotes unused
**                                      slots in the yy_action[] table.
**
**   N between YY_MIN_REDUCE            Reduce by rule N-YY_MIN_REDUCE
**     and YY_MAX_REDUCE
**
** The action table is constructed as a single large table named yy_action[].
** Given state S and lookahead X, the action is computed as either:
**
**    (A)   N = yy_action[ yy_shift_ofst[S] + X ]
**    (B)   N = yy_default[S]
**
** The (A) formula is preferred.  The B formula is used instead if
** yy_lookahead[yy_shift_ofst[S]+X] is not equal to X.
**
** The formulas above are for computing the action when the lookahead is
** a terminal symbol.  If the lookahead is a non-terminal (as occurs after
** a reduce action) then the yy_reduce_ofst[] array is used in place of
** the yy_shift_ofst[] array.
**
** The following are the tables generated in this section:
**
**  yy_action[]        A single table containing all actions.
**  yy_lookahead[]     A table containing the lookahead for each entry in
**                     yy_action.  Used to detect hash collisions.
**  yy_shift_ofst[]    For each state, the offset into yy_action for
**                     shifting terminals.
**  yy_reduce_ofst[]   For each state, the offset into yy_action for
**                     shifting non-terminals after a reduce.
**  yy_default[]       Default action for each state.
**
*********** Begin parsing tables **********************************************/
#define YY_ACTTAB_COUNT (158)
static const YYACTIONTYPE yy_action[] = {
 /*     0 */    23,  191,  199,  200,  201,  202,    4,  204,  205,  206,
 /*    10 */     9,  208,    6,  210,  211,    3,  213,  214,   23,  189,
 /*    20 */   199,  200,  201,  202,    4,  204,  205,  206,    9,  208,
 /*    30 */     6,  210,  211,    3,  213,  214,   42,   20,   20,   20,
 /*    40 */    52,   16,   35,   10,   10,  224,   28,    7,  226,    5,
 /*    50 */    23,  127,  231,  221,  222,  223,  224,   71,  235,  148,
 /*    60 */    30,   14,  182,   77,   76,   75,   45,   57,   56,   55,
 /*    70 */    74,   20,   20,   35,   54,  185,  129,   12,   10,   20,
 /*    80 */    74,  226,    7,    1,  229,   11,  176,   43,  179,    8,
 /*    90 */   128,  229,  174,   51,  178,  190,  131,  130,  220,   18,
 /*   100 */    19,    2,   21,   22,   17,   24,   25,   68,   62,   69,
 /*   110 */    43,   70,  247,   27,   72,  187,   29,   73,   58,   44,
 /*   120 */    15,   31,   32,   13,   46,   47,   48,   53,  238,   49,
 /*   130 */    50,   26,  121,  237,  236,   33,   34,  125,  174,  183,
 /*   140 */    60,   59,   36,   61,  126,   37,   64,   63,   38,   39,
 /*   150 */    66,   65,   40,   67,   41,  234,  233,  232,
};
static const YYCODETYPE yy_lookahead[] = {
 /*     0 */    28,   29,   30,   31,   32,   33,   34,   35,   36,   37,
 /*    10 */    38,   39,   40,   41,   42,   43,   44,   45,   28,   29,
 /*    20 */    30,   31,   32,   33,   34,   35,   36,   37,   38,   39,
 /*    30 */    40,   41,   42,   43,   44,   45,   20,   28,   28,   28,
 /*    40 */    13,   14,    8,   34,   34,   34,   12,   38,   38,   40,
 /*    50 */    28,   17,   43,   31,   32,   33,   34,   27,    0,   14,
 /*    60 */    10,    3,   46,   47,   48,   49,   50,   51,   52,   53,
 /*    70 */    54,   28,   28,    8,   58,   49,   14,   34,   34,   28,
 /*    80 */    54,   38,   38,   23,   40,   34,    3,   57,    3,   38,
 /*    90 */    14,   40,    9,   24,    9,   22,   19,   18,   28,   28,
 /*   100 */    28,   23,   28,   28,   14,   21,   24,   14,   14,    7,
 /*   110 */    57,    6,   26,   25,    5,   26,   25,    4,   57,   56,
 /*   120 */    13,   55,   55,   55,   14,   14,   14,    3,    0,   15,
 /*   130 */    14,   14,   11,    0,    0,   55,   55,   14,    9,   59,
 /*   140 */    14,   16,    3,   16,   14,    3,   14,   16,    3,    3,
 /*   150 */    14,   16,    3,   16,    3,    0,    0,    0,   59,   59,
 /*   160 */    59,   59,   59,   59,   59,   59,   59,   59,   59,   59,
 /*   170 */    59,   59,   59,   59,   59,   59,   59,   59,
};
#define YY_SHIFT_COUNT    (77)
#define YY_SHIFT_MIN      (0)
#define YY_SHIFT_MAX      (157)
static const unsigned char yy_shift_ofst[] = {
 /*     0 */    34,   45,   45,   45,   45,   45,   45,   45,   45,   45,
 /*    10 */    45,   45,   45,   50,   65,   62,   76,   77,   45,   45,
 /*    20 */    45,   45,   45,   45,   62,   79,   90,   93,   94,   93,
 /*    30 */    94,  102,  105,  109,  113,  158,  158,  158,  158,  158,
 /*    40 */   158,  158,   27,   83,   85,   58,  107,  110,  111,  112,
 /*    50 */   114,  116,  117,  121,  124,  128,  133,  134,  129,  123,
 /*    60 */   125,  126,  127,  130,  131,  132,  135,  136,  137,  139,
 /*    70 */   142,  145,  146,  149,  151,  155,  156,  157,
};
#define YY_REDUCE_COUNT (41)
#define YY_REDUCE_MIN   (-28)
#define YY_REDUCE_MAX   (91)
static const signed char yy_reduce_ofst[] = {
 /*     0 */    16,  -28,  -10,    9,   22,   44,   51,   10,   10,   43,
 /*    10 */    11,   11,   11,   30,   26,   60,   69,   73,   70,   71,
 /*    20 */    72,   70,   74,   75,   78,   84,   82,   86,   88,   89,
 /*    30 */    91,   53,   53,   53,   53,   61,   63,   66,   67,   68,
 /*    40 */    80,   81,
};
static const YYACTIONTYPE yy_default[] = {
 /*     0 */   184,  216,  216,  212,  203,  230,  209,  181,  228,  207,
 /*    10 */   181,  227,  225,  240,  181,  181,  181,  195,  181,  181,
 /*    20 */   181,  219,  218,  217,  181,  181,  181,  181,  181,  181,
 /*    30 */   181,  240,  240,  240,  240,  240,  244,  242,  242,  242,
 /*    40 */   242,  242,  181,  181,  186,  181,  181,  181,  181,  181,
 /*    50 */   181,  181,  181,  181,  181,  181,  181,  181,  239,  181,
 /*    60 */   181,  181,  181,  181,  181,  181,  181,  181,  181,  181,
 /*    70 */   181,  181,  181,  181,  181,  181,  181,  181,
};
/********** End of lemon-generated parsing tables *****************************/

/* The next table maps tokens (terminal symbols) into fallback tokens.
** If a construct like the following:
**
**      %fallback ID X Y Z.
**
** appears in the grammar, then ID becomes a fallback token for X, Y,
** and Z.  Whenever one of the tokens X, Y, or Z is input to the parser
** but it does not parse, the type of the token is changed to ID and
** the parse is retried before an error is thrown.
**
** This feature can be used, for example, to cause some keywords in a language
** to revert to identifiers if they keyword does not apply in the context where
** it appears.
*/
#ifdef YYFALLBACK
static const YYCODETYPE yyFallback[] = {
};
#endif /* YYFALLBACK */

/* The following structure represents a single element of the
** parser's stack.  Information stored includes:
**
**   +  The state number for the parser at this level of the stack.
**
**   +  The value of the token stored at this level of the stack.
**      (In other words, the "major" token.)
**
**   +  The semantic value stored at this level of the stack.  This is
**      the information used by the action routines in the grammar.
**      It is sometimes called the "minor" token.
**
** After the "shift" half of a SHIFTREDUCE action, the stateno field
** actually contains the reduce action for the second half of the
** SHIFTREDUCE.
*/
struct yyStackEntry {
  YYACTIONTYPE stateno;  /* The state-number, or reduce action in SHIFTREDUCE */
  YYCODETYPE major;      /* The major token value.  This is the code
                         ** number for the token at this stack level */
  YYMINORTYPE minor;     /* The user-supplied minor token value.  This
                         ** is the value of the token  */
};
typedef struct yyStackEntry yyStackEntry;

/* The state of the parser is completely contained in an instance of
** the following structure */
struct yyParser {
  yyStackEntry *yytos;          /* Pointer to top element of the stack */
#ifdef YYTRACKMAXSTACKDEPTH
  int yyhwm;                    /* High-water mark of the stack */
#endif
#ifndef YYNOERRORRECOVERY
  int yyerrcnt;                 /* Shifts left before out of the error */
#endif
  BusmasterParserARG_SDECL                /* A place to hold %extra_argument */
  BusmasterParserCTX_SDECL                /* A place to hold %extra_context */
#if YYSTACKDEPTH<=0
  int yystksz;                  /* Current side of the stack */
  yyStackEntry *yystack;        /* The parser's stack */
  yyStackEntry yystk0;          /* First stack entry */
#else
  yyStackEntry yystack[YYSTACKDEPTH];  /* The parser's stack */
  yyStackEntry *yystackEnd;            /* Last entry in the stack */
#endif
};
typedef struct yyParser yyParser;

#ifndef NDEBUG
#include <stdio.h>
static FILE *yyTraceFILE = 0;
static char *yyTracePrompt = 0;
#endif /* NDEBUG */

#ifndef NDEBUG
/*
** Turn parser tracing on by giving a stream to which to write the trace
** and a prompt to preface each trace message.  Tracing is turned off
** by making either argument NULL
**
** Inputs:
** <ul>
** <li> A FILE* to which trace output should be written.
**      If NULL, then tracing is turned off.
** <li> A prefix string written at the beginning of every
**      line of trace output.  If NULL, then tracing is
**      turned off.
** </ul>
**
** Outputs:
** None.
*/
void BusmasterParserTrace(FILE *TraceFILE, char *zTracePrompt){
  yyTraceFILE = TraceFILE;
  yyTracePrompt = zTracePrompt;
  if( yyTraceFILE==0 ) yyTracePrompt = 0;
  else if( yyTracePrompt==0 ) yyTraceFILE = 0;
}
#endif /* NDEBUG */

#if defined(YYCOVERAGE) || !defined(NDEBUG)
/* For tracing shifts, the names of all terminals and nonterminals
** are required.  The following table supplies these names */
static const char *const yyTokenName[] = {
  /*    0 */ "$",
  /*    1 */ "INVALID_CHAR",
  /*    2 */ "INVALID_NUMBER",
  /*    3 */ "ENDL",
  /*    4 */ "PROTOCOL_TYPE",
  /*    5 */ "START_SESSION",
  /*    6 */ "DATA_MODE",
  /*    7 */ "TIME_MODE",
  /*    8 */ "HEADER_VER",
  /*    9 */ "HEADER_CHAR",
  /*   10 */ "START_TIME",
  /*   11 */ "STOP_SESSION",
  /*   12 */ "END_TIME",
  /*   13 */ "MSG_DIR",
  /*   14 */ "INT",
  /*   15 */ "J1939_MSG_TYPE",
  /*   16 */ "COLON",
  /*   17 */ "MSG_TIME",
  /*   18 */ "MSG_TYPE",
  /*   19 */ "ERR_MSG_TYPE",
  /*   20 */ "msg_time",
  /*   21 */ "msg_type",
  /*   22 */ "err_msg_type",
  /*   23 */ "msg_length",
  /*   24 */ "msg_id",
  /*   25 */ "ref_date",
  /*   26 */ "ref_time",
  /*   27 */ "start_time",
  /*   28 */ "byte",
  /*   29 */ "data",
  /*   30 */ "data0",
  /*   31 */ "data1",
  /*   32 */ "data2",
  /*   33 */ "data3",
  /*   34 */ "data4",
  /*   35 */ "data5",
  /*   36 */ "data6",
  /*   37 */ "data7",
  /*   38 */ "data8",
  /*   39 */ "data12",
  /*   40 */ "data16",
  /*   41 */ "data20",
  /*   42 */ "data24",
  /*   43 */ "data32",
  /*   44 */ "data48",
  /*   45 */ "data64",
  /*   46 */ "entry",
  /*   47 */ "empty_line",
  /*   48 */ "footer_and_header",
  /*   49 */ "header",
  /*   50 */ "footer",
  /*   51 */ "msg",
  /*   52 */ "err_msg",
  /*   53 */ "j1939_msg",
  /*   54 */ "version",
  /*   55 */ "maybe_lines",
  /*   56 */ "anything",
  /*   57 */ "maybe_chars",
  /*   58 */ "end_time",
};
#endif /* defined(YYCOVERAGE) || !defined(NDEBUG) */

#ifndef NDEBUG
/* For tracing reduce actions, the names of all rules are required.
*/
static const char *const yyRuleName[] = {
 /*   0 */ "empty_line ::=",
 /*   1 */ "footer_and_header ::= footer ENDL header",
 /*   2 */ "header ::= version ENDL maybe_lines PROTOCOL_TYPE ENDL maybe_lines START_SESSION ENDL maybe_lines start_time ENDL maybe_lines DATA_MODE ENDL maybe_lines TIME_MODE ENDL anything",
 /*   3 */ "start_time ::= START_TIME ref_date ref_time",
 /*   4 */ "footer ::= end_time ENDL STOP_SESSION",
 /*   5 */ "msg ::= msg_time MSG_DIR INT msg_id msg_type msg_length data",
 /*   6 */ "err_msg ::= msg_time MSG_DIR INT INT err_msg_type",
 /*   7 */ "j1939_msg ::= msg_time INT msg_id INT J1939_MSG_TYPE INT INT INT MSG_DIR msg_length data",
 /*   8 */ "ref_date ::= INT COLON INT COLON INT",
 /*   9 */ "ref_time ::= INT COLON INT COLON INT COLON INT",
 /*  10 */ "msg_time ::= MSG_TIME",
 /*  11 */ "msg_id ::= INT",
 /*  12 */ "msg_length ::= INT",
 /*  13 */ "msg_type ::= MSG_TYPE",
 /*  14 */ "err_msg_type ::= ERR_MSG_TYPE",
 /*  15 */ "data ::= data0",
 /*  16 */ "data ::= data1",
 /*  17 */ "data ::= data2",
 /*  18 */ "data ::= data3",
 /*  19 */ "data ::= data4",
 /*  20 */ "data ::= data5",
 /*  21 */ "data ::= data6",
 /*  22 */ "data ::= data7",
 /*  23 */ "data ::= data8",
 /*  24 */ "data ::= data12",
 /*  25 */ "data ::= data16",
 /*  26 */ "data ::= data20",
 /*  27 */ "data ::= data24",
 /*  28 */ "data ::= data32",
 /*  29 */ "data ::= data48",
 /*  30 */ "data ::= data64",
 /*  31 */ "byte ::= INT",
 /*  32 */ "data0 ::=",
 /*  33 */ "data1 ::= byte",
 /*  34 */ "data2 ::= byte byte",
 /*  35 */ "data3 ::= byte byte byte",
 /*  36 */ "data4 ::= byte byte byte byte",
 /*  37 */ "data5 ::= data4 data1",
 /*  38 */ "data6 ::= data4 data2",
 /*  39 */ "data7 ::= data4 data3",
 /*  40 */ "data8 ::= data4 data4",
 /*  41 */ "data12 ::= data8 data4",
 /*  42 */ "data16 ::= data8 data8",
 /*  43 */ "data20 ::= data16 data4",
 /*  44 */ "data24 ::= data16 data8",
 /*  45 */ "data32 ::= data16 data16",
 /*  46 */ "data48 ::= data32 data16",
 /*  47 */ "data64 ::= data32 data32",
 /*  48 */ "entry ::= empty_line",
 /*  49 */ "entry ::= footer_and_header",
 /*  50 */ "entry ::= header",
 /*  51 */ "entry ::= footer",
 /*  52 */ "entry ::= msg",
 /*  53 */ "entry ::= err_msg",
 /*  54 */ "entry ::= j1939_msg",
 /*  55 */ "version ::= HEADER_VER maybe_chars",
 /*  56 */ "maybe_chars ::=",
 /*  57 */ "maybe_chars ::= maybe_chars HEADER_CHAR",
 /*  58 */ "maybe_lines ::=",
 /*  59 */ "maybe_lines ::= maybe_lines maybe_chars ENDL",
 /*  60 */ "anything ::=",
 /*  61 */ "anything ::= anything HEADER_CHAR",
 /*  62 */ "anything ::= anything ENDL",
 /*  63 */ "end_time ::= END_TIME ref_date ref_time",
};
#endif /* NDEBUG */


#if YYSTACKDEPTH<=0
/*
** Try to increase the size of the parser stack.  Return the number
** of errors.  Return 0 on success.
*/
static int yyGrowStack(yyParser *p){
  int newSize;
  int idx;
  yyStackEntry *pNew;

  newSize = p->yystksz*2 + 100;
  idx = p->yytos ? (int)(p->yytos - p->yystack) : 0;
  if( p->yystack==&p->yystk0 ){
    pNew = malloc(newSize*sizeof(pNew[0]));
    if( pNew ) pNew[0] = p->yystk0;
  }else{
    pNew = realloc(p->yystack, newSize*sizeof(pNew[0]));
  }
  if( pNew ){
    p->yystack = pNew;
    p->yytos = &p->yystack[idx];
#ifndef NDEBUG
    if( yyTraceFILE ){
      fprintf(yyTraceFILE,"%sStack grows from %d to %d entries.\n",
              yyTracePrompt, p->yystksz, newSize);
    }
#endif
    p->yystksz = newSize;
  }
  return pNew==0;
}
#endif

/* Datatype of the argument to the memory allocated passed as the
** second argument to BusmasterParserAlloc() below.  This can be changed by
** putting an appropriate #define in the %include section of the input
** grammar.
*/
#ifndef YYMALLOCARGTYPE
# define YYMALLOCARGTYPE size_t
#endif

/* Initialize a new parser that has already been allocated.
*/
static void BusmasterParserInit(void *yypRawParser BusmasterParserCTX_PDECL){
  yyParser *yypParser = (yyParser*)yypRawParser;
  BusmasterParserCTX_STORE
#ifdef YYTRACKMAXSTACKDEPTH
  yypParser->yyhwm = 0;
#endif
#if YYSTACKDEPTH<=0
  yypParser->yytos = NULL;
  yypParser->yystack = NULL;
  yypParser->yystksz = 0;
  if( yyGrowStack(yypParser) ){
    yypParser->yystack = &yypParser->yystk0;
    yypParser->yystksz = 1;
  }
#endif
#ifndef YYNOERRORRECOVERY
  yypParser->yyerrcnt = -1;
#endif
  yypParser->yytos = yypParser->yystack;
  yypParser->yystack[0].stateno = 0;
  yypParser->yystack[0].major = 0;
#if YYSTACKDEPTH>0
  yypParser->yystackEnd = &yypParser->yystack[YYSTACKDEPTH-1];
#endif
}

#ifndef BusmasterParser_ENGINEALWAYSONSTACK
/*
** This function allocates a new parser.
** The only argument is a pointer to a function which works like
** malloc.
**
** Inputs:
** A pointer to the function used to allocate memory.
**
** Outputs:
** A pointer to a parser.  This pointer is used in subsequent calls
** to BusmasterParser and BusmasterParserFree.
*/
void *BusmasterParserAlloc(void *(*mallocProc)(YYMALLOCARGTYPE) BusmasterParserCTX_PDECL){
  yyParser *yypParser;
  yypParser = (yyParser*)(*mallocProc)( (YYMALLOCARGTYPE)sizeof(yyParser) );
  if( yypParser ){
    BusmasterParserCTX_STORE
    BusmasterParserInit(yypParser BusmasterParserCTX_PARAM);
  }
  return (void*)yypParser;
}
#endif /* BusmasterParser_ENGINEALWAYSONSTACK */


/* The following function deletes the "minor type" or semantic value
** associated with a symbol.  The symbol can be either a terminal
** or nonterminal. "yymajor" is the symbol code, and "yypminor" is
** a pointer to the value to be deleted.  The code used to do the
** deletions is derived from the %destructor and/or %token_destructor
** directives of the input grammar.
*/
static void yy_destructor(
  yyParser *yypParser,    /* The parser */
  YYCODETYPE yymajor,     /* Type code for object to destroy */
  YYMINORTYPE *yypminor   /* The object to be destroyed */
){
  BusmasterParserARG_FETCH
  BusmasterParserCTX_FETCH
  switch( yymajor ){
    /* Here is inserted the actions which take place when a
    ** terminal or non-terminal is destroyed.  This can happen
    ** when the symbol is popped from the stack during a
    ** reduce or during error processing or when a parser is
    ** being destroyed before it is finished parsing.
    **
    ** Note: during a reduce, the only symbols destroyed are those
    ** which appear on the RHS of the rule, but which are *not* used
    ** inside the C code.
    */
/********* Begin destructor definitions ***************************************/
      /* TERMINAL Destructor */
    case 1: /* INVALID_CHAR */
    case 2: /* INVALID_NUMBER */
    case 3: /* ENDL */
    case 4: /* PROTOCOL_TYPE */
    case 5: /* START_SESSION */
    case 6: /* DATA_MODE */
    case 7: /* TIME_MODE */
    case 8: /* HEADER_VER */
    case 9: /* HEADER_CHAR */
    case 10: /* START_TIME */
    case 11: /* STOP_SESSION */
    case 12: /* END_TIME */
    case 13: /* MSG_DIR */
    case 14: /* INT */
    case 15: /* J1939_MSG_TYPE */
    case 16: /* COLON */
    case 17: /* MSG_TIME */
    case 18: /* MSG_TYPE */
    case 19: /* ERR_MSG_TYPE */
{
#line 47 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"

    (void)state;
    (void)yypParser;
    (void)yypminor;

#line 694 "./busmaster_parser.c"
}
      break;
/********* End destructor definitions *****************************************/
    default:  break;   /* If no destructor action specified: do nothing */
  }
}

/*
** Pop the parser's stack once.
**
** If there is a destructor routine associated with the token which
** is popped from the stack, then call it.
*/
static void yy_pop_parser_stack(yyParser *pParser){
  yyStackEntry *yytos;
  assert( pParser->yytos!=0 );
  assert( pParser->yytos > pParser->yystack );
  yytos = pParser->yytos--;
#ifndef NDEBUG
  if( yyTraceFILE ){
    fprintf(yyTraceFILE,"%sPopping %s\n",
      yyTracePrompt,
      yyTokenName[yytos->major]);
  }
#endif
  yy_destructor(pParser, yytos->major, &yytos->minor);
}

/*
** Clear all secondary memory allocations from the parser
*/
static void BusmasterParserFinalize(void *p){
  yyParser *pParser = (yyParser*)p;
  while( pParser->yytos>pParser->yystack ) yy_pop_parser_stack(pParser);
#if YYSTACKDEPTH<=0
  if( pParser->yystack!=&pParser->yystk0 ) free(pParser->yystack);
#endif
}

#ifndef BusmasterParser_ENGINEALWAYSONSTACK
/*
** Deallocate and destroy a parser.  Destructors are called for
** all stack elements before shutting the parser down.
**
** If the YYPARSEFREENEVERNULL macro exists (for example because it
** is defined in a %include section of the input grammar) then it is
** assumed that the input pointer is never NULL.
*/
void BusmasterParserFree(
  void *p,                    /* The parser to be deleted */
  void (*freeProc)(void*)     /* Function used to reclaim memory */
){
#ifndef YYPARSEFREENEVERNULL
  if( p==0 ) return;
#endif
  BusmasterParserFinalize(p);
  (*freeProc)(p);
}
#endif /* BusmasterParser_ENGINEALWAYSONSTACK */

/*
** Return the peak depth of the stack for a parser.
*/
#ifdef YYTRACKMAXSTACKDEPTH
int BusmasterParserStackPeak(void *p){
  yyParser *pParser = (yyParser*)p;
  return pParser->yyhwm;
}
#endif

/* This array of booleans keeps track of the parser statement
** coverage.  The element yycoverage[X][Y] is set when the parser
** is in state X and has a lookahead token Y.  In a well-tested
** systems, every element of this matrix should end up being set.
*/
#if defined(YYCOVERAGE)
static unsigned char yycoverage[YYNSTATE][YYNTOKEN];
#endif

/*
** Write into out a description of every state/lookahead combination that
**
**   (1)  has not been used by the parser, and
**   (2)  is not a syntax error.
**
** Return the number of missed state/lookahead combinations.
*/
#if defined(YYCOVERAGE)
int BusmasterParserCoverage(FILE *out){
  int stateno, iLookAhead, i;
  int nMissed = 0;
  for(stateno=0; stateno<YYNSTATE; stateno++){
    i = yy_shift_ofst[stateno];
    for(iLookAhead=0; iLookAhead<YYNTOKEN; iLookAhead++){
      if( yy_lookahead[i+iLookAhead]!=iLookAhead ) continue;
      if( yycoverage[stateno][iLookAhead]==0 ) nMissed++;
      if( out ){
        fprintf(out,"State %d lookahead %s %s\n", stateno,
                yyTokenName[iLookAhead],
                yycoverage[stateno][iLookAhead] ? "ok" : "missed");
      }
    }
  }
  return nMissed;
}
#endif

/*
** Find the appropriate action for a parser given the terminal
** look-ahead token iLookAhead.
*/
static YYACTIONTYPE yy_find_shift_action(
  YYCODETYPE iLookAhead,    /* The look-ahead token */
  YYACTIONTYPE stateno      /* Current state number */
){
  int i;

  if( stateno>YY_MAX_SHIFT ) return stateno;
  assert( stateno <= YY_SHIFT_COUNT );
#if defined(YYCOVERAGE)
  yycoverage[stateno][iLookAhead] = 1;
#endif
  do{
    i = yy_shift_ofst[stateno];
    assert( i>=0 );
    /* assert( i+YYNTOKEN<=(int)YY_NLOOKAHEAD ); */
    assert( iLookAhead!=YYNOCODE );
    assert( iLookAhead < YYNTOKEN );
    i += iLookAhead;
    if( i>=YY_NLOOKAHEAD || yy_lookahead[i]!=iLookAhead ){
#ifdef YYFALLBACK
      YYCODETYPE iFallback;            /* Fallback token */
      if( iLookAhead<sizeof(yyFallback)/sizeof(yyFallback[0])
             && (iFallback = yyFallback[iLookAhead])!=0 ){
#ifndef NDEBUG
        if( yyTraceFILE ){
          fprintf(yyTraceFILE, "%sFALLBACK %s => %s\n",
             yyTracePrompt, yyTokenName[iLookAhead], yyTokenName[iFallback]);
        }
#endif
        assert( yyFallback[iFallback]==0 ); /* Fallback loop must terminate */
        iLookAhead = iFallback;
        continue;
      }
#endif
#ifdef YYWILDCARD
      {
        int j = i - iLookAhead + YYWILDCARD;
        if(
#if YY_SHIFT_MIN+YYWILDCARD<0
          j>=0 &&
#endif
#if YY_SHIFT_MAX+YYWILDCARD>=YY_ACTTAB_COUNT
          j<YY_ACTTAB_COUNT &&
#endif
          j<(int)(sizeof(yy_lookahead)/sizeof(yy_lookahead[0])) &&
          yy_lookahead[j]==YYWILDCARD && iLookAhead>0
        ){
#ifndef NDEBUG
          if( yyTraceFILE ){
            fprintf(yyTraceFILE, "%sWILDCARD %s => %s\n",
               yyTracePrompt, yyTokenName[iLookAhead],
               yyTokenName[YYWILDCARD]);
          }
#endif /* NDEBUG */
          return yy_action[j];
        }
      }
#endif /* YYWILDCARD */
      return yy_default[stateno];
    }else{
      return yy_action[i];
    }
  }while(1);
}

/*
** Find the appropriate action for a parser given the non-terminal
** look-ahead token iLookAhead.
*/
static YYACTIONTYPE yy_find_reduce_action(
  YYACTIONTYPE stateno,     /* Current state number */
  YYCODETYPE iLookAhead     /* The look-ahead token */
){
  int i;
#ifdef YYERRORSYMBOL
  if( stateno>YY_REDUCE_COUNT ){
    return yy_default[stateno];
  }
#else
  assert( stateno<=YY_REDUCE_COUNT );
#endif
  i = yy_reduce_ofst[stateno];
  assert( iLookAhead!=YYNOCODE );
  i += iLookAhead;
#ifdef YYERRORSYMBOL
  if( i<0 || i>=YY_ACTTAB_COUNT || yy_lookahead[i]!=iLookAhead ){
    return yy_default[stateno];
  }
#else
  assert( i>=0 && i<YY_ACTTAB_COUNT );
  assert( yy_lookahead[i]==iLookAhead );
#endif
  return yy_action[i];
}

/*
** The following routine is called if the stack overflows.
*/
static void yyStackOverflow(yyParser *yypParser){
   BusmasterParserARG_FETCH
   BusmasterParserCTX_FETCH
#ifndef NDEBUG
   if( yyTraceFILE ){
     fprintf(yyTraceFILE,"%sStack Overflow!\n",yyTracePrompt);
   }
#endif
   while( yypParser->yytos>yypParser->yystack ) yy_pop_parser_stack(yypParser);
   /* Here code is inserted which will execute if the parser
   ** stack every overflows */
/******** Begin %stack_overflow code ******************************************/
#line 86 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"

    g_free(state->parse_error);
    state->entry_type  = LOG_ENTRY_ERROR;
    state->parse_error = g_strdup("Parser stack overflow");
    busmaster_debug_printf("%s: Parser stack overflow\n", G_STRFUNC);
#line 922 "./busmaster_parser.c"
/******** End %stack_overflow code ********************************************/
   BusmasterParserARG_STORE /* Suppress warning about unused %extra_argument var */
   BusmasterParserCTX_STORE
}

/*
** Print tracing information for a SHIFT action
*/
#ifndef NDEBUG
static void yyTraceShift(yyParser *yypParser, int yyNewState, const char *zTag){
  if( yyTraceFILE ){
    if( yyNewState<YYNSTATE ){
      fprintf(yyTraceFILE,"%s%s '%s', go to state %d\n",
         yyTracePrompt, zTag, yyTokenName[yypParser->yytos->major],
         yyNewState);
    }else{
      fprintf(yyTraceFILE,"%s%s '%s', pending reduce %d\n",
         yyTracePrompt, zTag, yyTokenName[yypParser->yytos->major],
         yyNewState - YY_MIN_REDUCE);
    }
  }
}
#else
# define yyTraceShift(X,Y,Z)
#endif

/*
** Perform a shift action.
*/
static void yy_shift(
  yyParser *yypParser,          /* The parser to be shifted */
  YYACTIONTYPE yyNewState,      /* The new state to shift in */
  YYCODETYPE yyMajor,           /* The major token to shift in */
  BusmasterParserTOKENTYPE yyMinor        /* The minor token to shift in */
){
  yyStackEntry *yytos;
  yypParser->yytos++;
#ifdef YYTRACKMAXSTACKDEPTH
  if( (int)(yypParser->yytos - yypParser->yystack)>yypParser->yyhwm ){
    yypParser->yyhwm++;
    assert( yypParser->yyhwm == (int)(yypParser->yytos - yypParser->yystack) );
  }
#endif
#if YYSTACKDEPTH>0
  if( yypParser->yytos>yypParser->yystackEnd ){
    yypParser->yytos--;
    yyStackOverflow(yypParser);
    return;
  }
#else
  if( yypParser->yytos>=&yypParser->yystack[yypParser->yystksz] ){
    if( yyGrowStack(yypParser) ){
      yypParser->yytos--;
      yyStackOverflow(yypParser);
      return;
    }
  }
#endif
  if( yyNewState > YY_MAX_SHIFT ){
    yyNewState += YY_MIN_REDUCE - YY_MIN_SHIFTREDUCE;
  }
  yytos = yypParser->yytos;
  yytos->stateno = yyNewState;
  yytos->major = yyMajor;
  yytos->minor.yy0 = yyMinor;
  yyTraceShift(yypParser, yyNewState, "Shift");
}

/* The following table contains information about every rule that
** is used during the reduce.
*/
static const struct {
  YYCODETYPE lhs;       /* Symbol on the left-hand side of the rule */
  signed char nrhs;     /* Negative of the number of RHS symbols in the rule */
} yyRuleInfo[] = {
  {   47,    0 }, /* (0) empty_line ::= */
  {   48,   -3 }, /* (1) footer_and_header ::= footer ENDL header */
  {   49,  -18 }, /* (2) header ::= version ENDL maybe_lines PROTOCOL_TYPE ENDL maybe_lines START_SESSION ENDL maybe_lines start_time ENDL maybe_lines DATA_MODE ENDL maybe_lines TIME_MODE ENDL anything */
  {   27,   -3 }, /* (3) start_time ::= START_TIME ref_date ref_time */
  {   50,   -3 }, /* (4) footer ::= end_time ENDL STOP_SESSION */
  {   51,   -7 }, /* (5) msg ::= msg_time MSG_DIR INT msg_id msg_type msg_length data */
  {   52,   -5 }, /* (6) err_msg ::= msg_time MSG_DIR INT INT err_msg_type */
  {   53,  -11 }, /* (7) j1939_msg ::= msg_time INT msg_id INT J1939_MSG_TYPE INT INT INT MSG_DIR msg_length data */
  {   25,   -5 }, /* (8) ref_date ::= INT COLON INT COLON INT */
  {   26,   -7 }, /* (9) ref_time ::= INT COLON INT COLON INT COLON INT */
  {   20,   -1 }, /* (10) msg_time ::= MSG_TIME */
  {   24,   -1 }, /* (11) msg_id ::= INT */
  {   23,   -1 }, /* (12) msg_length ::= INT */
  {   21,   -1 }, /* (13) msg_type ::= MSG_TYPE */
  {   22,   -1 }, /* (14) err_msg_type ::= ERR_MSG_TYPE */
  {   29,   -1 }, /* (15) data ::= data0 */
  {   29,   -1 }, /* (16) data ::= data1 */
  {   29,   -1 }, /* (17) data ::= data2 */
  {   29,   -1 }, /* (18) data ::= data3 */
  {   29,   -1 }, /* (19) data ::= data4 */
  {   29,   -1 }, /* (20) data ::= data5 */
  {   29,   -1 }, /* (21) data ::= data6 */
  {   29,   -1 }, /* (22) data ::= data7 */
  {   29,   -1 }, /* (23) data ::= data8 */
  {   29,   -1 }, /* (24) data ::= data12 */
  {   29,   -1 }, /* (25) data ::= data16 */
  {   29,   -1 }, /* (26) data ::= data20 */
  {   29,   -1 }, /* (27) data ::= data24 */
  {   29,   -1 }, /* (28) data ::= data32 */
  {   29,   -1 }, /* (29) data ::= data48 */
  {   29,   -1 }, /* (30) data ::= data64 */
  {   28,   -1 }, /* (31) byte ::= INT */
  {   30,    0 }, /* (32) data0 ::= */
  {   31,   -1 }, /* (33) data1 ::= byte */
  {   32,   -2 }, /* (34) data2 ::= byte byte */
  {   33,   -3 }, /* (35) data3 ::= byte byte byte */
  {   34,   -4 }, /* (36) data4 ::= byte byte byte byte */
  {   35,   -2 }, /* (37) data5 ::= data4 data1 */
  {   36,   -2 }, /* (38) data6 ::= data4 data2 */
  {   37,   -2 }, /* (39) data7 ::= data4 data3 */
  {   38,   -2 }, /* (40) data8 ::= data4 data4 */
  {   39,   -2 }, /* (41) data12 ::= data8 data4 */
  {   40,   -2 }, /* (42) data16 ::= data8 data8 */
  {   41,   -2 }, /* (43) data20 ::= data16 data4 */
  {   42,   -2 }, /* (44) data24 ::= data16 data8 */
  {   43,   -2 }, /* (45) data32 ::= data16 data16 */
  {   44,   -2 }, /* (46) data48 ::= data32 data16 */
  {   45,   -2 }, /* (47) data64 ::= data32 data32 */
  {   46,   -1 }, /* (48) entry ::= empty_line */
  {   46,   -1 }, /* (49) entry ::= footer_and_header */
  {   46,   -1 }, /* (50) entry ::= header */
  {   46,   -1 }, /* (51) entry ::= footer */
  {   46,   -1 }, /* (52) entry ::= msg */
  {   46,   -1 }, /* (53) entry ::= err_msg */
  {   46,   -1 }, /* (54) entry ::= j1939_msg */
  {   54,   -2 }, /* (55) version ::= HEADER_VER maybe_chars */
  {   57,    0 }, /* (56) maybe_chars ::= */
  {   57,   -2 }, /* (57) maybe_chars ::= maybe_chars HEADER_CHAR */
  {   55,    0 }, /* (58) maybe_lines ::= */
  {   55,   -3 }, /* (59) maybe_lines ::= maybe_lines maybe_chars ENDL */
  {   56,    0 }, /* (60) anything ::= */
  {   56,   -2 }, /* (61) anything ::= anything HEADER_CHAR */
  {   56,   -2 }, /* (62) anything ::= anything ENDL */
  {   58,   -3 }, /* (63) end_time ::= END_TIME ref_date ref_time */
};

static void yy_accept(yyParser*);  /* Forward Declaration */

/*
** Perform a reduce action and the shift that must immediately
** follow the reduce.
**
** The yyLookahead and yyLookaheadToken parameters provide reduce actions
** access to the lookahead token (if any).  The yyLookahead will be YYNOCODE
** if the lookahead token has already been consumed.  As this procedure is
** only called from one place, optimizing compilers will in-line it, which
** means that the extra parameters have no performance impact.
*/
static YYACTIONTYPE yy_reduce(
  yyParser *yypParser,         /* The parser */
  unsigned int yyruleno,       /* Number of the rule by which to reduce */
  int yyLookahead,             /* Lookahead token, or YYNOCODE if none */
  BusmasterParserTOKENTYPE yyLookaheadToken  /* Value of the lookahead token */
  BusmasterParserCTX_PDECL                   /* %extra_context */
){
  int yygoto;                     /* The next state */
  YYACTIONTYPE yyact;             /* The next action */
  yyStackEntry *yymsp;            /* The top of the parser's stack */
  int yysize;                     /* Amount to pop the stack */
  BusmasterParserARG_FETCH
  (void)yyLookahead;
  (void)yyLookaheadToken;
  yymsp = yypParser->yytos;
#ifndef NDEBUG
  if( yyTraceFILE && yyruleno<(int)(sizeof(yyRuleName)/sizeof(yyRuleName[0])) ){
    yysize = yyRuleInfo[yyruleno].nrhs;
    if( yysize ){
      fprintf(yyTraceFILE, "%sReduce %d [%s], go to state %d.\n",
        yyTracePrompt,
        yyruleno, yyRuleName[yyruleno], yymsp[yysize].stateno);
    }else{
      fprintf(yyTraceFILE, "%sReduce %d [%s].\n",
        yyTracePrompt, yyruleno, yyRuleName[yyruleno]);
    }
  }
#endif /* NDEBUG */

  /* Check that the stack is large enough to grow by a single entry
  ** if the RHS of the rule is empty.  This ensures that there is room
  ** enough on the stack to push the LHS value */
  if( yyRuleInfo[yyruleno].nrhs==0 ){
#ifdef YYTRACKMAXSTACKDEPTH
    if( (int)(yypParser->yytos - yypParser->yystack)>yypParser->yyhwm ){
      yypParser->yyhwm++;
      assert( yypParser->yyhwm == (int)(yypParser->yytos - yypParser->yystack));
    }
#endif
#if YYSTACKDEPTH>0
    if( yypParser->yytos>=yypParser->yystackEnd ){
      yyStackOverflow(yypParser);
      /* The call to yyStackOverflow() above pops the stack until it is
      ** empty, causing the main parser loop to exit.  So the return value
      ** is never used and does not matter. */
      return 0;
    }
#else
    if( yypParser->yytos>=&yypParser->yystack[yypParser->yystksz-1] ){
      if( yyGrowStack(yypParser) ){
        yyStackOverflow(yypParser);
        /* The call to yyStackOverflow() above pops the stack until it is
        ** empty, causing the main parser loop to exit.  So the return value
        ** is never used and does not matter. */
        return 0;
      }
      yymsp = yypParser->yytos;
    }
#endif
  }

  switch( yyruleno ){
  /* Beginning here are the reduction cases.  A typical example
  ** follows:
  **   case 0:
  **  #line <lineno> <grammarfile>
  **     { ... }           // User supplied code
  **  #line <lineno> <thisfile>
  **     break;
  */
/********** Begin reduce actions **********************************************/
        YYMINORTYPE yylhsminor;
      case 0: /* empty_line ::= */
#line 137 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    busmaster_debug_printf("%s: EMPTY\n", G_STRFUNC);
    state->entry_type = LOG_ENTRY_EMPTY;
}
#line 1154 "./busmaster_parser.c"
        break;
      case 1: /* footer_and_header ::= footer ENDL header */
#line 143 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    busmaster_debug_printf("%s: FOOTER AND HEADER\n", G_STRFUNC);
    state->entry_type = LOG_ENTRY_FOOTER_AND_HEADER;
}
#line 1162 "./busmaster_parser.c"
  yy_destructor(yypParser,3,&yymsp[-1].minor);
        break;
      case 2: /* header ::= version ENDL maybe_lines PROTOCOL_TYPE ENDL maybe_lines START_SESSION ENDL maybe_lines start_time ENDL maybe_lines DATA_MODE ENDL maybe_lines TIME_MODE ENDL anything */
#line 154 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    busmaster_debug_printf("%s: HEADER\n", G_STRFUNC);

    state->entry_type        = LOG_ENTRY_HEADER;
    state->header.start_date = yymsp[-8].minor.yy80.date;
    state->header.start_time = yymsp[-8].minor.yy80.time;
    state->header.protocol   = (protocol_t)yymsp[-14].minor.yy0.v0;
    state->header.data_mode  = (data_mode_t)yymsp[-5].minor.yy0.v0;
    state->header.time_mode  = (time_mode_t)yymsp[-2].minor.yy0.v0;
}
#line 1177 "./busmaster_parser.c"
  yy_destructor(yypParser,3,&yymsp[-16].minor);
  yy_destructor(yypParser,3,&yymsp[-13].minor);
  yy_destructor(yypParser,5,&yymsp[-11].minor);
  yy_destructor(yypParser,3,&yymsp[-10].minor);
  yy_destructor(yypParser,3,&yymsp[-7].minor);
  yy_destructor(yypParser,3,&yymsp[-4].minor);
  yy_destructor(yypParser,3,&yymsp[-1].minor);
        break;
      case 3: /* start_time ::= START_TIME ref_date ref_time */
{  yy_destructor(yypParser,10,&yymsp[-2].minor);
#line 178 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    yymsp[-2].minor.yy80.date = yymsp[-1].minor.yy74;
    yymsp[-2].minor.yy80.time = yymsp[0].minor.yy63;
}
#line 1193 "./busmaster_parser.c"
}
        break;
      case 4: /* footer ::= end_time ENDL STOP_SESSION */
#line 184 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    busmaster_debug_printf("%s: FOOTER\n", G_STRFUNC);
    state->entry_type = LOG_ENTRY_FOOTER;
}
#line 1202 "./busmaster_parser.c"
  yy_destructor(yypParser,3,&yymsp[-1].minor);
  yy_destructor(yypParser,11,&yymsp[0].minor);
        break;
      case 5: /* msg ::= msg_time MSG_DIR INT msg_id msg_type msg_length data */
#line 193 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    msg_t msg;

    /* DLC is always in DEC mode, thus we need to fix the value
     * if it was read initially as HEX. */
    if (state->header.data_mode == DATA_MODE_HEX)
    {
        yymsp[-1].minor.yy2 = (yymsp[-1].minor.yy2 / 16) * 10 + (yymsp[-1].minor.yy2 % 16);
    }

    /* Fix data in RTR frames. Data may not be present,
     * but length field is set. */
    if (yymsp[-2].minor.yy32 == MSG_TYPE_STD_RTR ||
        yymsp[-2].minor.yy32 == MSG_TYPE_EXT_RTR)
    {
        memset(&yymsp[0].minor.yy48, 0, sizeof(yymsp[0].minor.yy48));
        yymsp[0].minor.yy48.length = yymsp[-1].minor.yy2;
    }

    msg.timestamp = yymsp[-6].minor.yy63;
    msg.id        = yymsp[-3].minor.yy113;
    msg.type      = yymsp[-2].minor.yy32;
    msg.data      = yymsp[0].minor.yy48;

    busmaster_debug_printf("%s: MSG\n", G_STRFUNC);

    state->msg = msg;
    state->entry_type = LOG_ENTRY_MSG;
}
#line 1237 "./busmaster_parser.c"
  yy_destructor(yypParser,13,&yymsp[-5].minor);
  yy_destructor(yypParser,14,&yymsp[-4].minor);
        break;
      case 6: /* err_msg ::= msg_time MSG_DIR INT INT err_msg_type */
#line 225 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    msg_t msg;

    msg.timestamp   = yymsp[-4].minor.yy63;
    msg.id          = 0;
    msg.type        = yymsp[0].minor.yy32;
    msg.data.length = CAN_MAX_DLEN;

    memset(msg.data.data, 0, sizeof(msg.data.data));

    busmaster_debug_printf("%s: ERR MSG\n", G_STRFUNC);

    state->msg = msg;
    state->entry_type = LOG_ENTRY_MSG;
}
#line 1258 "./busmaster_parser.c"
  yy_destructor(yypParser,13,&yymsp[-3].minor);
  yy_destructor(yypParser,14,&yymsp[-2].minor);
  yy_destructor(yypParser,14,&yymsp[-1].minor);
        break;
      case 7: /* j1939_msg ::= msg_time INT msg_id INT J1939_MSG_TYPE INT INT INT MSG_DIR msg_length data */
#line 243 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    msg_t msg;

    msg.timestamp = yymsp[-10].minor.yy63;
    msg.id        = yymsp[-8].minor.yy113;
    msg.type      = MSG_TYPE_EXT;
    msg.data      = yymsp[0].minor.yy48;

    busmaster_debug_printf("%s: J1939 MSG\n", G_STRFUNC);

    state->msg = msg;
    state->entry_type = LOG_ENTRY_MSG;
}
#line 1278 "./busmaster_parser.c"
  yy_destructor(yypParser,14,&yymsp[-9].minor);
  yy_destructor(yypParser,14,&yymsp[-7].minor);
  yy_destructor(yypParser,15,&yymsp[-6].minor);
  yy_destructor(yypParser,14,&yymsp[-5].minor);
  yy_destructor(yypParser,14,&yymsp[-4].minor);
  yy_destructor(yypParser,14,&yymsp[-3].minor);
  yy_destructor(yypParser,13,&yymsp[-2].minor);
        break;
      case 8: /* ref_date ::= INT COLON INT COLON INT */
#line 258 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    yylhsminor.yy74.year  = (guint)yymsp[0].minor.yy0.v0;
    yylhsminor.yy74.month = (guint)yymsp[-2].minor.yy0.v0;
    yylhsminor.yy74.day   = (guint)yymsp[-4].minor.yy0.v0;
}
#line 1294 "./busmaster_parser.c"
  yy_destructor(yypParser,16,&yymsp[-3].minor);
  yy_destructor(yypParser,16,&yymsp[-1].minor);
  yymsp[-4].minor.yy74 = yylhsminor.yy74;
        break;
      case 9: /* ref_time ::= INT COLON INT COLON INT COLON INT */
#line 265 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    yylhsminor.yy63.hours   = (guint)yymsp[-6].minor.yy0.v0;
    yylhsminor.yy63.minutes = (guint)yymsp[-4].minor.yy0.v0;
    yylhsminor.yy63.seconds = (guint)yymsp[-2].minor.yy0.v0;
    yylhsminor.yy63.micros  = (guint)yymsp[0].minor.yy0.v0 * 1000;
}
#line 1307 "./busmaster_parser.c"
  yy_destructor(yypParser,16,&yymsp[-5].minor);
  yy_destructor(yypParser,16,&yymsp[-3].minor);
  yy_destructor(yypParser,16,&yymsp[-1].minor);
  yymsp[-6].minor.yy63 = yylhsminor.yy63;
        break;
      case 10: /* msg_time ::= MSG_TIME */
#line 273 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    yylhsminor.yy63.hours   = (guint)yymsp[0].minor.yy0.v0;
    yylhsminor.yy63.minutes = (guint)yymsp[0].minor.yy0.v1;
    yylhsminor.yy63.seconds = (guint)yymsp[0].minor.yy0.v2;
    yylhsminor.yy63.micros  = (guint)yymsp[0].minor.yy0.v3 * 100;
}
#line 1321 "./busmaster_parser.c"
  yymsp[0].minor.yy63 = yylhsminor.yy63;
        break;
      case 11: /* msg_id ::= INT */
#line 281 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    yylhsminor.yy113 = (guint)yymsp[0].minor.yy0.v0;
}
#line 1329 "./busmaster_parser.c"
  yymsp[0].minor.yy113 = yylhsminor.yy113;
        break;
      case 12: /* msg_length ::= INT */
#line 286 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    yylhsminor.yy2 = (guint)yymsp[0].minor.yy0.v0;
}
#line 1337 "./busmaster_parser.c"
  yymsp[0].minor.yy2 = yylhsminor.yy2;
        break;
      case 13: /* msg_type ::= MSG_TYPE */
      case 14: /* err_msg_type ::= ERR_MSG_TYPE */ yytestcase(yyruleno==14);
#line 291 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    yylhsminor.yy32 = (msg_type_t)yymsp[0].minor.yy0.v0;
}
#line 1346 "./busmaster_parser.c"
  yymsp[0].minor.yy32 = yylhsminor.yy32;
        break;
      case 15: /* data ::= data0 */
      case 16: /* data ::= data1 */ yytestcase(yyruleno==16);
      case 17: /* data ::= data2 */ yytestcase(yyruleno==17);
      case 18: /* data ::= data3 */ yytestcase(yyruleno==18);
      case 19: /* data ::= data4 */ yytestcase(yyruleno==19);
      case 20: /* data ::= data5 */ yytestcase(yyruleno==20);
      case 21: /* data ::= data6 */ yytestcase(yyruleno==21);
      case 22: /* data ::= data7 */ yytestcase(yyruleno==22);
      case 23: /* data ::= data8 */ yytestcase(yyruleno==23);
      case 24: /* data ::= data12 */ yytestcase(yyruleno==24);
      case 25: /* data ::= data16 */ yytestcase(yyruleno==25);
      case 26: /* data ::= data20 */ yytestcase(yyruleno==26);
      case 27: /* data ::= data24 */ yytestcase(yyruleno==27);
      case 28: /* data ::= data32 */ yytestcase(yyruleno==28);
      case 29: /* data ::= data48 */ yytestcase(yyruleno==29);
      case 30: /* data ::= data64 */ yytestcase(yyruleno==30);
#line 300 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{ yylhsminor.yy48 = yymsp[0].minor.yy48; }
#line 1367 "./busmaster_parser.c"
  yymsp[0].minor.yy48 = yylhsminor.yy48;
        break;
      case 31: /* byte ::= INT */
#line 318 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    yylhsminor.yy72 = (guint8)yymsp[0].minor.yy0.v0;
}
#line 1375 "./busmaster_parser.c"
  yymsp[0].minor.yy72 = yylhsminor.yy72;
        break;
      case 32: /* data0 ::= */
#line 323 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    yymsp[1].minor.yy48.length = 0;
}
#line 1383 "./busmaster_parser.c"
        break;
      case 33: /* data1 ::= byte */
#line 328 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    yylhsminor.yy48.length  = 1;
    yylhsminor.yy48.data[0] = yymsp[0].minor.yy72;
}
#line 1391 "./busmaster_parser.c"
  yymsp[0].minor.yy48 = yylhsminor.yy48;
        break;
      case 34: /* data2 ::= byte byte */
#line 334 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    yylhsminor.yy48.length  = 2;
    yylhsminor.yy48.data[0] = yymsp[-1].minor.yy72;
    yylhsminor.yy48.data[1] = yymsp[0].minor.yy72;
}
#line 1401 "./busmaster_parser.c"
  yymsp[-1].minor.yy48 = yylhsminor.yy48;
        break;
      case 35: /* data3 ::= byte byte byte */
#line 341 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    yylhsminor.yy48.length  = 3;
    yylhsminor.yy48.data[0] = yymsp[-2].minor.yy72;
    yylhsminor.yy48.data[1] = yymsp[-1].minor.yy72;
    yylhsminor.yy48.data[2] = yymsp[0].minor.yy72;
}
#line 1412 "./busmaster_parser.c"
  yymsp[-2].minor.yy48 = yylhsminor.yy48;
        break;
      case 36: /* data4 ::= byte byte byte byte */
#line 349 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
    yylhsminor.yy48.length  = 4;
    yylhsminor.yy48.data[0] = yymsp[-3].minor.yy72;
    yylhsminor.yy48.data[1] = yymsp[-2].minor.yy72;
    yylhsminor.yy48.data[2] = yymsp[-1].minor.yy72;
    yylhsminor.yy48.data[3] = yymsp[0].minor.yy72;
}
#line 1424 "./busmaster_parser.c"
  yymsp[-3].minor.yy48 = yylhsminor.yy48;
        break;
      case 37: /* data5 ::= data4 data1 */
      case 38: /* data6 ::= data4 data2 */ yytestcase(yyruleno==38);
      case 39: /* data7 ::= data4 data3 */ yytestcase(yyruleno==39);
      case 40: /* data8 ::= data4 data4 */ yytestcase(yyruleno==40);
      case 41: /* data12 ::= data8 data4 */ yytestcase(yyruleno==41);
      case 42: /* data16 ::= data8 data8 */ yytestcase(yyruleno==42);
      case 43: /* data20 ::= data16 data4 */ yytestcase(yyruleno==43);
      case 44: /* data24 ::= data16 data8 */ yytestcase(yyruleno==44);
      case 45: /* data32 ::= data16 data16 */ yytestcase(yyruleno==45);
      case 46: /* data48 ::= data32 data16 */ yytestcase(yyruleno==46);
      case 47: /* data64 ::= data32 data32 */ yytestcase(yyruleno==47);
#line 357 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{ merge_msg_data(&yylhsminor.yy48, &yymsp[-1].minor.yy48, &yymsp[0].minor.yy48); }
#line 1440 "./busmaster_parser.c"
  yymsp[-1].minor.yy48 = yylhsminor.yy48;
        break;
      case 55: /* version ::= HEADER_VER maybe_chars */
{  yy_destructor(yypParser,8,&yymsp[-1].minor);
#line 165 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
}
#line 1448 "./busmaster_parser.c"
}
        break;
      case 57: /* maybe_chars ::= maybe_chars HEADER_CHAR */
      case 61: /* anything ::= anything HEADER_CHAR */ yytestcase(yyruleno==61);
#line 168 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
}
#line 1456 "./busmaster_parser.c"
  yy_destructor(yypParser,9,&yymsp[0].minor);
        break;
      case 59: /* maybe_lines ::= maybe_lines maybe_chars ENDL */
      case 62: /* anything ::= anything ENDL */ yytestcase(yyruleno==62);
#line 171 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
}
#line 1464 "./busmaster_parser.c"
  yy_destructor(yypParser,3,&yymsp[0].minor);
        break;
      case 63: /* end_time ::= END_TIME ref_date ref_time */
{  yy_destructor(yypParser,12,&yymsp[-2].minor);
#line 189 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"
{
}
#line 1472 "./busmaster_parser.c"
}
        break;
      default:
      /* (48) entry ::= empty_line */ yytestcase(yyruleno==48);
      /* (49) entry ::= footer_and_header */ yytestcase(yyruleno==49);
      /* (50) entry ::= header */ yytestcase(yyruleno==50);
      /* (51) entry ::= footer */ yytestcase(yyruleno==51);
      /* (52) entry ::= msg */ yytestcase(yyruleno==52);
      /* (53) entry ::= err_msg */ yytestcase(yyruleno==53);
      /* (54) entry ::= j1939_msg */ yytestcase(yyruleno==54);
      /* (56) maybe_chars ::= */ yytestcase(yyruleno==56);
      /* (58) maybe_lines ::= */ yytestcase(yyruleno==58);
      /* (60) anything ::= */ yytestcase(yyruleno==60);
        break;
/********** End reduce actions ************************************************/
  };
  assert( yyruleno<sizeof(yyRuleInfo)/sizeof(yyRuleInfo[0]) );
  yygoto = yyRuleInfo[yyruleno].lhs;
  yysize = yyRuleInfo[yyruleno].nrhs;
  yyact = yy_find_reduce_action(yymsp[yysize].stateno,(YYCODETYPE)yygoto);

  /* There are no SHIFTREDUCE actions on nonterminals because the table
  ** generator has simplified them to pure REDUCE actions. */
  assert( !(yyact>YY_MAX_SHIFT && yyact<=YY_MAX_SHIFTREDUCE) );

  /* It is not possible for a REDUCE to be followed by an error */
  assert( yyact!=YY_ERROR_ACTION );

  yymsp += yysize+1;
  yypParser->yytos = yymsp;
  yymsp->stateno = (YYACTIONTYPE)yyact;
  yymsp->major = (YYCODETYPE)yygoto;
  yyTraceShift(yypParser, yyact, "... then shift");
  return yyact;
}

/*
** The following code executes when the parse fails
*/
#ifndef YYNOERRORRECOVERY
static void yy_parse_failed(
  yyParser *yypParser           /* The parser */
){
  BusmasterParserARG_FETCH
  BusmasterParserCTX_FETCH
#ifndef NDEBUG
  if( yyTraceFILE ){
    fprintf(yyTraceFILE,"%sFail!\n",yyTracePrompt);
  }
#endif
  while( yypParser->yytos>yypParser->yystack ) yy_pop_parser_stack(yypParser);
  /* Here code is inserted which will be executed whenever the
  ** parser fails */
/************ Begin %parse_failure code ***************************************/
#line 78 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"

    g_free(state->parse_error);
    state->entry_type  = LOG_ENTRY_ERROR;
    state->parse_error = g_strdup("Parse Error");
    busmaster_debug_printf("%s: Parse Error\n", G_STRFUNC);
#line 1533 "./busmaster_parser.c"
/************ End %parse_failure code *****************************************/
  BusmasterParserARG_STORE /* Suppress warning about unused %extra_argument variable */
  BusmasterParserCTX_STORE
}
#endif /* YYNOERRORRECOVERY */

/*
** The following code executes when a syntax error first occurs.
*/
static void yy_syntax_error(
  yyParser *yypParser,           /* The parser */
  int yymajor _U_,               /* The major type of the error token */
  BusmasterParserTOKENTYPE yyminor         /* The minor type of the error token */
){
  BusmasterParserARG_FETCH
  BusmasterParserCTX_FETCH
#define TOKEN yyminor
/************ Begin %syntax_error code ****************************************/
#line 56 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"

    (void)yypParser;
    (void)yyminor;

#ifdef BUSMASTER_DEBUG
    const int n = sizeof(yyTokenName) / sizeof(yyTokenName[0]);
    busmaster_debug_printf("%s: got token: %s\n", G_STRFUNC, yyTokenName[yymajor]);
    for (int i = 0; i < n; ++i) {
        int a = yy_find_shift_action((YYCODETYPE)i, yypParser->yytos->stateno);
        if (a < YYNSTATE + YYNRULE) {
            busmaster_debug_printf("%s: possible token: %s\n", G_STRFUNC, yyTokenName[i]);
        }
    }
#endif

    g_free(state->parse_error);
    state->entry_type  = LOG_ENTRY_ERROR;
    state->parse_error = g_strdup_printf("Syntax Error");
    busmaster_debug_printf("%s: Syntax Error\n", G_STRFUNC);
#line 1572 "./busmaster_parser.c"
/************ End %syntax_error code ******************************************/
  BusmasterParserARG_STORE /* Suppress warning about unused %extra_argument variable */
  BusmasterParserCTX_STORE
}

/*
** The following is executed when the parser accepts
*/
static void yy_accept(
  yyParser *yypParser           /* The parser */
){
  BusmasterParserARG_FETCH
  BusmasterParserCTX_FETCH
#ifndef NDEBUG
  if( yyTraceFILE ){
    fprintf(yyTraceFILE,"%sAccept!\n",yyTracePrompt);
  }
#endif
#ifndef YYNOERRORRECOVERY
  yypParser->yyerrcnt = -1;
#endif
  assert( yypParser->yytos==yypParser->yystack );
  /* Here code is inserted which will be executed whenever the
  ** parser accepts */
/*********** Begin %parse_accept code *****************************************/
/*********** End %parse_accept code *******************************************/
  BusmasterParserARG_STORE /* Suppress warning about unused %extra_argument variable */
  BusmasterParserCTX_STORE
}

/* The main parser program.
** The first argument is a pointer to a structure obtained from
** "BusmasterParserAlloc" which describes the current state of the parser.
** The second argument is the major token number.  The third is
** the minor token.  The fourth optional argument is whatever the
** user wants (and specified in the grammar) and is available for
** use by the action routines.
**
** Inputs:
** <ul>
** <li> A pointer to the parser (an opaque structure.)
** <li> The major token number.
** <li> The minor token number.
** <li> An option argument of a grammar-specified type.
** </ul>
**
** Outputs:
** None.
*/
void BusmasterParser(
  void *yyp,                   /* The parser */
  int yymajor,                 /* The major token code number */
  BusmasterParserTOKENTYPE yyminor       /* The value for the token */
  BusmasterParserARG_PDECL               /* Optional %extra_argument parameter */
){
  YYMINORTYPE yyminorunion;
  YYACTIONTYPE yyact;   /* The parser action. */
#if !defined(YYERRORSYMBOL) && !defined(YYNOERRORRECOVERY)
  int yyendofinput;     /* True if we are at the end of input */
#endif
#ifdef YYERRORSYMBOL
  int yyerrorhit = 0;   /* True if yymajor has invoked an error */
#endif
  yyParser *yypParser = (yyParser*)yyp;  /* The parser */
  BusmasterParserCTX_FETCH
  BusmasterParserARG_STORE

  assert( yypParser->yytos!=0 );
#if !defined(YYERRORSYMBOL) && !defined(YYNOERRORRECOVERY)
  yyendofinput = (yymajor==0);
#endif

  yyact = yypParser->yytos->stateno;
#ifndef NDEBUG
  if( yyTraceFILE ){
    if( yyact < YY_MIN_REDUCE ){
      fprintf(yyTraceFILE,"%sInput '%s' in state %d\n",
              yyTracePrompt,yyTokenName[yymajor],yyact);
    }else{
      fprintf(yyTraceFILE,"%sInput '%s' with pending reduce %d\n",
              yyTracePrompt,yyTokenName[yymajor],yyact-YY_MIN_REDUCE);
    }
  }
#endif

  do{
    assert( yyact==yypParser->yytos->stateno );
    yyact = yy_find_shift_action((YYCODETYPE)yymajor,yyact);
    if( yyact >= YY_MIN_REDUCE ){
      yyact = yy_reduce(yypParser,yyact-YY_MIN_REDUCE,yymajor,
                        yyminor BusmasterParserCTX_PARAM);
    }else if( yyact <= YY_MAX_SHIFTREDUCE ){
      yy_shift(yypParser,yyact,(YYCODETYPE)yymajor,yyminor);
#ifndef YYNOERRORRECOVERY
      yypParser->yyerrcnt--;
#endif
      break;
    }else if( yyact==YY_ACCEPT_ACTION ){
      yypParser->yytos--;
      yy_accept(yypParser);
      return;
    }else{
      assert( yyact == YY_ERROR_ACTION );
      yyminorunion.yy0 = yyminor;
#ifdef YYERRORSYMBOL
      int yymx;
#endif
#ifndef NDEBUG
      if( yyTraceFILE ){
        fprintf(yyTraceFILE,"%sSyntax Error!\n",yyTracePrompt);
      }
#endif
#ifdef YYERRORSYMBOL
      /* A syntax error has occurred.
      ** The response to an error depends upon whether or not the
      ** grammar defines an error token "ERROR".
      **
      ** This is what we do if the grammar does define ERROR:
      **
      **  * Call the %syntax_error function.
      **
      **  * Begin popping the stack until we enter a state where
      **    it is legal to shift the error symbol, then shift
      **    the error symbol.
      **
      **  * Set the error count to three.
      **
      **  * Begin accepting and shifting new tokens.  No new error
      **    processing will occur until three tokens have been
      **    shifted successfully.
      **
      */
      if( yypParser->yyerrcnt<0 ){
        yy_syntax_error(yypParser,yymajor,yyminor);
      }
      yymx = yypParser->yytos->major;
      if( yymx==YYERRORSYMBOL || yyerrorhit ){
#ifndef NDEBUG
        if( yyTraceFILE ){
          fprintf(yyTraceFILE,"%sDiscard input token %s\n",
             yyTracePrompt,yyTokenName[yymajor]);
        }
#endif
        yy_destructor(yypParser, (YYCODETYPE)yymajor, &yyminorunion);
        yymajor = YYNOCODE;
      }else{
        while( yypParser->yytos >= yypParser->yystack
            && yymx != YYERRORSYMBOL
            && (yyact = yy_find_reduce_action(
                        yypParser->yytos->stateno,
                        YYERRORSYMBOL)) >= YY_MIN_REDUCE
        ){
          yy_pop_parser_stack(yypParser);
        }
        if( yypParser->yytos < yypParser->yystack || yymajor==0 ){
          yy_destructor(yypParser,(YYCODETYPE)yymajor,&yyminorunion);
          yy_parse_failed(yypParser);
#ifndef YYNOERRORRECOVERY
          yypParser->yyerrcnt = -1;
#endif
          yymajor = YYNOCODE;
        }else if( yymx!=YYERRORSYMBOL ){
          yy_shift(yypParser,yyact,YYERRORSYMBOL,yyminor);
        }
      }
      yypParser->yyerrcnt = 3;
      yyerrorhit = 1;
      if( yymajor==YYNOCODE ) break;
      yyact = yypParser->yytos->stateno;
#elif defined(YYNOERRORRECOVERY)
      /* If the YYNOERRORRECOVERY macro is defined, then do not attempt to
      ** do any kind of error recovery.  Instead, simply invoke the syntax
      ** error routine and continue going as if nothing had happened.
      **
      ** Applications can set this macro (for example inside %include) if
      ** they intend to abandon the parse upon the first syntax error seen.
      */
      yy_syntax_error(yypParser,yymajor, yyminor);
      yy_destructor(yypParser,(YYCODETYPE)yymajor,&yyminorunion);
      break;
#else  /* YYERRORSYMBOL is not defined */
      /* This is what we do if the grammar does not define ERROR:
      **
      **  * Report an error message, and throw away the input token.
      **
      **  * If the input token is $, then fail the parse.
      **
      ** As before, subsequent error messages are suppressed until
      ** three input tokens have been successfully shifted.
      */
      if( yypParser->yyerrcnt<=0 ){
        yy_syntax_error(yypParser,yymajor, yyminor);
      }
      yypParser->yyerrcnt = 3;
      yy_destructor(yypParser,(YYCODETYPE)yymajor,&yyminorunion);
      if( yyendofinput ){
        yy_parse_failed(yypParser);
#ifndef YYNOERRORRECOVERY
        yypParser->yyerrcnt = -1;
#endif
      }
      break;
#endif
    }
  }while( yypParser->yytos>yypParser->yystack );
#ifndef NDEBUG
  if( yyTraceFILE ){
    yyStackEntry *i;
    char cDiv = '[';
    fprintf(yyTraceFILE,"%sReturn. Stack=",yyTracePrompt);
    for(i=&yypParser->yystack[1]; i<=yypParser->yytos; i++){
      fprintf(yyTraceFILE,"%c%s", cDiv, yyTokenName[i->major]);
      cDiv = ' ';
    }
    fprintf(yyTraceFILE,"]\n");
  }
#endif
  return;
}

#if 0
/*
** Return the fallback token corresponding to canonical token iToken, or
** 0 if iToken has no fallback.
*/
int BusmasterParserFallback(int iToken){
#ifdef YYFALLBACK
  if( iToken<(int)(sizeof(yyFallback)/sizeof(yyFallback[0])) ){
    return yyFallback[iToken];
  }
#else
  (void)iToken;
#endif
  return 0;
}
#endif
#line 369 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/busmaster_parser.lemon"


DIAG_ON(unreachable-code)

#include "busmaster_scanner_lex.h"
#include "busmaster_parser.h"

gboolean
run_busmaster_parser(busmaster_state_t *state,
                     int               *err, gchar **err_info)
{
    int       lex_code;
    yyscan_t  scanner;
    void     *parser;

    state->entry_type  = LOG_ENTRY_NONE;
    state->parse_error = NULL;
    state->err         = 0;
    state->err_info    = NULL;

    if (busmaster_lex_init_extra(state, &scanner) != 0)
    {
        *err      = errno;
        *err_info = g_strdup(g_strerror(errno));
        return FALSE;
    }

    parser = BusmasterParserAlloc(g_malloc);

#ifdef BUSMASTER_PARSER_TRACE
    BusmasterParserTrace(stdout, "BusmasterParser >> ");
#endif

    busmaster_debug_printf("%s: Starting parsing of the line\n", G_STRFUNC);

    do
    {
        lex_code = busmaster_lex(scanner);

#ifdef BUSMASTER_DEBUG
        if (lex_code)
            busmaster_debug_printf("%s: Feeding %s '%s'\n",
                                   G_STRFUNC, yyTokenName[lex_code],
                                   busmaster_get_text(scanner));
        else
            busmaster_debug_printf("%s: Feeding %s\n",
                                   G_STRFUNC, yyTokenName[lex_code]);
#endif

        BusmasterParser(parser, lex_code, state->token, state);

        if (state->err || state->err_info || state->parse_error)
            break;
    }
    while (lex_code);

    busmaster_debug_printf("%s: Done (%d)\n", G_STRFUNC, lex_code);

    BusmasterParserFree(parser, g_free);
    busmaster_lex_destroy(scanner);

    if (state->err || state->err_info || state->parse_error)
    {
        if (state->err_info)
        {
            *err_info = state->err_info;
            g_free(state->parse_error);
        }
        else
        {
            *err_info = state->parse_error;
        }

        if (state->err)
            *err = state->err;
        else
            *err = WTAP_ERR_BAD_FILE;

        return FALSE;
    }

    return TRUE;
}

#line 1894 "./busmaster_parser.c"
