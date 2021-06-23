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
#line 1 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"


/* candump_parser.lemon
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for candump log file format
 * Copyright (c) 2019 by Maksim Salau <maksim.salau@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <assert.h>
#include <string.h>
#include <wiretap/file_wrappers.h>
#include "candump_priv.h"

extern void *CandumpParserAlloc(void *(*mallocProc)(size_t));
extern void CandumpParser(void *yyp, int yymajor, token_t yyminor, candump_state_t *state);
extern void CandumpParserFree(void *p, void (*freeProc)(void*));

#ifdef CANDUMP_DEBUG
extern void CandumpParserTrace(FILE *TraceFILE, char *zTracePrompt);
#endif

static void merge_msg_data(msg_data_t *dst, const msg_data_t *a, const msg_data_t *b)
{
    dst->length = a->length + b->length;
    memcpy(&dst->data[0], &a->data[0], a->length);
    memcpy(&dst->data[a->length], &b->data[0], b->length);
}

DIAG_OFF(unreachable-code)

#line 64 "./candump_parser.c"
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
**    CandumpParserTOKENTYPE     is the data type used for minor type for terminal
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
**                       which is CandumpParserTOKENTYPE.  The entry in the union
**                       for terminal symbols is called "yy0".
**    YYSTACKDEPTH       is the maximum depth of the parser's stack.  If
**                       zero the stack is dynamically sized using realloc()
**    CandumpParserARG_SDECL     A static variable declaration for the %extra_argument
**    CandumpParserARG_PDECL     A parameter declaration for the %extra_argument
**    CandumpParserARG_PARAM     Code to pass %extra_argument as a subroutine parameter
**    CandumpParserARG_STORE     Code to store %extra_argument into yypParser
**    CandumpParserARG_FETCH     Code to extract %extra_argument from yypParser
**    CandumpParserCTX_*         As CandumpParserARG_ except for %extra_context
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
#define YYNOCODE 36
#define YYACTIONTYPE unsigned char
#define CandumpParserTOKENTYPE  token_t 
typedef union {
  int yyinit;
  CandumpParserTOKENTYPE yy0;
  msg_t yy11;
  guint32 yy13;
  msg_data_t yy16;
  nstime_t yy60;
  guint8 yy64;
} YYMINORTYPE;
#ifndef YYSTACKDEPTH
#define YYSTACKDEPTH 100
#endif
#define CandumpParserARG_SDECL  candump_state_t* state ;
#define CandumpParserARG_PDECL , candump_state_t* state 
#define CandumpParserARG_PARAM ,state 
#define CandumpParserARG_FETCH  candump_state_t* state =yypParser->state ;
#define CandumpParserARG_STORE yypParser->state =state ;
#define CandumpParserCTX_SDECL
#define CandumpParserCTX_PDECL
#define CandumpParserCTX_PARAM
#define CandumpParserCTX_FETCH
#define CandumpParserCTX_STORE
#define YYNSTATE             25
#define YYNRULE              54
#define YYNTOKEN             9
#define YY_MAX_SHIFT         24
#define YY_MIN_SHIFTREDUCE   65
#define YY_MAX_SHIFTREDUCE   118
#define YY_ERROR_ACTION      119
#define YY_ACCEPT_ACTION     120
#define YY_NO_ACTION         121
#define YY_MIN_REDUCE        122
#define YY_MAX_REDUCE        175
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
#define YY_ACTTAB_COUNT (97)
static const YYACTIONTYPE yy_action[] = {
 /*     0 */    22,  126,  126,  126,  126,  126,  126,    4,  126,  126,
 /*    10 */   126,    9,  126,    6,  126,  126,    3,  126,  126,    1,
 /*    20 */    22,  125,   74,  125,  125,  125,  125,    4,  125,  125,
 /*    30 */   125,  125,   16,   96,  100,   95,   97,   98,   99,  101,
 /*    40 */    96,  100,   95,   97,   98,   99,  101,   19,   19,  120,
 /*    50 */    11,  150,   15,   15,   12,   12,   24,   23,    7,  142,
 /*    60 */     5,   22,   19,  147,    2,  137,  138,  139,  140,   14,
 /*    70 */   136,   67,   19,  142,   19,   19,   73,   74,   17,   12,
 /*    80 */    18,  140,   13,    7,   20,  145,    8,   21,  145,  123,
 /*    90 */    91,  122,   70,  121,   10,   71,   72,
};
static const YYCODETYPE yy_lookahead[] = {
 /*     0 */    13,   14,   15,   16,   17,   18,   19,   20,   21,   22,
 /*    10 */    23,   24,   25,   26,   27,   28,   29,   30,   31,   12,
 /*    20 */    13,   14,    8,   16,   17,   18,   19,   20,   21,   22,
 /*    30 */    23,   24,    1,    2,    3,    4,    5,    6,    7,    8,
 /*    40 */     2,    3,    4,    5,    6,    7,    8,   13,   13,   32,
 /*    50 */    33,   35,   34,   35,   20,   20,    9,   10,   24,   24,
 /*    60 */    26,   13,   13,   29,   11,   17,   18,   19,   20,   20,
 /*    70 */    13,    2,   13,   24,   13,   13,    7,    8,   13,   20,
 /*    80 */    13,   20,   20,   24,   13,   26,   24,   13,   26,    0,
 /*    90 */     1,    0,    3,   36,    1,    5,    6,   36,   36,   36,
 /*   100 */    36,   36,   36,   36,   36,
};
#define YY_SHIFT_COUNT    (24)
#define YY_SHIFT_MIN      (0)
#define YY_SHIFT_MAX      (93)
static const unsigned char yy_shift_ofst[] = {
 /*     0 */    97,   14,   69,   14,   14,   14,   14,   14,   14,   14,
 /*    10 */    38,   89,   14,   14,   14,   31,   90,   14,   14,   14,
 /*    20 */    14,   14,   14,   93,   91,
};
#define YY_REDUCE_COUNT (22)
#define YY_REDUCE_MIN   (-13)
#define YY_REDUCE_MAX   (74)
static const signed char yy_reduce_ofst[] = {
 /*     0 */    17,  -13,    7,   34,   48,   59,   62,   35,   35,   49,
 /*    10 */    18,   47,   61,   61,   61,   16,   53,   57,   65,   67,
 /*    20 */    57,   71,   74,
};
static const YYACTIONTYPE yy_default[] = {
 /*     0 */   149,  132,  132,  173,  163,  146,  170,  119,  144,  167,
 /*    10 */   119,  119,  119,  143,  141,  119,  119,  119,  119,  119,
 /*    20 */   135,  134,  133,  119,  119,
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
  CandumpParserARG_SDECL                /* A place to hold %extra_argument */
  CandumpParserCTX_SDECL                /* A place to hold %extra_context */
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
void CandumpParserTrace(FILE *TraceFILE, char *zTracePrompt){
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
  /*    1 */ "SPACE",
  /*    2 */ "RTR",
  /*    3 */ "TIMESTAMP",
  /*    4 */ "UNKNOWN",
  /*    5 */ "STD_ID",
  /*    6 */ "EXT_ID",
  /*    7 */ "FLAGS",
  /*    8 */ "BYTE",
  /*    9 */ "msg",
  /*   10 */ "timestamp",
  /*   11 */ "id",
  /*   12 */ "flags",
  /*   13 */ "byte",
  /*   14 */ "data_max_8",
  /*   15 */ "data_max_64",
  /*   16 */ "data0",
  /*   17 */ "data1",
  /*   18 */ "data2",
  /*   19 */ "data3",
  /*   20 */ "data4",
  /*   21 */ "data5",
  /*   22 */ "data6",
  /*   23 */ "data7",
  /*   24 */ "data8",
  /*   25 */ "data12",
  /*   26 */ "data16",
  /*   27 */ "data20",
  /*   28 */ "data24",
  /*   29 */ "data32",
  /*   30 */ "data48",
  /*   31 */ "data64",
  /*   32 */ "line",
  /*   33 */ "maybe_spaces",
  /*   34 */ "ifname",
  /*   35 */ "any",
};
#endif /* defined(YYCOVERAGE) || !defined(NDEBUG) */

#ifndef NDEBUG
/* For tracing reduce actions, the names of all rules are required.
*/
static const char *const yyRuleName[] = {
 /*   0 */ "line ::= maybe_spaces msg",
 /*   1 */ "line ::= maybe_spaces",
 /*   2 */ "msg ::= timestamp SPACE ifname SPACE id RTR",
 /*   3 */ "msg ::= timestamp SPACE ifname SPACE id data_max_8",
 /*   4 */ "msg ::= timestamp SPACE ifname SPACE id flags data_max_64",
 /*   5 */ "timestamp ::= TIMESTAMP",
 /*   6 */ "id ::= STD_ID",
 /*   7 */ "id ::= EXT_ID",
 /*   8 */ "flags ::= FLAGS",
 /*   9 */ "byte ::= BYTE",
 /*  10 */ "data0 ::=",
 /*  11 */ "data1 ::= byte",
 /*  12 */ "data2 ::= byte byte",
 /*  13 */ "data3 ::= byte byte byte",
 /*  14 */ "data4 ::= byte byte byte byte",
 /*  15 */ "data5 ::= data4 data1",
 /*  16 */ "data6 ::= data4 data2",
 /*  17 */ "data7 ::= data4 data3",
 /*  18 */ "data8 ::= data4 data4",
 /*  19 */ "data12 ::= data8 data4",
 /*  20 */ "data16 ::= data8 data8",
 /*  21 */ "data20 ::= data16 data4",
 /*  22 */ "data24 ::= data16 data8",
 /*  23 */ "data32 ::= data16 data16",
 /*  24 */ "data48 ::= data32 data16",
 /*  25 */ "data64 ::= data32 data32",
 /*  26 */ "maybe_spaces ::= maybe_spaces SPACE",
 /*  27 */ "maybe_spaces ::=",
 /*  28 */ "ifname ::= ifname any",
 /*  29 */ "ifname ::= any",
 /*  30 */ "any ::= UNKNOWN",
 /*  31 */ "any ::= RTR",
 /*  32 */ "any ::= STD_ID",
 /*  33 */ "any ::= EXT_ID",
 /*  34 */ "any ::= FLAGS",
 /*  35 */ "any ::= TIMESTAMP",
 /*  36 */ "any ::= BYTE",
 /*  37 */ "data_max_8 ::= data0",
 /*  38 */ "data_max_8 ::= data1",
 /*  39 */ "data_max_8 ::= data2",
 /*  40 */ "data_max_8 ::= data3",
 /*  41 */ "data_max_8 ::= data4",
 /*  42 */ "data_max_8 ::= data5",
 /*  43 */ "data_max_8 ::= data6",
 /*  44 */ "data_max_8 ::= data7",
 /*  45 */ "data_max_8 ::= data8",
 /*  46 */ "data_max_64 ::= data_max_8",
 /*  47 */ "data_max_64 ::= data12",
 /*  48 */ "data_max_64 ::= data16",
 /*  49 */ "data_max_64 ::= data20",
 /*  50 */ "data_max_64 ::= data24",
 /*  51 */ "data_max_64 ::= data32",
 /*  52 */ "data_max_64 ::= data48",
 /*  53 */ "data_max_64 ::= data64",
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
** second argument to CandumpParserAlloc() below.  This can be changed by
** putting an appropriate #define in the %include section of the input
** grammar.
*/
#ifndef YYMALLOCARGTYPE
# define YYMALLOCARGTYPE size_t
#endif

/* Initialize a new parser that has already been allocated.
*/
static void CandumpParserInit(void *yypRawParser CandumpParserCTX_PDECL){
  yyParser *yypParser = (yyParser*)yypRawParser;
  CandumpParserCTX_STORE
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

#ifndef CandumpParser_ENGINEALWAYSONSTACK
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
** to CandumpParser and CandumpParserFree.
*/
void *CandumpParserAlloc(void *(*mallocProc)(YYMALLOCARGTYPE) CandumpParserCTX_PDECL){
  yyParser *yypParser;
  yypParser = (yyParser*)(*mallocProc)( (YYMALLOCARGTYPE)sizeof(yyParser) );
  if( yypParser ){
    CandumpParserCTX_STORE
    CandumpParserInit(yypParser CandumpParserCTX_PARAM);
  }
  return (void*)yypParser;
}
#endif /* CandumpParser_ENGINEALWAYSONSTACK */


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
  CandumpParserARG_FETCH
  CandumpParserCTX_FETCH
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
    case 1: /* SPACE */
    case 2: /* RTR */
    case 3: /* TIMESTAMP */
    case 4: /* UNKNOWN */
    case 5: /* STD_ID */
    case 6: /* EXT_ID */
    case 7: /* FLAGS */
    case 8: /* BYTE */
{
#line 45 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"

    (void)state;
    (void)yypParser;
    (void)yypminor;

#line 620 "./candump_parser.c"
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
static void CandumpParserFinalize(void *p){
  yyParser *pParser = (yyParser*)p;
  while( pParser->yytos>pParser->yystack ) yy_pop_parser_stack(pParser);
#if YYSTACKDEPTH<=0
  if( pParser->yystack!=&pParser->yystk0 ) free(pParser->yystack);
#endif
}

#ifndef CandumpParser_ENGINEALWAYSONSTACK
/*
** Deallocate and destroy a parser.  Destructors are called for
** all stack elements before shutting the parser down.
**
** If the YYPARSEFREENEVERNULL macro exists (for example because it
** is defined in a %include section of the input grammar) then it is
** assumed that the input pointer is never NULL.
*/
void CandumpParserFree(
  void *p,                    /* The parser to be deleted */
  void (*freeProc)(void*)     /* Function used to reclaim memory */
){
#ifndef YYPARSEFREENEVERNULL
  if( p==0 ) return;
#endif
  CandumpParserFinalize(p);
  (*freeProc)(p);
}
#endif /* CandumpParser_ENGINEALWAYSONSTACK */

/*
** Return the peak depth of the stack for a parser.
*/
#ifdef YYTRACKMAXSTACKDEPTH
int CandumpParserStackPeak(void *p){
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
int CandumpParserCoverage(FILE *out){
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
   CandumpParserARG_FETCH
   CandumpParserCTX_FETCH
#ifndef NDEBUG
   if( yyTraceFILE ){
     fprintf(yyTraceFILE,"%sStack Overflow!\n",yyTracePrompt);
   }
#endif
   while( yypParser->yytos>yypParser->yystack ) yy_pop_parser_stack(yypParser);
   /* Here code is inserted which will execute if the parser
   ** stack every overflows */
/******** Begin %stack_overflow code ******************************************/
/******** End %stack_overflow code ********************************************/
   CandumpParserARG_STORE /* Suppress warning about unused %extra_argument var */
   CandumpParserCTX_STORE
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
  CandumpParserTOKENTYPE yyMinor        /* The minor token to shift in */
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
  {   32,   -2 }, /* (0) line ::= maybe_spaces msg */
  {   32,   -1 }, /* (1) line ::= maybe_spaces */
  {    9,   -6 }, /* (2) msg ::= timestamp SPACE ifname SPACE id RTR */
  {    9,   -6 }, /* (3) msg ::= timestamp SPACE ifname SPACE id data_max_8 */
  {    9,   -7 }, /* (4) msg ::= timestamp SPACE ifname SPACE id flags data_max_64 */
  {   10,   -1 }, /* (5) timestamp ::= TIMESTAMP */
  {   11,   -1 }, /* (6) id ::= STD_ID */
  {   11,   -1 }, /* (7) id ::= EXT_ID */
  {   12,   -1 }, /* (8) flags ::= FLAGS */
  {   13,   -1 }, /* (9) byte ::= BYTE */
  {   16,    0 }, /* (10) data0 ::= */
  {   17,   -1 }, /* (11) data1 ::= byte */
  {   18,   -2 }, /* (12) data2 ::= byte byte */
  {   19,   -3 }, /* (13) data3 ::= byte byte byte */
  {   20,   -4 }, /* (14) data4 ::= byte byte byte byte */
  {   21,   -2 }, /* (15) data5 ::= data4 data1 */
  {   22,   -2 }, /* (16) data6 ::= data4 data2 */
  {   23,   -2 }, /* (17) data7 ::= data4 data3 */
  {   24,   -2 }, /* (18) data8 ::= data4 data4 */
  {   25,   -2 }, /* (19) data12 ::= data8 data4 */
  {   26,   -2 }, /* (20) data16 ::= data8 data8 */
  {   27,   -2 }, /* (21) data20 ::= data16 data4 */
  {   28,   -2 }, /* (22) data24 ::= data16 data8 */
  {   29,   -2 }, /* (23) data32 ::= data16 data16 */
  {   30,   -2 }, /* (24) data48 ::= data32 data16 */
  {   31,   -2 }, /* (25) data64 ::= data32 data32 */
  {   33,   -2 }, /* (26) maybe_spaces ::= maybe_spaces SPACE */
  {   33,    0 }, /* (27) maybe_spaces ::= */
  {   34,   -2 }, /* (28) ifname ::= ifname any */
  {   34,   -1 }, /* (29) ifname ::= any */
  {   35,   -1 }, /* (30) any ::= UNKNOWN */
  {   35,   -1 }, /* (31) any ::= RTR */
  {   35,   -1 }, /* (32) any ::= STD_ID */
  {   35,   -1 }, /* (33) any ::= EXT_ID */
  {   35,   -1 }, /* (34) any ::= FLAGS */
  {   35,   -1 }, /* (35) any ::= TIMESTAMP */
  {   35,   -1 }, /* (36) any ::= BYTE */
  {   14,   -1 }, /* (37) data_max_8 ::= data0 */
  {   14,   -1 }, /* (38) data_max_8 ::= data1 */
  {   14,   -1 }, /* (39) data_max_8 ::= data2 */
  {   14,   -1 }, /* (40) data_max_8 ::= data3 */
  {   14,   -1 }, /* (41) data_max_8 ::= data4 */
  {   14,   -1 }, /* (42) data_max_8 ::= data5 */
  {   14,   -1 }, /* (43) data_max_8 ::= data6 */
  {   14,   -1 }, /* (44) data_max_8 ::= data7 */
  {   14,   -1 }, /* (45) data_max_8 ::= data8 */
  {   15,   -1 }, /* (46) data_max_64 ::= data_max_8 */
  {   15,   -1 }, /* (47) data_max_64 ::= data12 */
  {   15,   -1 }, /* (48) data_max_64 ::= data16 */
  {   15,   -1 }, /* (49) data_max_64 ::= data20 */
  {   15,   -1 }, /* (50) data_max_64 ::= data24 */
  {   15,   -1 }, /* (51) data_max_64 ::= data32 */
  {   15,   -1 }, /* (52) data_max_64 ::= data48 */
  {   15,   -1 }, /* (53) data_max_64 ::= data64 */
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
  CandumpParserTOKENTYPE yyLookaheadToken  /* Value of the lookahead token */
  CandumpParserCTX_PDECL                   /* %extra_context */
){
  int yygoto;                     /* The next state */
  YYACTIONTYPE yyact;             /* The next action */
  yyStackEntry *yymsp;            /* The top of the parser's stack */
  int yysize;                     /* Amount to pop the stack */
  CandumpParserARG_FETCH
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
      case 0: /* line ::= maybe_spaces msg */
#line 114 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: read message\n", G_STRFUNC);
#endif

    state->msg          = yymsp[0].minor.yy11;
    state->is_msg_valid = TRUE;
}
#line 1067 "./candump_parser.c"
        break;
      case 1: /* line ::= maybe_spaces */
#line 124 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: read empty line\n", G_STRFUNC);
#endif
}
#line 1076 "./candump_parser.c"
        break;
      case 2: /* msg ::= timestamp SPACE ifname SPACE id RTR */
#line 134 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
    yylhsminor.yy11.ts          = yymsp[-5].minor.yy60;
    yylhsminor.yy11.is_fd       = FALSE;
    yylhsminor.yy11.id          = yymsp[-1].minor.yy13 | CAN_RTR_FLAG;
    yylhsminor.yy11.data.length = (guint8)yymsp[0].minor.yy0.v0;

    memset(yylhsminor.yy11.data.data, 0, sizeof(yylhsminor.yy11.data.data));
}
#line 1088 "./candump_parser.c"
  yy_destructor(yypParser,1,&yymsp[-4].minor);
  yy_destructor(yypParser,1,&yymsp[-2].minor);
  yymsp[-5].minor.yy11 = yylhsminor.yy11;
        break;
      case 3: /* msg ::= timestamp SPACE ifname SPACE id data_max_8 */
#line 144 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
    yylhsminor.yy11.ts    = yymsp[-5].minor.yy60;
    yylhsminor.yy11.is_fd = FALSE;
    yylhsminor.yy11.id    = yymsp[-1].minor.yy13;
    yylhsminor.yy11.data  = yymsp[0].minor.yy16;
}
#line 1101 "./candump_parser.c"
  yy_destructor(yypParser,1,&yymsp[-4].minor);
  yy_destructor(yypParser,1,&yymsp[-2].minor);
  yymsp[-5].minor.yy11 = yylhsminor.yy11;
        break;
      case 4: /* msg ::= timestamp SPACE ifname SPACE id flags data_max_64 */
#line 152 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
    yylhsminor.yy11.ts    = yymsp[-6].minor.yy60;
    yylhsminor.yy11.is_fd = TRUE;
    yylhsminor.yy11.id    = yymsp[-2].minor.yy13;
    yylhsminor.yy11.flags = yymsp[-1].minor.yy64;
    yylhsminor.yy11.data  = yymsp[0].minor.yy16;
}
#line 1115 "./candump_parser.c"
  yy_destructor(yypParser,1,&yymsp[-5].minor);
  yy_destructor(yypParser,1,&yymsp[-3].minor);
  yymsp[-6].minor.yy11 = yylhsminor.yy11;
        break;
      case 5: /* timestamp ::= TIMESTAMP */
#line 161 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
    yylhsminor.yy60.secs  = (time_t)yymsp[0].minor.yy0.v0;
    yylhsminor.yy60.nsecs = (int)yymsp[0].minor.yy0.v1 * 1000;
}
#line 1126 "./candump_parser.c"
  yymsp[0].minor.yy60 = yylhsminor.yy60;
        break;
      case 6: /* id ::= STD_ID */
#line 178 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
    yylhsminor.yy13 = (guint32)yymsp[0].minor.yy0.v0;
}
#line 1134 "./candump_parser.c"
  yymsp[0].minor.yy13 = yylhsminor.yy13;
        break;
      case 7: /* id ::= EXT_ID */
#line 183 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
    yylhsminor.yy13 = (guint32)yymsp[0].minor.yy0.v0;

    if (!(yylhsminor.yy13 & CAN_ERR_FLAG))
        yylhsminor.yy13 |= CAN_EFF_FLAG;
}
#line 1145 "./candump_parser.c"
  yymsp[0].minor.yy13 = yylhsminor.yy13;
        break;
      case 8: /* flags ::= FLAGS */
      case 9: /* byte ::= BYTE */ yytestcase(yyruleno==9);
#line 191 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
    yylhsminor.yy64 = (guint8)yymsp[0].minor.yy0.v0;
}
#line 1154 "./candump_parser.c"
  yymsp[0].minor.yy64 = yylhsminor.yy64;
        break;
      case 10: /* data0 ::= */
#line 220 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
    yymsp[1].minor.yy16.length = 0;
}
#line 1162 "./candump_parser.c"
        break;
      case 11: /* data1 ::= byte */
#line 225 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
    yylhsminor.yy16.length  = 1;
    yylhsminor.yy16.data[0] = yymsp[0].minor.yy64;
}
#line 1170 "./candump_parser.c"
  yymsp[0].minor.yy16 = yylhsminor.yy16;
        break;
      case 12: /* data2 ::= byte byte */
#line 231 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
    yylhsminor.yy16.length  = 2;
    yylhsminor.yy16.data[0] = yymsp[-1].minor.yy64;
    yylhsminor.yy16.data[1] = yymsp[0].minor.yy64;
}
#line 1180 "./candump_parser.c"
  yymsp[-1].minor.yy16 = yylhsminor.yy16;
        break;
      case 13: /* data3 ::= byte byte byte */
#line 238 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
    yylhsminor.yy16.length  = 3;
    yylhsminor.yy16.data[0] = yymsp[-2].minor.yy64;
    yylhsminor.yy16.data[1] = yymsp[-1].minor.yy64;
    yylhsminor.yy16.data[2] = yymsp[0].minor.yy64;
}
#line 1191 "./candump_parser.c"
  yymsp[-2].minor.yy16 = yylhsminor.yy16;
        break;
      case 14: /* data4 ::= byte byte byte byte */
#line 246 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
    yylhsminor.yy16.length  = 4;
    yylhsminor.yy16.data[0] = yymsp[-3].minor.yy64;
    yylhsminor.yy16.data[1] = yymsp[-2].minor.yy64;
    yylhsminor.yy16.data[2] = yymsp[-1].minor.yy64;
    yylhsminor.yy16.data[3] = yymsp[0].minor.yy64;
}
#line 1203 "./candump_parser.c"
  yymsp[-3].minor.yy16 = yylhsminor.yy16;
        break;
      case 15: /* data5 ::= data4 data1 */
      case 16: /* data6 ::= data4 data2 */ yytestcase(yyruleno==16);
      case 17: /* data7 ::= data4 data3 */ yytestcase(yyruleno==17);
      case 18: /* data8 ::= data4 data4 */ yytestcase(yyruleno==18);
      case 19: /* data12 ::= data8 data4 */ yytestcase(yyruleno==19);
      case 20: /* data16 ::= data8 data8 */ yytestcase(yyruleno==20);
      case 21: /* data20 ::= data16 data4 */ yytestcase(yyruleno==21);
      case 22: /* data24 ::= data16 data8 */ yytestcase(yyruleno==22);
      case 23: /* data32 ::= data16 data16 */ yytestcase(yyruleno==23);
      case 24: /* data48 ::= data32 data16 */ yytestcase(yyruleno==24);
      case 25: /* data64 ::= data32 data32 */ yytestcase(yyruleno==25);
#line 254 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{ merge_msg_data(&yylhsminor.yy16, &yymsp[-1].minor.yy16, &yymsp[0].minor.yy16); }
#line 1219 "./candump_parser.c"
  yymsp[-1].minor.yy16 = yylhsminor.yy16;
        break;
      case 26: /* maybe_spaces ::= maybe_spaces SPACE */
#line 130 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
}
#line 1226 "./candump_parser.c"
  yy_destructor(yypParser,1,&yymsp[0].minor);
        break;
      case 30: /* any ::= UNKNOWN */
{  yy_destructor(yypParser,4,&yymsp[0].minor);
#line 169 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
}
#line 1234 "./candump_parser.c"
}
        break;
      case 31: /* any ::= RTR */
{  yy_destructor(yypParser,2,&yymsp[0].minor);
#line 170 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
}
#line 1242 "./candump_parser.c"
}
        break;
      case 32: /* any ::= STD_ID */
{  yy_destructor(yypParser,5,&yymsp[0].minor);
#line 171 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
}
#line 1250 "./candump_parser.c"
}
        break;
      case 33: /* any ::= EXT_ID */
{  yy_destructor(yypParser,6,&yymsp[0].minor);
#line 172 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
}
#line 1258 "./candump_parser.c"
}
        break;
      case 34: /* any ::= FLAGS */
{  yy_destructor(yypParser,7,&yymsp[0].minor);
#line 173 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
}
#line 1266 "./candump_parser.c"
}
        break;
      case 35: /* any ::= TIMESTAMP */
{  yy_destructor(yypParser,3,&yymsp[0].minor);
#line 174 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
}
#line 1274 "./candump_parser.c"
}
        break;
      case 36: /* any ::= BYTE */
{  yy_destructor(yypParser,8,&yymsp[0].minor);
#line 175 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"
{
}
#line 1282 "./candump_parser.c"
}
        break;
      default:
      /* (27) maybe_spaces ::= */ yytestcase(yyruleno==27);
      /* (28) ifname ::= ifname any */ yytestcase(yyruleno==28);
      /* (29) ifname ::= any (OPTIMIZED OUT) */ assert(yyruleno!=29);
      /* (37) data_max_8 ::= data0 (OPTIMIZED OUT) */ assert(yyruleno!=37);
      /* (38) data_max_8 ::= data1 (OPTIMIZED OUT) */ assert(yyruleno!=38);
      /* (39) data_max_8 ::= data2 (OPTIMIZED OUT) */ assert(yyruleno!=39);
      /* (40) data_max_8 ::= data3 (OPTIMIZED OUT) */ assert(yyruleno!=40);
      /* (41) data_max_8 ::= data4 */ yytestcase(yyruleno==41);
      /* (42) data_max_8 ::= data5 (OPTIMIZED OUT) */ assert(yyruleno!=42);
      /* (43) data_max_8 ::= data6 (OPTIMIZED OUT) */ assert(yyruleno!=43);
      /* (44) data_max_8 ::= data7 (OPTIMIZED OUT) */ assert(yyruleno!=44);
      /* (45) data_max_8 ::= data8 */ yytestcase(yyruleno==45);
      /* (46) data_max_64 ::= data_max_8 (OPTIMIZED OUT) */ assert(yyruleno!=46);
      /* (47) data_max_64 ::= data12 (OPTIMIZED OUT) */ assert(yyruleno!=47);
      /* (48) data_max_64 ::= data16 */ yytestcase(yyruleno==48);
      /* (49) data_max_64 ::= data20 (OPTIMIZED OUT) */ assert(yyruleno!=49);
      /* (50) data_max_64 ::= data24 (OPTIMIZED OUT) */ assert(yyruleno!=50);
      /* (51) data_max_64 ::= data32 */ yytestcase(yyruleno==51);
      /* (52) data_max_64 ::= data48 (OPTIMIZED OUT) */ assert(yyruleno!=52);
      /* (53) data_max_64 ::= data64 (OPTIMIZED OUT) */ assert(yyruleno!=53);
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
  CandumpParserARG_FETCH
  CandumpParserCTX_FETCH
#ifndef NDEBUG
  if( yyTraceFILE ){
    fprintf(yyTraceFILE,"%sFail!\n",yyTracePrompt);
  }
#endif
  while( yypParser->yytos>yypParser->yystack ) yy_pop_parser_stack(yypParser);
  /* Here code is inserted which will be executed whenever the
  ** parser fails */
/************ Begin %parse_failure code ***************************************/
#line 77 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"

    g_free(state->parse_error);
    state->parse_error = g_strdup("Parse Error");
#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Parse Error\n", G_STRFUNC);
#endif
#line 1354 "./candump_parser.c"
/************ End %parse_failure code *****************************************/
  CandumpParserARG_STORE /* Suppress warning about unused %extra_argument variable */
  CandumpParserCTX_STORE
}
#endif /* YYNOERRORRECOVERY */

/*
** The following code executes when a syntax error first occurs.
*/
static void yy_syntax_error(
  yyParser *yypParser,           /* The parser */
  int yymajor _U_,               /* The major type of the error token */
  CandumpParserTOKENTYPE yyminor         /* The minor type of the error token */
){
  CandumpParserARG_FETCH
  CandumpParserCTX_FETCH
#define TOKEN yyminor
/************ Begin %syntax_error code ****************************************/
#line 54 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"

    (void)yypParser;
    (void)yyminor;

#ifdef CANDUMP_DEBUG
    const int n = sizeof(yyTokenName) / sizeof(yyTokenName[0]);
    ws_debug_printf("%s: got token: %s\n", G_STRFUNC, yyTokenName[yymajor]);
    for (int i = 0; i < n; ++i) {
        int a = yy_find_shift_action((YYCODETYPE)i, yypParser->yytos->stateno);
        if (a < YYNSTATE + YYNRULE) {
            ws_debug_printf("%s: possible token: %s\n", G_STRFUNC, yyTokenName[i]);
        }
    }
#endif

    g_free(state->parse_error);
    state->parse_error = g_strdup_printf("Syntax Error");
#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Syntax Error\n", G_STRFUNC);
#endif
#line 1394 "./candump_parser.c"
/************ End %syntax_error code ******************************************/
  CandumpParserARG_STORE /* Suppress warning about unused %extra_argument variable */
  CandumpParserCTX_STORE
}

/*
** The following is executed when the parser accepts
*/
static void yy_accept(
  yyParser *yypParser           /* The parser */
){
  CandumpParserARG_FETCH
  CandumpParserCTX_FETCH
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
  CandumpParserARG_STORE /* Suppress warning about unused %extra_argument variable */
  CandumpParserCTX_STORE
}

/* The main parser program.
** The first argument is a pointer to a structure obtained from
** "CandumpParserAlloc" which describes the current state of the parser.
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
void CandumpParser(
  void *yyp,                   /* The parser */
  int yymajor,                 /* The major token code number */
  CandumpParserTOKENTYPE yyminor       /* The value for the token */
  CandumpParserARG_PDECL               /* Optional %extra_argument parameter */
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
  CandumpParserCTX_FETCH
  CandumpParserARG_STORE

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
                        yyminor CandumpParserCTX_PARAM);
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
int CandumpParserFallback(int iToken){
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
#line 266 "/Users/miguel/Downloads/wireshark-3.4.2/wiretap/candump_parser.lemon"


DIAG_ON(unreachable-code)

#include "candump_scanner_lex.h"
#include "candump_parser.h"

gboolean
run_candump_parser(candump_state_t *state, int *err, gchar **err_info)
{
    int              lex_code;
    yyscan_t         scanner;
    void            *parser;

    state->err         = 0;
    state->err_info    = NULL;
    state->parse_error = NULL;

    if (candump_lex_init_extra(state, &scanner) != 0)
    {
        *err      = errno;
        *err_info = g_strdup(g_strerror(errno));

        return FALSE;
    }

    parser = CandumpParserAlloc(g_malloc);

#ifdef CANDUMP_DEBUG
    CandumpParserTrace(stdout, "parser >> ");

    ws_debug_printf("%s: Starting parsing\n", G_STRFUNC);
#endif

    do
    {
        lex_code = candump_lex(scanner);

#ifdef CANDUMP_DEBUG
        if (lex_code)
            ws_debug_printf("%s: Feeding %s '%s'\n",
                            G_STRFUNC, yyTokenName[lex_code],
                            candump_get_text(scanner));
        else
            ws_debug_printf("%s: Feeding %s\n",
                            G_STRFUNC, yyTokenName[lex_code]);
#endif

        CandumpParser(parser, lex_code, state->token, state);

        if (state->err || state->err_info || state->parse_error)
            break;
    }
    while (lex_code);

#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Done (%d)\n", G_STRFUNC, lex_code);
#endif

    CandumpParserFree(parser, g_free);
    candump_lex_destroy(scanner);

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

#line 1717 "./candump_parser.c"
