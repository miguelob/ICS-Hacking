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
#line 1 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"


/* dtd_parser.lemon
 * XML dissector for wireshark
 * XML's DTD grammar
 *
 * Copyright 2005, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <glib.h>
#include <assert.h>
#include "dtd.h"
#include "dtd_parse.h"

static dtd_named_list_t* dtd_named_list_new(gchar* name, GPtrArray* list) {
	dtd_named_list_t* nl = g_new(dtd_named_list_t,1);

	nl->name = name;
	nl->list = list;

	return nl;
}

static GPtrArray* g_ptr_array_join(GPtrArray* a, GPtrArray* b){

	while(b->len > 0) {
		g_ptr_array_add(a,g_ptr_array_remove_index_fast(b,0));
	}

	g_ptr_array_free(b,TRUE);

	return a;
}

#line 72 "./dtd_grammar.c"
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
**    DtdParseTOKENTYPE     is the data type used for minor type for terminal
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
**                       which is DtdParseTOKENTYPE.  The entry in the union
**                       for terminal symbols is called "yy0".
**    YYSTACKDEPTH       is the maximum depth of the parser's stack.  If
**                       zero the stack is dynamically sized using realloc()
**    DtdParseARG_SDECL     A static variable declaration for the %extra_argument
**    DtdParseARG_PDECL     A parameter declaration for the %extra_argument
**    DtdParseARG_PARAM     Code to pass %extra_argument as a subroutine parameter
**    DtdParseARG_STORE     Code to store %extra_argument into yypParser
**    DtdParseARG_FETCH     Code to extract %extra_argument from yypParser
**    DtdParseCTX_*         As DtdParseARG_ except for %extra_context
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
#define YYNOCODE 39
#define YYACTIONTYPE unsigned char
#define DtdParseTOKENTYPE  dtd_token_data_t* 
typedef union {
  int yyinit;
  DtdParseTOKENTYPE yy0;
  GPtrArray* yy9;
  gchar* yy28;
  dtd_named_list_t* yy41;
} YYMINORTYPE;
#ifndef YYSTACKDEPTH
#define YYSTACKDEPTH 100
#endif
#define DtdParseARG_SDECL  dtd_build_data_t *bd ;
#define DtdParseARG_PDECL , dtd_build_data_t *bd 
#define DtdParseARG_PARAM ,bd 
#define DtdParseARG_FETCH  dtd_build_data_t *bd =yypParser->bd ;
#define DtdParseARG_STORE yypParser->bd =bd ;
#define DtdParseCTX_SDECL
#define DtdParseCTX_PDECL
#define DtdParseCTX_PARAM
#define DtdParseCTX_FETCH
#define DtdParseCTX_STORE
#define YYNSTATE             33
#define YYNRULE              44
#define YYNTOKEN             24
#define YY_MAX_SHIFT         32
#define YY_MIN_SHIFTREDUCE   71
#define YY_MAX_SHIFTREDUCE   114
#define YY_ERROR_ACTION      115
#define YY_ACCEPT_ACTION     116
#define YY_NO_ACTION         117
#define YY_MIN_REDUCE        118
#define YY_MAX_REDUCE        161
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
#define YY_ACTTAB_COUNT (92)
static const YYACTIONTYPE yy_action[] = {
 /*     0 */   116,   32,    9,  121,  122,   17,   17,    8,   20,   17,
 /*    10 */   103,   30,  105,  106,  107,   19,  138,    1,    1,   77,
 /*    20 */   159,    1,  156,   28,   26,   88,   88,   27,  113,   88,
 /*    30 */    25,   81,   82,   83,   22,   31,   29,  114,   23,   15,
 /*    40 */     2,   21,   21,   21,    7,  121,  122,   81,   82,   83,
 /*    50 */    96,   98,   97,   87,    4,    8,   16,   18,   76,    5,
 /*    60 */   101,  119,  120,   22,  137,  136,    2,   11,    1,   11,
 /*    70 */   147,   22,   13,  127,  126,   14,   88,  108,    6,   31,
 /*    80 */    29,  125,   71,    3,   24,   86,   12,   85,   10,   84,
 /*    90 */   104,  146,
};
static const YYCODETYPE yy_lookahead[] = {
 /*     0 */    24,   25,   26,   27,   28,    3,    3,    3,   30,    3,
 /*    10 */    10,   11,   12,   13,   14,   37,   38,   15,   15,    6,
 /*    20 */    34,   15,   36,   21,   21,   23,   23,   21,    3,   23,
 /*    30 */     2,   18,   19,   20,    1,    7,    8,   12,    5,    1,
 /*    40 */    15,   34,   35,   36,   26,   27,   28,   18,   19,   20,
 /*    50 */    18,   19,   20,   16,   17,    3,   30,   30,    6,   22,
 /*    60 */     9,   27,   28,    1,   38,   38,   15,   32,   15,   34,
 /*    70 */     0,    1,   29,   33,   31,   30,   23,   16,   17,    7,
 /*    80 */     8,   31,    6,    4,    3,   16,    3,   16,    3,   16,
 /*    90 */    12,    0,   39,   39,   39,   39,   39,   39,   39,   39,
 /*   100 */    39,   39,   39,   39,   39,   39,   39,   39,   39,   39,
 /*   110 */    39,   39,   39,   39,   39,   39,
};
#define YY_SHIFT_COUNT    (32)
#define YY_SHIFT_MIN      (0)
#define YY_SHIFT_MAX      (91)
static const unsigned char yy_shift_ofst[] = {
 /*     0 */    38,    2,   25,   62,    3,    6,   25,   33,   51,   70,
 /*    10 */     4,    0,   53,   52,   13,   28,   29,   32,   29,   37,
 /*    20 */    29,   61,   72,   76,   79,   81,   69,   71,   73,   83,
 /*    30 */    78,   85,   91,
};
#define YY_REDUCE_COUNT (13)
#define YY_REDUCE_MIN   (-24)
#define YY_REDUCE_MAX   (50)
static const signed char yy_reduce_ofst[] = {
 /*     0 */   -24,  -22,    7,   18,   26,   27,  -14,   34,   35,   34,
 /*    10 */    43,   40,   45,   50,
};
static const YYACTIONTYPE yy_default[] = {
 /*     0 */   115,  115,  115,  115,  115,  115,  115,  115,  115,  115,
 /*    10 */   115,  115,  115,  115,  115,  115,  141,  142,  140,  115,
 /*    20 */   139,  115,  115,  115,  115,  115,  115,  115,  115,  115,
 /*    30 */   115,  115,  115,
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
  DtdParseARG_SDECL                /* A place to hold %extra_argument */
  DtdParseCTX_SDECL                /* A place to hold %extra_context */
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
void DtdParseTrace(FILE *TraceFILE, char *zTracePrompt){
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
  /*    1 */ "TAG_START",
  /*    2 */ "DOCTYPE_KW",
  /*    3 */ "NAME",
  /*    4 */ "OPEN_BRACKET",
  /*    5 */ "CLOSE_BRACKET",
  /*    6 */ "TAG_STOP",
  /*    7 */ "ATTLIST_KW",
  /*    8 */ "ELEMENT_KW",
  /*    9 */ "ATT_TYPE",
  /*   10 */ "ATT_DEF",
  /*   11 */ "ATT_DEF_WITH_VALUE",
  /*   12 */ "QUOTED",
  /*   13 */ "IMPLIED_KW",
  /*   14 */ "REQUIRED_KW",
  /*   15 */ "OPEN_PARENS",
  /*   16 */ "CLOSE_PARENS",
  /*   17 */ "PIPE",
  /*   18 */ "STAR",
  /*   19 */ "PLUS",
  /*   20 */ "QUESTION",
  /*   21 */ "ELEM_DATA",
  /*   22 */ "COMMA",
  /*   23 */ "EMPTY_KW",
  /*   24 */ "dtd",
  /*   25 */ "doctype",
  /*   26 */ "dtd_parts",
  /*   27 */ "element",
  /*   28 */ "attlist",
  /*   29 */ "attrib_list",
  /*   30 */ "sub_elements",
  /*   31 */ "attrib",
  /*   32 */ "att_type",
  /*   33 */ "att_default",
  /*   34 */ "enumeration",
  /*   35 */ "enum_list",
  /*   36 */ "enum_item",
  /*   37 */ "element_list",
  /*   38 */ "element_child",
};
#endif /* defined(YYCOVERAGE) || !defined(NDEBUG) */

#ifndef NDEBUG
/* For tracing reduce actions, the names of all rules are required.
*/
static const char *const yyRuleName[] = {
 /*   0 */ "doctype ::= TAG_START DOCTYPE_KW NAME OPEN_BRACKET dtd_parts CLOSE_BRACKET TAG_STOP",
 /*   1 */ "dtd_parts ::= dtd_parts element",
 /*   2 */ "dtd_parts ::= dtd_parts attlist",
 /*   3 */ "dtd_parts ::= element",
 /*   4 */ "dtd_parts ::= attlist",
 /*   5 */ "attlist ::= TAG_START ATTLIST_KW NAME attrib_list TAG_STOP",
 /*   6 */ "element ::= TAG_START ELEMENT_KW NAME sub_elements TAG_STOP",
 /*   7 */ "attrib_list ::= attrib_list attrib",
 /*   8 */ "attrib_list ::= attrib",
 /*   9 */ "attrib ::= NAME att_type att_default",
 /*  10 */ "sub_elements ::= sub_elements STAR",
 /*  11 */ "sub_elements ::= sub_elements PLUS",
 /*  12 */ "sub_elements ::= sub_elements QUESTION",
 /*  13 */ "sub_elements ::= OPEN_PARENS ELEM_DATA CLOSE_PARENS",
 /*  14 */ "sub_elements ::= OPEN_PARENS element_list COMMA ELEM_DATA CLOSE_PARENS",
 /*  15 */ "sub_elements ::= OPEN_PARENS element_list PIPE ELEM_DATA CLOSE_PARENS",
 /*  16 */ "sub_elements ::= OPEN_PARENS element_list CLOSE_PARENS",
 /*  17 */ "sub_elements ::= EMPTY_KW",
 /*  18 */ "element_list ::= element_list COMMA element_child",
 /*  19 */ "element_list ::= element_list PIPE element_child",
 /*  20 */ "element_list ::= element_child",
 /*  21 */ "element_list ::= sub_elements",
 /*  22 */ "element_list ::= element_list COMMA sub_elements",
 /*  23 */ "element_list ::= element_list PIPE sub_elements",
 /*  24 */ "element_child ::= NAME",
 /*  25 */ "element_child ::= NAME STAR",
 /*  26 */ "element_child ::= NAME QUESTION",
 /*  27 */ "element_child ::= NAME PLUS",
 /*  28 */ "dtd ::= doctype",
 /*  29 */ "dtd ::= dtd_parts",
 /*  30 */ "att_type ::= ATT_TYPE",
 /*  31 */ "att_type ::= enumeration",
 /*  32 */ "att_default ::= ATT_DEF",
 /*  33 */ "att_default ::= ATT_DEF_WITH_VALUE QUOTED",
 /*  34 */ "att_default ::= QUOTED",
 /*  35 */ "att_default ::= IMPLIED_KW",
 /*  36 */ "att_default ::= REQUIRED_KW",
 /*  37 */ "enumeration ::= OPEN_PARENS enum_list CLOSE_PARENS",
 /*  38 */ "enum_list ::= enum_list PIPE enum_item",
 /*  39 */ "enum_list ::= enum_item",
 /*  40 */ "enum_list ::= enumeration",
 /*  41 */ "enum_list ::= enum_list PIPE enumeration",
 /*  42 */ "enum_item ::= NAME",
 /*  43 */ "enum_item ::= QUOTED",
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
** second argument to DtdParseAlloc() below.  This can be changed by
** putting an appropriate #define in the %include section of the input
** grammar.
*/
#ifndef YYMALLOCARGTYPE
# define YYMALLOCARGTYPE size_t
#endif

/* Initialize a new parser that has already been allocated.
*/
static void DtdParseInit(void *yypRawParser DtdParseCTX_PDECL){
  yyParser *yypParser = (yyParser*)yypRawParser;
  DtdParseCTX_STORE
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

#ifndef DtdParse_ENGINEALWAYSONSTACK
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
** to DtdParse and DtdParseFree.
*/
void *DtdParseAlloc(void *(*mallocProc)(YYMALLOCARGTYPE) DtdParseCTX_PDECL){
  yyParser *yypParser;
  yypParser = (yyParser*)(*mallocProc)( (YYMALLOCARGTYPE)sizeof(yyParser) );
  if( yypParser ){
    DtdParseCTX_STORE
    DtdParseInit(yypParser DtdParseCTX_PARAM);
  }
  return (void*)yypParser;
}
#endif /* DtdParse_ENGINEALWAYSONSTACK */


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
  DtdParseARG_FETCH
  DtdParseCTX_FETCH
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
    case 1: /* TAG_START */
    case 2: /* DOCTYPE_KW */
    case 3: /* NAME */
    case 4: /* OPEN_BRACKET */
    case 5: /* CLOSE_BRACKET */
    case 6: /* TAG_STOP */
    case 7: /* ATTLIST_KW */
    case 8: /* ELEMENT_KW */
    case 9: /* ATT_TYPE */
    case 10: /* ATT_DEF */
    case 11: /* ATT_DEF_WITH_VALUE */
    case 12: /* QUOTED */
    case 13: /* IMPLIED_KW */
    case 14: /* REQUIRED_KW */
    case 15: /* OPEN_PARENS */
    case 16: /* CLOSE_PARENS */
    case 17: /* PIPE */
    case 18: /* STAR */
    case 19: /* PLUS */
    case 20: /* QUESTION */
    case 21: /* ELEM_DATA */
    case 22: /* COMMA */
    case 23: /* EMPTY_KW */
{
#line 50 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"

	(void) bd; /* Mark unused, similar to Q_UNUSED */
	if ((yypminor->yy0)) {
		g_free((yypminor->yy0)->text);
		g_free((yypminor->yy0)->location);
		g_free((yypminor->yy0));
	}

#line 639 "./dtd_grammar.c"
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
static void DtdParseFinalize(void *p){
  yyParser *pParser = (yyParser*)p;
  while( pParser->yytos>pParser->yystack ) yy_pop_parser_stack(pParser);
#if YYSTACKDEPTH<=0
  if( pParser->yystack!=&pParser->yystk0 ) free(pParser->yystack);
#endif
}

#ifndef DtdParse_ENGINEALWAYSONSTACK
/*
** Deallocate and destroy a parser.  Destructors are called for
** all stack elements before shutting the parser down.
**
** If the YYPARSEFREENEVERNULL macro exists (for example because it
** is defined in a %include section of the input grammar) then it is
** assumed that the input pointer is never NULL.
*/
void DtdParseFree(
  void *p,                    /* The parser to be deleted */
  void (*freeProc)(void*)     /* Function used to reclaim memory */
){
#ifndef YYPARSEFREENEVERNULL
  if( p==0 ) return;
#endif
  DtdParseFinalize(p);
  (*freeProc)(p);
}
#endif /* DtdParse_ENGINEALWAYSONSTACK */

/*
** Return the peak depth of the stack for a parser.
*/
#ifdef YYTRACKMAXSTACKDEPTH
int DtdParseStackPeak(void *p){
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
int DtdParseCoverage(FILE *out){
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
   DtdParseARG_FETCH
   DtdParseCTX_FETCH
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
   DtdParseARG_STORE /* Suppress warning about unused %extra_argument var */
   DtdParseCTX_STORE
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
  DtdParseTOKENTYPE yyMinor        /* The minor token to shift in */
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
  {   25,   -7 }, /* (0) doctype ::= TAG_START DOCTYPE_KW NAME OPEN_BRACKET dtd_parts CLOSE_BRACKET TAG_STOP */
  {   26,   -2 }, /* (1) dtd_parts ::= dtd_parts element */
  {   26,   -2 }, /* (2) dtd_parts ::= dtd_parts attlist */
  {   26,   -1 }, /* (3) dtd_parts ::= element */
  {   26,   -1 }, /* (4) dtd_parts ::= attlist */
  {   28,   -5 }, /* (5) attlist ::= TAG_START ATTLIST_KW NAME attrib_list TAG_STOP */
  {   27,   -5 }, /* (6) element ::= TAG_START ELEMENT_KW NAME sub_elements TAG_STOP */
  {   29,   -2 }, /* (7) attrib_list ::= attrib_list attrib */
  {   29,   -1 }, /* (8) attrib_list ::= attrib */
  {   31,   -3 }, /* (9) attrib ::= NAME att_type att_default */
  {   30,   -2 }, /* (10) sub_elements ::= sub_elements STAR */
  {   30,   -2 }, /* (11) sub_elements ::= sub_elements PLUS */
  {   30,   -2 }, /* (12) sub_elements ::= sub_elements QUESTION */
  {   30,   -3 }, /* (13) sub_elements ::= OPEN_PARENS ELEM_DATA CLOSE_PARENS */
  {   30,   -5 }, /* (14) sub_elements ::= OPEN_PARENS element_list COMMA ELEM_DATA CLOSE_PARENS */
  {   30,   -5 }, /* (15) sub_elements ::= OPEN_PARENS element_list PIPE ELEM_DATA CLOSE_PARENS */
  {   30,   -3 }, /* (16) sub_elements ::= OPEN_PARENS element_list CLOSE_PARENS */
  {   30,   -1 }, /* (17) sub_elements ::= EMPTY_KW */
  {   37,   -3 }, /* (18) element_list ::= element_list COMMA element_child */
  {   37,   -3 }, /* (19) element_list ::= element_list PIPE element_child */
  {   37,   -1 }, /* (20) element_list ::= element_child */
  {   37,   -1 }, /* (21) element_list ::= sub_elements */
  {   37,   -3 }, /* (22) element_list ::= element_list COMMA sub_elements */
  {   37,   -3 }, /* (23) element_list ::= element_list PIPE sub_elements */
  {   38,   -1 }, /* (24) element_child ::= NAME */
  {   38,   -2 }, /* (25) element_child ::= NAME STAR */
  {   38,   -2 }, /* (26) element_child ::= NAME QUESTION */
  {   38,   -2 }, /* (27) element_child ::= NAME PLUS */
  {   24,   -1 }, /* (28) dtd ::= doctype */
  {   24,   -1 }, /* (29) dtd ::= dtd_parts */
  {   32,   -1 }, /* (30) att_type ::= ATT_TYPE */
  {   32,   -1 }, /* (31) att_type ::= enumeration */
  {   33,   -1 }, /* (32) att_default ::= ATT_DEF */
  {   33,   -2 }, /* (33) att_default ::= ATT_DEF_WITH_VALUE QUOTED */
  {   33,   -1 }, /* (34) att_default ::= QUOTED */
  {   33,   -1 }, /* (35) att_default ::= IMPLIED_KW */
  {   33,   -1 }, /* (36) att_default ::= REQUIRED_KW */
  {   34,   -3 }, /* (37) enumeration ::= OPEN_PARENS enum_list CLOSE_PARENS */
  {   35,   -3 }, /* (38) enum_list ::= enum_list PIPE enum_item */
  {   35,   -1 }, /* (39) enum_list ::= enum_item */
  {   35,   -1 }, /* (40) enum_list ::= enumeration */
  {   35,   -3 }, /* (41) enum_list ::= enum_list PIPE enumeration */
  {   36,   -1 }, /* (42) enum_item ::= NAME */
  {   36,   -1 }, /* (43) enum_item ::= QUOTED */
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
  DtdParseTOKENTYPE yyLookaheadToken  /* Value of the lookahead token */
  DtdParseCTX_PDECL                   /* %extra_context */
){
  int yygoto;                     /* The next state */
  YYACTIONTYPE yyact;             /* The next action */
  yyStackEntry *yymsp;            /* The top of the parser's stack */
  int yysize;                     /* Amount to pop the stack */
  DtdParseARG_FETCH
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
      case 0: /* doctype ::= TAG_START DOCTYPE_KW NAME OPEN_BRACKET dtd_parts CLOSE_BRACKET TAG_STOP */
{  yy_destructor(yypParser,1,&yymsp[-6].minor);
#line 77 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
	dtd_named_list_t* root;
	GPtrArray* root_elems = g_ptr_array_new();
	guint i;
	gchar *name;

	if(! bd->proto_name) {
		bd->proto_name = yymsp[-4].minor.yy0->text;
	}

	g_free(bd->proto_root);

	bd->proto_root = yymsp[-4].minor.yy0->text;

	name = g_ascii_strdown(bd->proto_name, -1);
	g_free(bd->proto_name);
	bd->proto_name = name;

	for( i = 0; i< bd->elements->len; i++) {
		dtd_named_list_t* el = (dtd_named_list_t*)g_ptr_array_index(bd->elements,i);

		g_ptr_array_add(root_elems,g_strdup(el->name));
	}

	root = dtd_named_list_new(g_strdup(yymsp[-4].minor.yy0->text),root_elems);

	g_ptr_array_add(bd->elements,root);

	g_free(yymsp[-4].minor.yy0->location);
	g_free(yymsp[-4].minor.yy0);

}
#line 1101 "./dtd_grammar.c"
  yy_destructor(yypParser,2,&yymsp[-5].minor);
  yy_destructor(yypParser,4,&yymsp[-3].minor);
  yy_destructor(yypParser,5,&yymsp[-1].minor);
  yy_destructor(yypParser,6,&yymsp[0].minor);
}
        break;
      case 1: /* dtd_parts ::= dtd_parts element */
      case 3: /* dtd_parts ::= element */ yytestcase(yyruleno==3);
#line 110 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{ g_ptr_array_add(bd->elements,yymsp[0].minor.yy41); }
#line 1112 "./dtd_grammar.c"
        break;
      case 2: /* dtd_parts ::= dtd_parts attlist */
      case 4: /* dtd_parts ::= attlist */ yytestcase(yyruleno==4);
#line 111 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{ g_ptr_array_add(bd->attributes,yymsp[0].minor.yy41); }
#line 1118 "./dtd_grammar.c"
        break;
      case 5: /* attlist ::= TAG_START ATTLIST_KW NAME attrib_list TAG_STOP */
{  yy_destructor(yypParser,1,&yymsp[-4].minor);
#line 116 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
	yymsp[-4].minor.yy41 = dtd_named_list_new(g_ascii_strdown(yymsp[-2].minor.yy0->text, -1),yymsp[-1].minor.yy9);
	g_free(yymsp[-2].minor.yy0->text);
	g_free(yymsp[-2].minor.yy0->location);
	g_free(yymsp[-2].minor.yy0);
}
#line 1129 "./dtd_grammar.c"
  yy_destructor(yypParser,7,&yymsp[-3].minor);
  yy_destructor(yypParser,6,&yymsp[0].minor);
}
        break;
      case 6: /* element ::= TAG_START ELEMENT_KW NAME sub_elements TAG_STOP */
{  yy_destructor(yypParser,1,&yymsp[-4].minor);
#line 124 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
	yymsp[-4].minor.yy41 = dtd_named_list_new(g_ascii_strdown(yymsp[-2].minor.yy0->text, -1),yymsp[-1].minor.yy9);
	g_free(yymsp[-2].minor.yy0->text);
	g_free(yymsp[-2].minor.yy0->location);
	g_free(yymsp[-2].minor.yy0);
}
#line 1143 "./dtd_grammar.c"
  yy_destructor(yypParser,8,&yymsp[-3].minor);
  yy_destructor(yypParser,6,&yymsp[0].minor);
}
        break;
      case 7: /* attrib_list ::= attrib_list attrib */
#line 132 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{ g_ptr_array_add(yymsp[-1].minor.yy9,yymsp[0].minor.yy28); yylhsminor.yy9 = yymsp[-1].minor.yy9; }
#line 1151 "./dtd_grammar.c"
  yymsp[-1].minor.yy9 = yylhsminor.yy9;
        break;
      case 8: /* attrib_list ::= attrib */
#line 133 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{ yylhsminor.yy9 = g_ptr_array_new(); g_ptr_array_add(yylhsminor.yy9,yymsp[0].minor.yy28);  }
#line 1157 "./dtd_grammar.c"
  yymsp[0].minor.yy9 = yylhsminor.yy9;
        break;
      case 9: /* attrib ::= NAME att_type att_default */
#line 136 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
	yylhsminor.yy28 = g_ascii_strdown(yymsp[-2].minor.yy0->text, -1);
	g_free(yymsp[-2].minor.yy0->text);
	g_free(yymsp[-2].minor.yy0->location);
	g_free(yymsp[-2].minor.yy0);
}
#line 1168 "./dtd_grammar.c"
  yymsp[-2].minor.yy28 = yylhsminor.yy28;
        break;
      case 10: /* sub_elements ::= sub_elements STAR */
#line 164 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{yylhsminor.yy9=yymsp[-1].minor.yy9;}
#line 1174 "./dtd_grammar.c"
  yy_destructor(yypParser,18,&yymsp[0].minor);
  yymsp[-1].minor.yy9 = yylhsminor.yy9;
        break;
      case 11: /* sub_elements ::= sub_elements PLUS */
#line 165 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{yylhsminor.yy9=yymsp[-1].minor.yy9;}
#line 1181 "./dtd_grammar.c"
  yy_destructor(yypParser,19,&yymsp[0].minor);
  yymsp[-1].minor.yy9 = yylhsminor.yy9;
        break;
      case 12: /* sub_elements ::= sub_elements QUESTION */
#line 166 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{yylhsminor.yy9=yymsp[-1].minor.yy9;}
#line 1188 "./dtd_grammar.c"
  yy_destructor(yypParser,20,&yymsp[0].minor);
  yymsp[-1].minor.yy9 = yylhsminor.yy9;
        break;
      case 13: /* sub_elements ::= OPEN_PARENS ELEM_DATA CLOSE_PARENS */
{  yy_destructor(yypParser,15,&yymsp[-2].minor);
#line 167 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{ yymsp[-2].minor.yy9 = g_ptr_array_new(); }
#line 1196 "./dtd_grammar.c"
  yy_destructor(yypParser,21,&yymsp[-1].minor);
  yy_destructor(yypParser,16,&yymsp[0].minor);
}
        break;
      case 14: /* sub_elements ::= OPEN_PARENS element_list COMMA ELEM_DATA CLOSE_PARENS */
{  yy_destructor(yypParser,15,&yymsp[-4].minor);
#line 168 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{ yymsp[-4].minor.yy9 = yymsp[-3].minor.yy9; }
#line 1205 "./dtd_grammar.c"
  yy_destructor(yypParser,22,&yymsp[-2].minor);
  yy_destructor(yypParser,21,&yymsp[-1].minor);
  yy_destructor(yypParser,16,&yymsp[0].minor);
}
        break;
      case 15: /* sub_elements ::= OPEN_PARENS element_list PIPE ELEM_DATA CLOSE_PARENS */
{  yy_destructor(yypParser,15,&yymsp[-4].minor);
#line 169 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{ yymsp[-4].minor.yy9 = yymsp[-3].minor.yy9; }
#line 1215 "./dtd_grammar.c"
  yy_destructor(yypParser,17,&yymsp[-2].minor);
  yy_destructor(yypParser,21,&yymsp[-1].minor);
  yy_destructor(yypParser,16,&yymsp[0].minor);
}
        break;
      case 16: /* sub_elements ::= OPEN_PARENS element_list CLOSE_PARENS */
{  yy_destructor(yypParser,15,&yymsp[-2].minor);
#line 170 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{ yymsp[-2].minor.yy9 = yymsp[-1].minor.yy9; }
#line 1225 "./dtd_grammar.c"
  yy_destructor(yypParser,16,&yymsp[0].minor);
}
        break;
      case 17: /* sub_elements ::= EMPTY_KW */
{  yy_destructor(yypParser,23,&yymsp[0].minor);
#line 171 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{ yymsp[0].minor.yy9 = g_ptr_array_new(); }
#line 1233 "./dtd_grammar.c"
}
        break;
      case 18: /* element_list ::= element_list COMMA element_child */
#line 174 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{ g_ptr_array_add(yymsp[-2].minor.yy9,yymsp[0].minor.yy28); yylhsminor.yy9 = yymsp[-2].minor.yy9; }
#line 1239 "./dtd_grammar.c"
  yy_destructor(yypParser,22,&yymsp[-1].minor);
  yymsp[-2].minor.yy9 = yylhsminor.yy9;
        break;
      case 19: /* element_list ::= element_list PIPE element_child */
#line 175 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{ g_ptr_array_add(yymsp[-2].minor.yy9,yymsp[0].minor.yy28); yylhsminor.yy9 = yymsp[-2].minor.yy9; }
#line 1246 "./dtd_grammar.c"
  yy_destructor(yypParser,17,&yymsp[-1].minor);
  yymsp[-2].minor.yy9 = yylhsminor.yy9;
        break;
      case 20: /* element_list ::= element_child */
#line 176 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{ yylhsminor.yy9 = g_ptr_array_new(); g_ptr_array_add(yylhsminor.yy9,yymsp[0].minor.yy28); }
#line 1253 "./dtd_grammar.c"
  yymsp[0].minor.yy9 = yylhsminor.yy9;
        break;
      case 21: /* element_list ::= sub_elements */
#line 177 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{ yylhsminor.yy9 = yymsp[0].minor.yy9; }
#line 1259 "./dtd_grammar.c"
  yymsp[0].minor.yy9 = yylhsminor.yy9;
        break;
      case 22: /* element_list ::= element_list COMMA sub_elements */
#line 178 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{ yylhsminor.yy9 = g_ptr_array_join(yymsp[-2].minor.yy9,yymsp[0].minor.yy9); }
#line 1265 "./dtd_grammar.c"
  yy_destructor(yypParser,22,&yymsp[-1].minor);
  yymsp[-2].minor.yy9 = yylhsminor.yy9;
        break;
      case 23: /* element_list ::= element_list PIPE sub_elements */
#line 179 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{ yylhsminor.yy9 = g_ptr_array_join(yymsp[-2].minor.yy9,yymsp[0].minor.yy9); }
#line 1272 "./dtd_grammar.c"
  yy_destructor(yypParser,17,&yymsp[-1].minor);
  yymsp[-2].minor.yy9 = yylhsminor.yy9;
        break;
      case 24: /* element_child ::= NAME */
#line 182 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
	yylhsminor.yy28 = g_ascii_strdown(yymsp[0].minor.yy0->text, -1);
	g_free(yymsp[0].minor.yy0->text);
	g_free(yymsp[0].minor.yy0->location);
	g_free(yymsp[0].minor.yy0);
}
#line 1284 "./dtd_grammar.c"
  yymsp[0].minor.yy28 = yylhsminor.yy28;
        break;
      case 25: /* element_child ::= NAME STAR */
#line 189 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
	yylhsminor.yy28 = g_ascii_strdown(yymsp[-1].minor.yy0->text, -1);
	g_free(yymsp[-1].minor.yy0->text);
	g_free(yymsp[-1].minor.yy0->location);
	g_free(yymsp[-1].minor.yy0);
}
#line 1295 "./dtd_grammar.c"
  yy_destructor(yypParser,18,&yymsp[0].minor);
  yymsp[-1].minor.yy28 = yylhsminor.yy28;
        break;
      case 26: /* element_child ::= NAME QUESTION */
#line 196 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
	yylhsminor.yy28 = g_ascii_strdown(yymsp[-1].minor.yy0->text, -1);
	g_free(yymsp[-1].minor.yy0->text);
	g_free(yymsp[-1].minor.yy0->location);
	g_free(yymsp[-1].minor.yy0);
}
#line 1307 "./dtd_grammar.c"
  yy_destructor(yypParser,20,&yymsp[0].minor);
  yymsp[-1].minor.yy28 = yylhsminor.yy28;
        break;
      case 27: /* element_child ::= NAME PLUS */
#line 203 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
	yylhsminor.yy28 = g_ascii_strdown(yymsp[-1].minor.yy0->text, -1);
	g_free(yymsp[-1].minor.yy0->text);
	g_free(yymsp[-1].minor.yy0->location);
	g_free(yymsp[-1].minor.yy0);
}
#line 1319 "./dtd_grammar.c"
  yy_destructor(yypParser,19,&yymsp[0].minor);
  yymsp[-1].minor.yy28 = yylhsminor.yy28;
        break;
      case 30: /* att_type ::= ATT_TYPE */
{  yy_destructor(yypParser,9,&yymsp[0].minor);
#line 143 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
}
#line 1328 "./dtd_grammar.c"
}
        break;
      case 32: /* att_default ::= ATT_DEF */
{  yy_destructor(yypParser,10,&yymsp[0].minor);
#line 146 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
}
#line 1336 "./dtd_grammar.c"
}
        break;
      case 33: /* att_default ::= ATT_DEF_WITH_VALUE QUOTED */
{  yy_destructor(yypParser,11,&yymsp[-1].minor);
#line 147 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
}
#line 1344 "./dtd_grammar.c"
  yy_destructor(yypParser,12,&yymsp[0].minor);
}
        break;
      case 34: /* att_default ::= QUOTED */
      case 43: /* enum_item ::= QUOTED */ yytestcase(yyruleno==43);
{  yy_destructor(yypParser,12,&yymsp[0].minor);
#line 148 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
}
#line 1354 "./dtd_grammar.c"
}
        break;
      case 35: /* att_default ::= IMPLIED_KW */
{  yy_destructor(yypParser,13,&yymsp[0].minor);
#line 149 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
}
#line 1362 "./dtd_grammar.c"
}
        break;
      case 36: /* att_default ::= REQUIRED_KW */
{  yy_destructor(yypParser,14,&yymsp[0].minor);
#line 150 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
}
#line 1370 "./dtd_grammar.c"
}
        break;
      case 37: /* enumeration ::= OPEN_PARENS enum_list CLOSE_PARENS */
{  yy_destructor(yypParser,15,&yymsp[-2].minor);
#line 152 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
}
#line 1378 "./dtd_grammar.c"
  yy_destructor(yypParser,16,&yymsp[0].minor);
}
        break;
      case 38: /* enum_list ::= enum_list PIPE enum_item */
      case 41: /* enum_list ::= enum_list PIPE enumeration */ yytestcase(yyruleno==41);
#line 154 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
}
#line 1387 "./dtd_grammar.c"
  yy_destructor(yypParser,17,&yymsp[-1].minor);
        break;
      case 42: /* enum_item ::= NAME */
{  yy_destructor(yypParser,3,&yymsp[0].minor);
#line 159 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"
{
}
#line 1395 "./dtd_grammar.c"
}
        break;
      default:
      /* (28) dtd ::= doctype */ yytestcase(yyruleno==28);
      /* (29) dtd ::= dtd_parts */ yytestcase(yyruleno==29);
      /* (31) att_type ::= enumeration (OPTIMIZED OUT) */ assert(yyruleno!=31);
      /* (39) enum_list ::= enum_item (OPTIMIZED OUT) */ assert(yyruleno!=39);
      /* (40) enum_list ::= enumeration (OPTIMIZED OUT) */ assert(yyruleno!=40);
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
  DtdParseARG_FETCH
  DtdParseCTX_FETCH
#ifndef NDEBUG
  if( yyTraceFILE ){
    fprintf(yyTraceFILE,"%sFail!\n",yyTracePrompt);
  }
#endif
  while( yypParser->yytos>yypParser->yystack ) yy_pop_parser_stack(yypParser);
  /* Here code is inserted which will be executed whenever the
  ** parser fails */
/************ Begin %parse_failure code ***************************************/
#line 66 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"

	g_string_append_printf(bd->error,"DTD parsing failure\n");
#line 1448 "./dtd_grammar.c"
/************ End %parse_failure code *****************************************/
  DtdParseARG_STORE /* Suppress warning about unused %extra_argument variable */
  DtdParseCTX_STORE
}
#endif /* YYNOERRORRECOVERY */

/*
** The following code executes when a syntax error first occurs.
*/
static void yy_syntax_error(
  yyParser *yypParser,           /* The parser */
  int yymajor _U_,               /* The major type of the error token */
  DtdParseTOKENTYPE yyminor         /* The minor type of the error token */
){
  DtdParseARG_FETCH
  DtdParseCTX_FETCH
#define TOKEN yyminor
/************ Begin %syntax_error code ****************************************/
#line 59 "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_grammar.lemon"

	if (!TOKEN)
		g_string_append_printf(bd->error,"syntax error at end of file");
	else
		g_string_append_printf(bd->error,"syntax error in %s at or before '%s': \n", TOKEN->location,TOKEN->text);
#line 1473 "./dtd_grammar.c"
/************ End %syntax_error code ******************************************/
  DtdParseARG_STORE /* Suppress warning about unused %extra_argument variable */
  DtdParseCTX_STORE
}

/*
** The following is executed when the parser accepts
*/
static void yy_accept(
  yyParser *yypParser           /* The parser */
){
  DtdParseARG_FETCH
  DtdParseCTX_FETCH
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
  DtdParseARG_STORE /* Suppress warning about unused %extra_argument variable */
  DtdParseCTX_STORE
}

/* The main parser program.
** The first argument is a pointer to a structure obtained from
** "DtdParseAlloc" which describes the current state of the parser.
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
void DtdParse(
  void *yyp,                   /* The parser */
  int yymajor,                 /* The major token code number */
  DtdParseTOKENTYPE yyminor       /* The value for the token */
  DtdParseARG_PDECL               /* Optional %extra_argument parameter */
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
  DtdParseCTX_FETCH
  DtdParseARG_STORE

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
                        yyminor DtdParseCTX_PARAM);
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
int DtdParseFallback(int iToken){
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
