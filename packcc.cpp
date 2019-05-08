/*
 * PackCC: a packrat parser generator for C.
 *
 * Copyright (c) 2014 Arihiro Yoshida. All rights reserved.
 * Copyright (c) 2019 Gerald Gainant. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * The algorithm is based on the paper "Packrat Parsers Can Support Left Recursion"
 * authored by A. Warth, J. R. Douglass, and T. Millstein.
 *
 * The specification is determined by referring to peg/leg developed by Ian Piumarta.
 */

#ifdef _MSC_VER
#ifdef _DEBUG
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#ifndef _MSC_VER
#if defined __GNUC__ && defined _WIN32 /* MinGW */
static size_t strnlen(const char *str, size_t maxlen) {
    size_t i;
    for (i = 0; str[i] && i < maxlen; i++);
    return i;
}
#else
#include <unistd.h> /* for strnlen() */
#endif
#endif

#define VERSION "1.3.0"

#ifndef BUFFER_INIT_SIZE
#define BUFFER_INIT_SIZE 256
#endif
#ifndef ARRAY_INIT_SIZE
#define ARRAY_INIT_SIZE 2
#endif

#define FlaggableEnum(_T) \
	inline bool operator !  (_T  a       ) { return     static_cast<unsigned>(a) == 0; } \
	inline _T   operator ~  (_T  a       ) { return     static_cast<_T>(~ static_cast<unsigned>(a)); } \
	inline _T   operator |  (_T  a, _T  b) { return     static_cast<_T>(static_cast<unsigned>(a) | static_cast<unsigned>(b));    } \
	inline _T   operator &  (_T  a, _T  b) { return     static_cast<_T>(static_cast<unsigned>(a) & static_cast<unsigned>(b));    } \
	inline _T   operator ^  (_T  a, _T  b) { return     static_cast<_T>(static_cast<unsigned>(a) ^ static_cast<unsigned>(b));    } \
	inline _T&  operator |= (_T& a, _T  b) { return a = static_cast<_T>(static_cast<unsigned>(a) | static_cast<unsigned>(b)), a; } \
	inline _T&  operator &= (_T& a, _T  b) { return a = static_cast<_T>(static_cast<unsigned>(a) & static_cast<unsigned>(b)), a; } \
	inline _T&  operator ^= (_T& a, _T  b) { return a = static_cast<_T>(static_cast<unsigned>(a) ^ static_cast<unsigned>(b)), a; }

 enum bool_t {
    FALSE = 0,
    TRUE
};

struct char_array {
    char *buf;
    int max;
    int len;
};

enum node_type {
    NODE_RULE = 0,
    NODE_REFERENCE,
    NODE_STRING,
    NODE_CHARCLASS,
    NODE_QUANTITY,
    NODE_PREDICATE,
    NODE_SEQUENCE,
    NODE_ALTERNATE,
    NODE_CAPTURE,
    NODE_EXPAND,
    NODE_ACTION,
    NODE_ERROR,
};

struct node;

struct node_array {
    node **buf;
    int max;
    int len;
};

struct node_const_array {
    const node **buf;
    int max;
    int len;
};

struct node_hash_table_t {
    const node **buf;
    int max;
    int mod;
};

struct node_rule {
    char *name;
    node *expr;
    int ref; /* mutable */
    node_const_array vars;
    node_const_array capts;
    node_const_array codes;
    int line;
    int col;
};

struct node_reference {
    char *name;
    const node *rule;
    int line;
    int col;
};

struct node_string {
    char *value;
};

struct node_charclass {
    char *value; /* NULL means any character */
};

struct node_quantity {
    int min;
    int max;
    node *expr;
};

struct node_predicate {
    bool_t neg;
    node *expr;
};

struct node_sequence {
    node_array nodes;
};

struct node_alternate {
    node_array nodes;
};

struct node_capture {
    node *expr;
    int index;
};

struct node_expand {
    int index;
    int line;
    int col;
};

struct node_action {
    char *value;
    int index;
    node_const_array vars;
    node_const_array capts;
};

struct node_error {
    node *expr;
    char *value;
    int index;
    node_const_array vars;
    node_const_array capts;
};

union node_data {
    node_rule      rule;
    node_reference reference;
    node_string    string;
    node_charclass charclass;
    node_quantity  quantity;
    node_predicate predicate;
    node_sequence  sequence;
    node_alternate alternate;
    node_capture   capture;
    node_expand    expand;
    node_action    action;
    node_error     error;
};

struct node {
    node_type type;
    node_data data;
};

struct context {
    char *iname;
    char *sname;
    char *hname;
    FILE *ifile;
    FILE *sfile;
    FILE *hfile;
    char *hid;
    char *atype;
    char *prefix;
	unsigned inputbuffsize;
	unsigned parsebuffsize;
    bool_t debug;
    int errnum;
    int linenum;
    int linepos;
    int bufpos;
    char_array buffer;
    node_array rules;
    node_hash_table_t rulehash;
};

struct generated {
    FILE *stream;
    const node *rule;
    int label;
};

enum string_flag {
    STRING_FLAG__NONE = 0,
    STRING_FLAG__NOTEMPTY = 1,
    STRING_FLAG__NOTVOID = 2,
    STRING_FLAG__IDENTIFIER = 4,
};

FlaggableEnum(string_flag)

enum code_reach {
    CODE_REACH__BOTH = 0,
    CODE_REACH__ALWAYS_SUCCEED = 1,
    CODE_REACH__ALWAYS_FAIL = -1
};

static const char *g_cmdname = "packcc"; /* replaced later with actual one */

static int print_error(const char *format, ...) {
    int n;
    va_list a;
    va_start(a, format);
    n = fprintf(stderr, "%s: ", g_cmdname) + vfprintf(stderr, format, a);
    va_end(a);
    return n;
}

static FILE *fopen_rb_e(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        print_error("Cannot open file '%s' to read\n", path);
        exit(2);
    }
    return f;
}

static FILE *fopen_wt_e(const char *path) {
    FILE *f = fopen(path, "wt");
    if (f == NULL) {
        print_error("Cannot open file '%s' to write\n", path);
        exit(2);
    }
    return f;
}

static void *malloc_e(size_t size) {
    void *p = malloc(size);
    if (p == NULL) {
        print_error("Out of memory\n");
        exit(3);
    }
    return p;
}

static void *realloc_e(void *ptr, size_t size) {
    void *p = realloc(ptr, size);
    if (p == NULL) {
        print_error("Out of memory\n");
        exit(3);
    }
    return p;
}

static char *strdup_e(const char *str) {
    size_t m = strlen(str);
    char *s = (char *)malloc_e(m + 1);
    memcpy(s, str, m);
    s[m] = '\0';
    return s;
}

static char *strndup_e(const char *str, size_t len) {
    size_t m = strnlen(str, len);
    char *s = (char *)malloc_e(m + 1);
    memcpy(s, str, m);
    s[m] = '\0';
    return s;
}

static bool_t is_filled_string(const char *str) {
    size_t i;
    for (i = 0; str[i]; i++) {
        if (
            str[i] != ' '  &&
            str[i] != '\v' &&
            str[i] != '\f' &&
            str[i] != '\t' &&
            str[i] != '\n' &&
            str[i] != '\r'
        ) return TRUE;
    }
    return FALSE;
}

static bool_t is_identifier_string(const char *str) {
    size_t i;
    if (!(
        (str[0] >= 'a' && str[0] <= 'z') ||
        (str[0] >= 'A' && str[0] <= 'Z') ||
         str[0] == '_'
    )) return FALSE;
    for (i = 1; str[i]; i++) {
        if (!(
            (str[i] >= 'a' && str[i] <= 'z') ||
            (str[i] >= 'A' && str[i] <= 'Z') ||
            (str[i] >= '0' && str[i] <= '9') ||
             str[i] == '_'
        )) return FALSE;
    }
    return TRUE;
}

static bool_t is_pointer_type(const char *str) {
    size_t n = strlen(str);
    return (n > 0 && str[n - 1] == '*') ? TRUE : FALSE;
}

static bool_t unescape_string(char *str) {
    bool_t b = TRUE;
    size_t i, j;
    for (j = 0, i = 0; str[i]; i++) {
        if (str[i] == '\\') {
            i++;
            switch (str[i]) {
            case '\0': str[j++] = '\\'; str[j] = '\0'; return FALSE;
            case '0': str[j++] = '\x00'; break;
            case 'a': str[j++] = '\x07'; break;
            case 'b': str[j++] = '\x08'; break;
            case 'f': str[j++] = '\x0c'; break;
            case 'n': str[j++] = '\x0a'; break;
            case 'r': str[j++] = '\x0d'; break;
            case 't': str[j++] = '\x09'; break;
            case 'v': str[j++] = '\x0b'; break;
            case 'x':
                if (str[i + 1] == '\0') {
                    str[j++] = '\\'; str[j++] = 'x'; str[j] = '\0'; return FALSE;
                }
                if (str[i + 2] == '\0') {
                    str[j++] = '\\'; str[j++] = 'x'; str[j++] = str[i + 1]; str[j] = '\0'; return FALSE; 
                }
                {
                    char c = str[i + 1];
                    char d = str[i + 2];
                    c = (c >= '0' && c <= '9') ? c - '0' :
                        (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                        (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
                    d = (d >= '0' && d <= '9') ? d - '0' :
                        (d >= 'a' && d <= 'f') ? d - 'a' + 10 :
                        (d >= 'A' && d <= 'F') ? d - 'A' + 10 : -1;
                    if (c < 0 || d < 0) {
                        str[j++] = '\\'; str[j++] = 'x'; str[j++] = str[i + 1]; str[j++] = str[i + 2];
                        b = FALSE;
                    }
                    else {
                        str[j++] = (c << 4) | d;
                    }
                    i += 2;
                }
                break;
            case '\n': break;
            case '\r': if (str[i + 1] == '\n') i++; break;
            default: str[j++] = str[i];
            }
        }
        else {
            str[j++] = str[i];
        }
    }
    str[j] = '\0';
    return b;
}

static const char *escape_character(char ch, char (*buf)[5]) {
    switch (ch) {
    case '\x00': strncpy(*buf, "\\0", 5); break;
    case '\x07': strncpy(*buf, "\\a", 5); break;
    case '\x08': strncpy(*buf, "\\b", 5); break;
    case '\x0c': strncpy(*buf, "\\f", 5); break;
    case '\x0a': strncpy(*buf, "\\n", 5); break;
    case '\x0d': strncpy(*buf, "\\r", 5); break;
    case '\x09': strncpy(*buf, "\\t", 5); break;
    case '\x0b': strncpy(*buf, "\\v", 5); break;
    case '\\':  strncpy(*buf, "\\\\", 5); break;
    case '\'':  strncpy(*buf, "\\\'", 5); break;
    case '\"':  strncpy(*buf, "\\\"", 5); break;
    default:
        if (ch >= '\x20' && ch < '\x7f')
            _snprintf(*buf, 5, "%c", ch);
        else
            _snprintf(*buf, 5, "\\x%02x", (unsigned)ch);
    }
    (*buf)[4] = '\0';
    return *buf;
}

static void remove_heading_blank(char *str) {
    size_t i, j;
    for (i = 0; str[i]; i++) {
        if (
            str[i] != ' '  &&
            str[i] != '\v' &&
            str[i] != '\f' &&
            str[i] != '\t' &&
            str[i] != '\n' &&
            str[i] != '\r'
        ) break;
    }
    for (j = 0; str[i]; i++) {
        str[j++] = str[i];
    }
    str[j] = '\0';
}

static void remove_trailing_blank(char *str) {
    size_t i, j;
    for (j = 0, i = 0; str[i]; i++) {
        if (
            str[i] != ' '  &&
            str[i] != '\v' &&
            str[i] != '\f' &&
            str[i] != '\t' &&
            str[i] != '\n' &&
            str[i] != '\r'
        ) j = i + 1;
    }
    str[j] = '\0';
}

static void make_header_identifier(char *str) {
    size_t i;
    for (i = 0; str[i]; i++) {
        str[i] =
            ((str[i] >= 'A' && str[i] <= 'Z') || (str[i] >= '0' && str[i] <= '9')) ? str[i] :
             (str[i] >= 'a' && str[i] <= 'z') ? str[i] - 'a' + 'A' : '_';
    }
}

static void write_characters(FILE *stream, char ch, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) fputc(ch, stream);
}

static void write_text(FILE *stream, const char *ptr, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (ptr[i] == '\r') {
            if (i + 1 < len && ptr[i + 1] == '\n') i++;
            fputc('\n', stream);
        }
        else {
            fputc(ptr[i], stream);
        }
    }
}

static void write_code_block(FILE *stream, const char *ptr, size_t len, int indent) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (ptr[i] == '\n') break;
        if (ptr[i] == '\r') {
            if (i + 1 < len && ptr[i + 1] == '\n') i++;
            break;
        }
    }
    if (i < len) {
        bool_t s = TRUE;
        size_t k = i + 1;
        int l = 0, m = -1;
        for (i = k; i < len; i++) {
            switch (ptr[i]) {
            case ' ':
            case '\v':
            case '\f':
                if (s) l++;
                break;
            case '\t':
                if (s) l = (l + 8) & ~7;
                break;
            case '\n':
                s = TRUE;
                l = 0;
                break;
            case '\r':
                if (i + 1 < len && ptr[i + 1] == '\n') i++;
                s = TRUE;
                l = 0;
                break;
            default:
                s = FALSE;
                m = (m >= 0 && m < l) ? m : l;
            }
        }
        for (i = 0; i < k; i++) {
            if (
                ptr[i] != ' '  &&
                ptr[i] != '\v' &&
                ptr[i] != '\f' &&
                ptr[i] != '\t' &&
                ptr[i] != '\n' &&
                ptr[i] != '\r'
            ) break;
        }
        if (i < k) {
            write_characters(stream, ' ', indent);
            write_text(stream, ptr + i, k - i);
        }
        s = TRUE;
        l = 0;
        for (i = k; i < len; i++) {
            switch (ptr[i]) {
            case ' ':
            case '\v':
            case '\f':
                if (s) l++; else fputc(ptr[i], stream);
                break;
            case '\t':
                if (s) l = (l + 8) & ~7; else fputc(ptr[i], stream);
                break;
            case '\n':
                fputc('\n', stream);
                s = TRUE;
                l = 0;
                break;
            case '\r':
                if (i + 1 < len && ptr[i + 1] == '\n') i++;
                fputc('\n', stream);
                s = TRUE;
                l = 0;
                break;
            default:
                if (s) {
                    write_characters(stream, ' ', l - m + indent);
                    s = FALSE;
                }
                fputc(ptr[i], stream);
            }
        }
        if (!s) fputc('\n', stream);
    }
    else {
        for (i = 0; i < len; i++) {
            if (
                ptr[i] != ' '  &&
                ptr[i] != '\v' &&
                ptr[i] != '\f' &&
                ptr[i] != '\t'
            ) break;
        }
        if (i < len) {
            write_characters(stream, ' ', indent);
            write_text(stream, ptr + i, len - i);
            fputc('\n', stream);
        }
    }
}

static const char *extract_filename(const char *path) {
    size_t i, n = strlen(path);
    for (i = n - 1; i >= 0; i--) {
        if (path[i] == '/' || path[i] == '\\' || path[i] == ':') break;
    }
    return path + i + 1;
}

static const char *extract_fileext(const char *path) {
    size_t i, n = strlen(path);
    for (i = n - 1; i >= 0; i--) {
        if (path[i] == '/' || path[i] == '\\' || path[i] == ':') break;
        if (path[i] == '.') return path + i;
    }
    return path + n;
}

static char *replace_fileext(const char *path, const char *ext) {
    const char *p = extract_fileext(path);
    size_t m = p - path;
    size_t n = strlen(ext);
    char *s = (char *)malloc_e(m + n + 2);
    memcpy(s, path, m);
    s[m] = '.';
    memcpy(s + m + 1, ext, n + 1);
    return s;
}

static char *add_fileext(const char *path, const char *ext) {
    size_t m = strlen(path);
    size_t n = strlen(ext);
    char *s = (char *)malloc_e(m + n + 2);
    memcpy(s, path, m);
    s[m] = '.';
    memcpy(s + m + 1, ext, n + 1);
    return s;
}

static int hash_string(const char *str) {
    int i, h = 0;
    for (i = 0; str[i]; i++) {
        h = h * 31 + str[i];
    }
    return h;
}

static int populate_bits(int x) {
    x |= x >>  1;
    x |= x >>  2;
    x |= x >>  4;
    x |= x >>  8;
    x |= x >> 16;
    return x;
}

static void char_array__init(char_array *array, int max) {
    array->len = 0;
    array->max = max;
    array->buf = (char *)malloc_e(array->max);
}

static void char_array__add(char_array *array, char ch) {
    if (array->max <= 0) array->max = 1;
    while (array->max <= array->len) array->max <<= 1;
    array->buf = (char *)realloc_e(array->buf, array->max);
    array->buf[array->len++] = ch;
}

static void char_array__term(char_array *array) {
    free(array->buf);
}

static void node_array__init(node_array *array, int max) {
    array->len = 0;
    array->max = max;
    array->buf = (node **)malloc_e(array->max * sizeof(node *));
}

static void node_array__add(node_array *array, node *n) {
    if (array->max <= 0) array->max = 1;
    while (array->max <= array->len) array->max <<= 1;
    array->buf = (node **) realloc_e(array->buf, array->max * sizeof(node *));
    array->buf[array->len++] = n;
}

static void destroy_node(node *node);

static void node_array__term(node_array *array) {
    int i;
    for (i = array->len - 1; i >= 0; i--) {
        destroy_node(array->buf[i]);
    }
    free(array->buf);
}

static void node_const_array__init(node_const_array *array, int max) {
    array->len = 0;
    array->max = max;
    array->buf = (const node **)malloc_e(array->max * sizeof(const node *));
}

static void node_const_array__add(node_const_array *array, const node *n) {
    if (array->max <= 0) array->max = 1;
    while (array->max <= array->len) array->max <<= 1;
    array->buf = (const node **)realloc_e((node **)array->buf, array->max * sizeof(const node *));
    array->buf[array->len++] = n;
}

static void node_const_array__clear(node_const_array *array) {
    array->len = 0;
}

static void node_const_array__copy(node_const_array *array, const node_const_array *src) {
    int i;
    node_const_array__clear(array);
    for (i = 0; i < src->len; i++) {
        node_const_array__add(array, src->buf[i]);
    }
}

static void node_const_array__term(node_const_array *array) {
    free((node **)array->buf);
}

static context *create_context(const char *iname, const char *oname, bool_t debug) {
    context *ctx = (context *)malloc_e(sizeof(context));
    ctx->iname = strdup_e((iname && iname[0]) ? iname : "-");
    ctx->sname = (oname && oname[0]) ? add_fileext(oname, "cpp") : replace_fileext(ctx->iname, "cpp");
    ctx->hname = (oname && oname[0]) ? add_fileext(oname, "hpp") : replace_fileext(ctx->iname, "hpp");
    ctx->ifile = (iname && iname[0]) ? fopen_rb_e(ctx->iname) : stdin;
    ctx->sfile = fopen_wt_e(ctx->sname);
    ctx->hfile = fopen_wt_e(ctx->hname);
    ctx->hid = strdup_e(ctx->hname); make_header_identifier(ctx->hid);
    ctx->atype = NULL;
    ctx->prefix = NULL;
	ctx->inputbuffsize = 64;
	ctx->parsebuffsize = 4096;
    ctx->debug = debug;
    ctx->errnum = 0;
    ctx->linenum = 0;
    ctx->linepos = 0;
    ctx->bufpos = 0;
    char_array__init(&ctx->buffer, BUFFER_INIT_SIZE);
    node_array__init(&ctx->rules, ARRAY_INIT_SIZE);
    ctx->rulehash.mod = 0;
    ctx->rulehash.max = 0;
    ctx->rulehash.buf = NULL;
    return ctx;
}

static node *create_node(node_type type) {
    node *n = (node*)malloc_e(sizeof(node));
    n->type = type;
    switch (n->type) {
    case NODE_RULE:
        n->data.rule.name = NULL;
        n->data.rule.expr = NULL;
        n->data.rule.ref = 0;
        node_const_array__init(&n->data.rule.vars, ARRAY_INIT_SIZE);
        node_const_array__init(&n->data.rule.capts, ARRAY_INIT_SIZE);
        node_const_array__init(&n->data.rule.codes, ARRAY_INIT_SIZE);
        n->data.rule.line = -1;
        n->data.rule.col = -1;
        break;
    case NODE_REFERENCE:
        n->data.reference.name = NULL;
        n->data.reference.rule = NULL;
        n->data.reference.line = -1;
        n->data.reference.col = -1;
        break;
    case NODE_STRING:
        n->data.string.value = NULL;
        break;
    case NODE_CHARCLASS:
        n->data.charclass.value = NULL;
        break;
    case NODE_QUANTITY:
        n->data.quantity.min = n->data.quantity.max = 0;
        n->data.quantity.expr = NULL;
        break;
    case NODE_PREDICATE:
        n->data.predicate.neg = FALSE;
        n->data.predicate.expr = NULL;
        break;
    case NODE_SEQUENCE:
        node_array__init(&n->data.sequence.nodes, ARRAY_INIT_SIZE);
        break;
    case NODE_ALTERNATE:
        node_array__init(&n->data.alternate.nodes, ARRAY_INIT_SIZE);
        break;
    case NODE_CAPTURE:
        n->data.capture.expr = NULL;
        n->data.capture.index = -1;
        break;
    case NODE_EXPAND:
        n->data.expand.index = -1;
        n->data.expand.line = -1;
        n->data.expand.col = -1;
        break;
    case NODE_ACTION:
        n->data.action.value = NULL;
        n->data.action.index = -1;
        node_const_array__init(&n->data.action.vars, ARRAY_INIT_SIZE);
        node_const_array__init(&n->data.action.capts, ARRAY_INIT_SIZE);
        break;
    case NODE_ERROR:
        n->data.error.expr = NULL;
        n->data.error.value = NULL;
        n->data.error.index = -1;
        node_const_array__init(&n->data.error.vars, ARRAY_INIT_SIZE);
        node_const_array__init(&n->data.error.capts, ARRAY_INIT_SIZE);
        break;
    default:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    }
    return n;
}

static void destroy_node(node *node) {
    if (node == NULL) return;
    switch (node->type) {
    case NODE_RULE:
        node_const_array__term(&node->data.rule.codes);
        node_const_array__term(&node->data.rule.capts);
        node_const_array__term(&node->data.rule.vars);
        destroy_node(node->data.rule.expr);
        free(node->data.rule.name);
        break;
    case NODE_REFERENCE:
        free(node->data.reference.name);
        break;
    case NODE_STRING:
        free(node->data.string.value);
        break;
    case NODE_CHARCLASS:
        free(node->data.charclass.value);
        break;
    case NODE_QUANTITY:
        destroy_node(node->data.quantity.expr);
        break;
    case NODE_PREDICATE:
        destroy_node(node->data.predicate.expr);
        break;
    case NODE_SEQUENCE:
        node_array__term(&node->data.sequence.nodes);
        break;
    case NODE_ALTERNATE:
        node_array__term(&node->data.alternate.nodes);
        break;
    case NODE_CAPTURE:
        destroy_node(node->data.capture.expr);
        break;
    case NODE_EXPAND:
        break;
    case NODE_ACTION:
        node_const_array__term(&node->data.action.capts);
        node_const_array__term(&node->data.action.vars);
        free(node->data.action.value);
        break;
    case NODE_ERROR:
        node_const_array__term(&node->data.error.capts);
        node_const_array__term(&node->data.error.vars);
        free(node->data.error.value);
        destroy_node(node->data.error.expr);
        break;
    default:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    }
    free(node);
}

static void destroy_context(context *ctx) {
    if (ctx == NULL) return;
    free((node **)ctx->rulehash.buf);
    node_array__term(&ctx->rules);
    char_array__term(&ctx->buffer);
    free(ctx->prefix);
    free(ctx->atype);
    free(ctx->hid);
    fclose(ctx->hfile); if (ctx->errnum) _unlink(ctx->hname);
    fclose(ctx->sfile); if (ctx->errnum) _unlink(ctx->sname);
    fclose(ctx->ifile);
    free(ctx->hname);
    free(ctx->sname);
    free(ctx->iname);
    free(ctx);
}

static void make_rulehash(context *ctx) {
    int i, j;
    ctx->rulehash.mod = populate_bits(ctx->rules.len * 4);
    ctx->rulehash.max = ctx->rulehash.mod + 1;
    ctx->rulehash.buf = (const node **)realloc_e((node **)ctx->rulehash.buf, ctx->rulehash.max * sizeof(const node *));
    for (i = 0; i < ctx->rulehash.max; i++) {
        ctx->rulehash.buf[i] = NULL;
    }
    for (i = 0; i < ctx->rules.len; i++) {
        assert(ctx->rules.buf[i]->type == NODE_RULE);
        j = hash_string(ctx->rules.buf[i]->data.rule.name) & ctx->rulehash.mod;
        while (ctx->rulehash.buf[j] != NULL) {
            if (strcmp(ctx->rules.buf[i]->data.rule.name, ctx->rulehash.buf[j]->data.rule.name) == 0) {
                assert(ctx->rules.buf[i]->data.rule.ref == 0);
                assert(ctx->rulehash.buf[j]->data.rule.ref == 0);
                ctx->rules.buf[i]->data.rule.ref = -1;
                goto EXCEPTION;
            }
            j = (j + 1) & ctx->rulehash.mod;
        }
        ctx->rulehash.buf[j] = ctx->rules.buf[i];

EXCEPTION:;
    }
}

static const node *lookup_rulehash(const context *ctx, const char *name) {
    int j = hash_string(name) & ctx->rulehash.mod;
    while (ctx->rulehash.buf[j] != NULL && strcmp(name, ctx->rulehash.buf[j]->data.rule.name) != 0) {
        j = (j + 1) & ctx->rulehash.mod;
    }
    return (ctx->rulehash.buf[j] != NULL) ? ctx->rulehash.buf[j] : NULL;
}

static void link_references(context *ctx, node *n) {
    if (n == NULL) return;
    switch (n->type) {
    case NODE_RULE:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    case NODE_REFERENCE:
        n->data.reference.rule = lookup_rulehash(ctx, n->data.reference.name);
        if (n->data.reference.rule == NULL) {
            print_error("%s(%d): %d: No definition of rule '%s'\n",
                ctx->iname, n->data.reference.line + 1, n->data.reference.col + 1, n->data.reference.name);
            ctx->errnum++;
        }
        else {
            assert(n->data.reference.rule->type == NODE_RULE);
            ((node *)n->data.reference.rule)->data.rule.ref++;
        }
        break;
    case NODE_STRING:
        break;
    case NODE_CHARCLASS:
        break;
    case NODE_QUANTITY:
        link_references(ctx, n->data.quantity.expr);
        break;
    case NODE_PREDICATE:
        link_references(ctx, n->data.predicate.expr);
        break;
    case NODE_SEQUENCE:
        {
            int i;
            for (i = 0; i < n->data.sequence.nodes.len; i++) {
                link_references(ctx, n->data.sequence.nodes.buf[i]);
            }
        }
        break;
    case NODE_ALTERNATE:
        {
            int i;
            for (i = 0; i < n->data.alternate.nodes.len; i++) {
                link_references(ctx, n->data.alternate.nodes.buf[i]);
            }
        }
        break;
    case NODE_CAPTURE:
        link_references(ctx, n->data.capture.expr);
        break;
    case NODE_EXPAND:
        break;
    case NODE_ACTION:
        break;
    case NODE_ERROR:
        link_references(ctx, n->data.error.expr);
        break;
    default:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    }
}

static void verify_captures(context *ctx, node *node, node_const_array *capts) {
    node_const_array a;
    bool_t b = (capts == NULL) ? TRUE : FALSE;
    if (node == NULL) return;
    if (b) {
        node_const_array__init(&a, ARRAY_INIT_SIZE);
        capts = &a;
    }
    switch (node->type) {
    case NODE_RULE:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    case NODE_REFERENCE:
        break;
    case NODE_STRING:
        break;
    case NODE_CHARCLASS:
        break;
    case NODE_QUANTITY:
        verify_captures(ctx, node->data.quantity.expr, capts);
        break;
    case NODE_PREDICATE:
        verify_captures(ctx, node->data.predicate.expr, capts);
        break;
    case NODE_SEQUENCE:
        {
            int i;
            for (i = 0; i < node->data.sequence.nodes.len; i++) {
                verify_captures(ctx, node->data.sequence.nodes.buf[i], capts);
            }
        }
        break;
    case NODE_ALTERNATE:
        {
            int i, j, m = capts->len;
            node_const_array v;
            node_const_array__init(&v, ARRAY_INIT_SIZE);
            node_const_array__copy(&v, capts);
            for (i = 0; i < node->data.alternate.nodes.len; i++) {
                v.len = m;
                verify_captures(ctx, node->data.alternate.nodes.buf[i], &v);
                for (j = m; j < v.len; j++) {
                    node_const_array__add(capts, v.buf[j]);
                }
            }
            node_const_array__term(&v);
        }
        break;
    case NODE_CAPTURE:
        verify_captures(ctx, node->data.capture.expr, capts);
        node_const_array__add(capts, node);
        break;
    case NODE_EXPAND:
        {
            int i;
            for (i = 0; i < capts->len; i++) {
                assert(capts->buf[i]->type == NODE_CAPTURE);
                if (node->data.expand.index == capts->buf[i]->data.capture.index) break;
            }
            if (i >= capts->len && node->data.expand.index >= 0) {
                print_error("%s:%d:%d: Capture %d not available at this position\n",
                    ctx->iname, node->data.expand.line + 1, node->data.expand.col + 1, node->data.expand.index + 1);
                ctx->errnum++;
            }
        }
        break;
    case NODE_ACTION:
        node_const_array__copy(&node->data.action.capts, capts);
        break;
    case NODE_ERROR:
        node_const_array__copy(&node->data.error.capts, capts);
        verify_captures(ctx, node->data.error.expr, capts);
        break;
    default:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    }
    if (b) {
        node_const_array__term(&a);
    }
}

static void dump_node(context *ctx, const node *node) {
    if (node == NULL) return;
    switch (node->type) {
    case NODE_RULE:
        fprintf(stdout, "Rule(name:'%s',ref:%d,vars.len:%d,capts.len:%d,codes.len:%d){\n",
            node->data.rule.name, node->data.rule.ref, node->data.rule.vars.len, node->data.rule.capts.len, node->data.rule.codes.len);
        dump_node(ctx, node->data.rule.expr);
        fprintf(stdout, "}\n");
        break;
    case NODE_REFERENCE:
        fprintf(stdout, "Reference(name:'%s',rule:'%s')\n",
            node->data.reference.name, (node->data.reference.rule) ? node->data.reference.rule->data.rule.name : NULL);
        break;
    case NODE_STRING:
        fprintf(stdout, "String(value:'%s')\n", node->data.string.value);
        break;
    case NODE_CHARCLASS:
        fprintf(stdout, "Charclass(value:'%s')\n", node->data.charclass.value);
        break;
    case NODE_QUANTITY:
        fprintf(stdout, "Quantity(min:%d,max%d){\n", node->data.quantity.min, node->data.quantity.max);
        dump_node(ctx, node->data.quantity.expr);
        fprintf(stdout, "}\n");
        break;
    case NODE_PREDICATE:
        fprintf(stdout, "Predicate(neg:%d){\n", node->data.predicate.neg);
        dump_node(ctx, node->data.predicate.expr);
        fprintf(stdout, "}\n");
        break;
    case NODE_SEQUENCE:
        fprintf(stdout, "Sequence(max:%d,len:%d){\n", node->data.sequence.nodes.max, node->data.sequence.nodes.len);
        {
            int i;
            for (i = 0; i < node->data.sequence.nodes.len; i++) {
                dump_node(ctx, node->data.sequence.nodes.buf[i]);
            }
        }
        fprintf(stdout, "}\n");
        break;
    case NODE_ALTERNATE:
        fprintf(stdout, "Alternate(max:%d,len:%d){\n", node->data.alternate.nodes.max, node->data.alternate.nodes.len);
        {
            int i;
            for (i = 0; i < node->data.alternate.nodes.len; i++) {
                dump_node(ctx, node->data.alternate.nodes.buf[i]);
            }
        }
        fprintf(stdout, "}\n");
        break;
    case NODE_CAPTURE:
        fprintf(stdout, "Capture(index:%d){\n", node->data.capture.index);
        dump_node(ctx, node->data.capture.expr);
        fprintf(stdout, "}\n");
        break;
    case NODE_EXPAND:
        fprintf(stdout, "Expand(index:%d)\n", node->data.expand.index);
        break;
    case NODE_ACTION:
        fprintf(stdout, "Action(index:%d,value:{%s},vars:\n", node->data.action.index, node->data.action.value);
        {
            int i;
            for (i = 0; i < node->data.action.capts.len; i++) {
                fprintf(stdout, "    $%d\n", node->data.action.capts.buf[i]->data.capture.index + 1);
            }
        }
        fprintf(stdout, ")\n");
        break;
    case NODE_ERROR:
        fprintf(stdout, "Error(index:%d,value:{%s},vars:\n", node->data.error.index, node->data.error.value);
        {
            int i;
            for (i = 0; i < node->data.error.capts.len; i++) {
                fprintf(stdout, "    $%d\n", node->data.error.capts.buf[i]->data.capture.index + 1);
            }
        }
        fprintf(stdout, "){\n");
        dump_node(ctx, node->data.error.expr);
        fprintf(stdout, "}\n");
        break;
    default:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    }
}

static int refill_buffer(context *ctx, int num) {
    int n, c;
    n = ctx->buffer.len - ctx->bufpos;
    if (n >= num) return n;
    while (ctx->buffer.len < ctx->bufpos + num) {
        c = fgetc(ctx->ifile);
        if (c == EOF) break;
        char_array__add(&ctx->buffer, (char)c);
    }
    return ctx->buffer.len - ctx->bufpos;
}

static void commit_buffer(context *ctx) {
    ctx->linepos -= ctx->bufpos;
    memmove(ctx->buffer.buf, ctx->buffer.buf + ctx->bufpos, ctx->buffer.len - ctx->bufpos);
    ctx->buffer.len -= ctx->bufpos;
    ctx->bufpos = 0;
}

static bool_t match_eof(context *ctx) {
    return (refill_buffer(ctx, 1) < 1) ? TRUE : FALSE;
}

static bool_t match_eol(context *ctx) {
    if (refill_buffer(ctx, 1) >= 1) {
        switch (ctx->buffer.buf[ctx->bufpos]) {
        case '\n':
            ctx->bufpos++;
            ctx->linenum++;
            ctx->linepos = ctx->bufpos;
            return TRUE;
        case '\r':
            ctx->bufpos++;
            if (refill_buffer(ctx, 1) >= 1) {
                if (ctx->buffer.buf[ctx->bufpos] == '\n') ctx->bufpos++;
            }
            ctx->linenum++;
            ctx->linepos = ctx->bufpos;
            return TRUE;
        }
    }
    return FALSE;
}

static bool_t match_character(context *ctx, char ch) {
    if (refill_buffer(ctx, 1) >= 1) {
        if (ctx->buffer.buf[ctx->bufpos] == ch) {
            ctx->bufpos++;
            return TRUE;
        }
    }
    return FALSE;
}

static bool_t match_character_range(context *ctx, char min, char max) {
    if (refill_buffer(ctx, 1) >= 1) {
        char c = ctx->buffer.buf[ctx->bufpos];
        if (c >= min && c <= max) { 
            ctx->bufpos++;
            return TRUE;
        }
    }
    return FALSE;
}

static bool_t match_character_set(context *ctx, const char *chs) {
    if (refill_buffer(ctx, 1) >= 1) {
        char c = ctx->buffer.buf[ctx->bufpos];
        int i;
        for (i = 0; chs[i]; i++) {
            if (c == chs[i]) {
                ctx->bufpos++;
                return TRUE;
            }
        }
    }
    return FALSE;
}

static bool_t match_character_any(context *ctx) {
    if (refill_buffer(ctx, 1) >= 1) {
        ctx->bufpos++;
        return TRUE;
    }
    return FALSE;
}

static bool_t match_string(context *ctx, const char *str) {
    int n = (int)strlen(str);
    if ( refill_buffer(ctx, n) >= n ) {
        if (strncmp(ctx->buffer.buf + ctx->bufpos, str, n) == 0) {
            ctx->bufpos += n;
            return TRUE;
        }
    }
    return FALSE;
}

static bool_t match_blank(context *ctx) {
    return match_character_set(ctx, " \t\v\f");
}

static bool_t match_section_line_(context *ctx, const char *head) {
    if (match_string(ctx, head)) {
        while (!match_eol(ctx) && !match_eof(ctx)) match_character_any(ctx);
        return TRUE;
    }
    return FALSE;
}

static bool_t match_section_line_continuable_(context *ctx, const char *head) {
    if (match_string(ctx, head)) {
        while (!match_eof(ctx)) {
            int p = ctx->bufpos;
            if (match_eol(ctx)) {
                if (ctx->buffer.buf[p - 1] != '\\') break;
            }
            else {
                match_character_any(ctx);
            }
        }
        return TRUE;
    }
    return FALSE;
}

static bool_t match_section_block_(context *ctx, const char *left, const char *right, const char *name) {
    int l = ctx->linenum;
    int m = ctx->bufpos - ctx->linepos;
    if (match_string(ctx, left)) {
        while (!match_string(ctx, right)) {
            if (match_eof(ctx)) {
                print_error("%s:%d:%d: Premature EOF in %s\n", ctx->iname, l + 1, m + 1, name);
                ctx->errnum++;
                break;
            }
            if (!match_eol(ctx)) match_character_any(ctx);
        }
        return TRUE;
    }
    return FALSE;
}

static bool_t match_quotation_(context *ctx, const char *left, const char *right, const char *name) {
    int l = ctx->linenum;
    int m = ctx->bufpos - ctx->linepos;
    if (match_string(ctx, left)) {
        while (!match_string(ctx, right)) {
            if (match_eof(ctx)) {
                print_error("%s:%d:%d: Premature EOF in %s\n", ctx->iname, l + 1, m + 1, name);
                ctx->errnum++;
                break;
            }
            if (match_character(ctx, '\\')) {
                if (!match_eol(ctx)) match_character_any(ctx);
            }
            else {
                if (match_eol(ctx)) {
                    print_error("%s:%d:%d: Premature EOL in %s\n", ctx->iname, l + 1, m + 1, name);
                    ctx->errnum++;
                    break;
                }
                match_character_any(ctx);
            }
        }
        return TRUE;
    }
    return FALSE;
}

static bool_t match_directive_c(context *ctx) {
    return match_section_line_continuable_(ctx, "#");
}

static bool_t match_comment(context *ctx) {
    return match_section_line_(ctx, "#");
}

static bool_t match_comment_c(context *ctx) {
    return match_section_block_(ctx, "/*", "*/", "C comment");
}

static bool_t match_comment_cxx(context *ctx) {
    return match_section_line_(ctx, "//");
}

static bool_t match_quotation_single(context *ctx) {
    return match_quotation_(ctx, "\'", "\'", "single quotation");
}

static bool_t match_quotation_double(context *ctx) {
    return match_quotation_(ctx, "\"", "\"", "double quotation");
}

static bool_t match_character_class(context *ctx) {
    return match_quotation_(ctx, "[", "]", "character class");
}

static bool_t match_spaces(context *ctx) {
    int n = 0;
    while (match_blank(ctx) || match_eol(ctx) || match_comment(ctx)) n++;
    return (n > 0) ? TRUE : FALSE;
}

static bool_t match_number(context *ctx) {
    if (match_character_range(ctx, '0', '9')) {
        while (match_character_range(ctx, '0', '9'));
        return TRUE;
    }
    return FALSE;
}

static bool_t match_identifier(context *ctx) {
    if (
        match_character_range(ctx, 'a', 'z') ||
        match_character_range(ctx, 'A', 'Z') ||
        match_character(ctx, '_')
    ) {
        while (
            match_character_range(ctx, 'a', 'z') ||
            match_character_range(ctx, 'A', 'Z') ||
            match_character_range(ctx, '0', '9') ||
            match_character(ctx, '_')
        );
        return TRUE;
    }
    return FALSE;
}

static bool_t match_code_block(context *ctx) {
    int l = ctx->linenum;
    int m = ctx->bufpos - ctx->linepos;
    if (match_character(ctx, '{')) {
        int d = 1;
        for (;;) {
            if (match_eof(ctx)) {
                print_error("%s:%d:%d: Premature EOF in code block\n", ctx->iname, l + 1, m + 1);
                ctx->errnum++;
                break;
            }
            if (
                match_directive_c(ctx) ||
                match_comment_c(ctx) ||
                match_comment_cxx(ctx) ||
                match_quotation_single(ctx) ||
                match_quotation_double(ctx)
            ) continue;
            if (match_character(ctx, '{')) {
                d++;
            }
            else if (match_character(ctx, '}')) {
                d--;
                if (d == 0) break;
            }
            else {
                if (!match_eol(ctx)) {
                    if (match_character(ctx, '$')) {
                        ctx->buffer.buf[ctx->bufpos - 1] = '_';
                    }
                    else {
                        match_character_any(ctx);
                    }
                }
            }
        }
        return TRUE;
    }
    return FALSE;
}

static bool_t match_footer_start(context *ctx) {
    return match_string(ctx, "%%");
}

static node *parse_expression(context *ctx, node *rule);

static node *parse_primary(context *ctx, node *rule) {
    int p = ctx->bufpos;
    int l = ctx->linenum;
    int m = ctx->bufpos - ctx->linepos;
    node *n_p = NULL;
    if (match_identifier(ctx)) {
        int q = ctx->bufpos;
        match_spaces(ctx);
        if (match_character(ctx, ':')) goto EXCEPTION;
        if (match_string(ctx, "<-")) goto EXCEPTION;
        n_p = create_node(NODE_REFERENCE);
        n_p->data.reference.name = strndup_e(ctx->buffer.buf + p, q - p);
        n_p->data.reference.line = l;
        n_p->data.reference.col = m;
    }
    else if (match_character(ctx, '(')) {
        match_spaces(ctx);
        n_p = parse_expression(ctx, rule);
        if (n_p == NULL) goto EXCEPTION;
        if (!match_character(ctx, ')')) goto EXCEPTION;
        match_spaces(ctx);
    }
    else if (match_character(ctx, '<')) {
        match_spaces(ctx);
        n_p = create_node(NODE_CAPTURE);
        n_p->data.capture.index = rule->data.rule.capts.len;
        node_const_array__add(&rule->data.rule.capts, n_p);
        n_p->data.capture.expr = parse_expression(ctx, rule);
        if (n_p->data.capture.expr == NULL || !match_character(ctx, '>')) {
            rule->data.rule.capts.len = n_p->data.capture.index;
            goto EXCEPTION;
        }
        match_spaces(ctx);
    }
    else if (match_character(ctx, '$')) {
        int p;
        match_spaces(ctx);
        p = ctx->bufpos;
        if (match_number(ctx)) {
            int q = ctx->bufpos;
            char *s;
            match_spaces(ctx);
            n_p = create_node(NODE_EXPAND);
            s = strndup_e(ctx->buffer.buf + p, q - p);
            n_p->data.expand.index = atoi(s);
            if (n_p->data.expand.index == 0) {
                print_error("%s:%d:%d: 0 not allowed\n", ctx->iname, l + 1, m + 1);
                ctx->errnum++;
            }
            else if (s[0] == '0') {
                print_error("%s:%d:%d: 0-prefixed number not allowed\n", ctx->iname, l + 1, m + 1);
                ctx->errnum++;
            }
            free(s);
            n_p->data.expand.index--;
            n_p->data.expand.line = l;
            n_p->data.expand.col = m;
        }
        else {
            goto EXCEPTION;
        }
    }
    else if (match_character(ctx, '.')) {
        match_spaces(ctx);
        n_p = create_node(NODE_CHARCLASS);
        n_p->data.charclass.value = NULL;
    }
    else if (match_character_class(ctx)) {
        int q = ctx->bufpos;
        match_spaces(ctx);
        n_p = create_node(NODE_CHARCLASS);
        n_p->data.charclass.value = strndup_e(ctx->buffer.buf + p + 1, q - p - 2);
        if (!unescape_string(n_p->data.charclass.value)) {
            print_error("%s:%d:%d: Illegal escape sequence\n", ctx->iname, l + 1, m + 1);
            ctx->errnum++;
        }
    }
    else if (match_quotation_single(ctx) || match_quotation_double(ctx)) {
        int q = ctx->bufpos;
        match_spaces(ctx);
        n_p = create_node(NODE_STRING);
        n_p->data.string.value = strndup_e(ctx->buffer.buf + p + 1, q - p - 2);
        if (!unescape_string(n_p->data.string.value)) {
            print_error("%s:%d:%d: Illegal escape sequence\n", ctx->iname, l + 1, m + 1);
            ctx->errnum++;
        }
    }
    else if (match_code_block(ctx)) {
        int q = ctx->bufpos;
        match_spaces(ctx);
        n_p = create_node(NODE_ACTION);
        n_p->data.action.value = strndup_e(ctx->buffer.buf + p + 1, q - p - 2);
        n_p->data.action.index = rule->data.rule.codes.len;
        node_const_array__add(&rule->data.rule.codes, n_p);
    }
    else {
        goto EXCEPTION;
    }
    return n_p;

EXCEPTION:;
    destroy_node(n_p);
    ctx->bufpos = p;
    ctx->linenum = l;
    ctx->linepos = p - m;
    return NULL;
}

static node *parse_term(context *ctx, node *rule) {
    int p = ctx->bufpos;
    int l = ctx->linenum;
    int m = ctx->bufpos - ctx->linepos;
    node *n_p = NULL;
    node *n_q = NULL;
    node *n_r = NULL;
    node *n_t = NULL;
    char t = match_character(ctx, '&') ? '&' : match_character(ctx, '!') ? '!' : '\0';
    if (t) match_spaces(ctx);
    n_p = parse_primary(ctx, rule);
    if (n_p == NULL) goto EXCEPTION;
    if (match_character(ctx, '*')) {
        match_spaces(ctx);
        n_q = create_node(NODE_QUANTITY);
        n_q->data.quantity.min = 0;
        n_q->data.quantity.max = -1;
        n_q->data.quantity.expr = n_p;
    }
    else if (match_character(ctx, '+')) {
        match_spaces(ctx);
        n_q = create_node(NODE_QUANTITY);
        n_q->data.quantity.min = 1;
        n_q->data.quantity.max = -1;
        n_q->data.quantity.expr = n_p;
    }
    else if (match_character(ctx, '?')) {
        match_spaces(ctx);
        n_q = create_node(NODE_QUANTITY);
        n_q->data.quantity.min = 0;
        n_q->data.quantity.max = 1;
        n_q->data.quantity.expr = n_p;
    }
    else {
        n_q = n_p;
    }
    switch (t) {
    case '&':
        n_r = create_node(NODE_PREDICATE);
        n_r->data.predicate.neg = FALSE;
        n_r->data.predicate.expr = n_q;
        break;
    case '!':
        n_r = create_node(NODE_PREDICATE);
        n_r->data.predicate.neg = TRUE;
        n_r->data.predicate.expr = n_q;
        break;
    default:
        n_r = n_q;
    }
    if (match_character(ctx, '~')) {
        int p;
        match_spaces(ctx);
        p = ctx->bufpos;
        if (match_code_block(ctx)) {
            int q = ctx->bufpos;
            match_spaces(ctx);
            n_t = create_node(NODE_ERROR);
            n_t->data.error.expr = n_r;
            n_t->data.error.value = strndup_e(ctx->buffer.buf + p + 1, q - p -2);
            n_t->data.error.index = rule->data.rule.codes.len;
            node_const_array__add(&rule->data.rule.codes, n_t);
        }
        else {
            goto EXCEPTION;
        }
    }
    else {
        n_t = n_r;
    }
    return n_t;

EXCEPTION:;
    destroy_node(n_r);
    ctx->bufpos = p;
    ctx->linenum = l;
    ctx->linepos = p - m;
    return NULL;
}

static node *parse_sequence(context *ctx, node *rule) {
    int p = ctx->bufpos;
    int l = ctx->linenum;
    int m = ctx->bufpos - ctx->linepos;
    node_array *a_t = NULL;
    node *n_t = NULL;
    node *n_u = NULL;
    node *n_s = NULL;
    n_t = parse_term(ctx, rule);
    if (n_t == NULL) goto EXCEPTION;
    n_u = parse_term(ctx, rule);
    if (n_u != NULL) {
        n_s = create_node(NODE_SEQUENCE);
        a_t = &n_s->data.sequence.nodes;
        node_array__add(a_t, n_t);
        node_array__add(a_t, n_u);
        while ((n_t = parse_term(ctx, rule)) != NULL) {
            node_array__add(a_t, n_t);
        }
    }
    else {
        n_s = n_t;
    }
    return n_s;

EXCEPTION:;
    ctx->bufpos = p;
    ctx->linenum = l;
    ctx->linepos = p - m;
    return NULL;
}

static node *parse_expression(context *ctx, node *rule) {
    int p = ctx->bufpos, q;
    int l = ctx->linenum;
    int m = ctx->bufpos - ctx->linepos;
    node_array *a_s = NULL;
    node *n_s = NULL;
    node *n_e = NULL;
    n_s = parse_sequence(ctx, rule);
    if (n_s == NULL) goto EXCEPTION;
    q = ctx->bufpos;
    if (match_character(ctx, '/')) {
        ctx->bufpos = q;
        n_e = create_node(NODE_ALTERNATE);
        a_s = &n_e->data.alternate.nodes;
        node_array__add(a_s, n_s);
        while (match_character(ctx, '/')) {
            match_spaces(ctx);
            n_s = parse_sequence(ctx, rule);
            if (n_s == NULL) goto EXCEPTION;
            node_array__add(a_s, n_s);
        }
    }
    else {
        n_e = n_s;
    }
    return n_e;

EXCEPTION:;
    destroy_node(n_e);
    ctx->bufpos = p;
    ctx->linenum = l;
    ctx->linepos = p - m;
    return NULL;
}

static node *parse_rule(context *ctx) {
    int p = ctx->bufpos, q;
    int l = ctx->linenum;
    int m = ctx->bufpos - ctx->linepos;
    node *n_r = NULL;
    if (!match_identifier(ctx)) goto EXCEPTION;
    q = ctx->bufpos;
    match_spaces(ctx);
    if (!match_string(ctx, "<-")) goto EXCEPTION;
    match_spaces(ctx);
    n_r = create_node(NODE_RULE);
    n_r->data.rule.expr = parse_expression(ctx, n_r);
    if (n_r->data.rule.expr == NULL) goto EXCEPTION;
    n_r->data.rule.name = strndup_e(ctx->buffer.buf + p, q - p);
    n_r->data.rule.line = l;
    n_r->data.rule.col = m;
    return n_r;

EXCEPTION:;
    destroy_node(n_r);
    ctx->bufpos = p;
    ctx->linenum = l;
    ctx->linepos = p - m;
    return NULL;
}

static const char *get_auxil_type(context *ctx) {
    return (ctx->atype && ctx->atype[0]) ? ctx->atype : "void *";
}

static const char *get_prefix(context *ctx) {
    return (ctx->prefix && ctx->prefix[0]) ? ctx->prefix : "pcc";
}

static void dump_options(context *ctx) {
    fprintf(stdout, "auxil:'%s'\n", get_auxil_type(ctx));
    fprintf(stdout, "prefix:'%s'\n", get_prefix(ctx));
    fprintf(stdout, "input-bsize:'%d'\n", ctx->inputbuffsize);
    fprintf(stdout, "parse-bsize:'%d'\n", ctx->parsebuffsize);
}

static bool_t parse_directive_include_(context *ctx, const char *name, FILE *output1, FILE *output2) {
    int l = ctx->linenum;
    int m = ctx->bufpos - ctx->linepos;
    if (!match_string(ctx, name)) return FALSE;
    match_spaces(ctx);
    {
        int p = ctx->bufpos;
        if (match_code_block(ctx)) {
            int q = ctx->bufpos;
            match_spaces(ctx);
            if (output1 != NULL) {
                write_code_block(output1, ctx->buffer.buf + p + 1, q - p - 2, 0);
                fputc('\n', output1);
            }
            if (output2 != NULL) {
                write_code_block(output2, ctx->buffer.buf + p + 1, q - p - 2, 0);
                fputc('\n', output2);
            }
        }
        else {
            print_error("%s:%d:%d: Illegal %s syntax\n", ctx->iname, l + 1, m + 1, name);
            ctx->errnum++;
        }
    }
    return TRUE;
}

static bool_t parse_directive_string_(context *ctx, const char *name, char **output, string_flag mode) {
    int l = ctx->linenum;
    int m = ctx->bufpos - ctx->linepos;
    if (!match_string(ctx, name)) return FALSE;
    match_spaces(ctx);
    {
        char *s = NULL;
        int p = ctx->bufpos, q;
        int lv = ctx->linenum;
        int mv = ctx->bufpos - ctx->linepos;
        if (match_quotation_single(ctx) || match_quotation_double(ctx)) {
            q = ctx->bufpos;
            match_spaces(ctx);
            s = strndup_e(ctx->buffer.buf + p + 1, q - p - 2);
            if (!unescape_string(s)) {
                print_error("%s:%d:%d: Illegal escape sequence\n", ctx->iname, lv + 1, mv + 1);
                ctx->errnum++;
            }
        }
        else {
            print_error("%s:%d:%d: Illegal %s syntax\n", ctx->iname, l + 1, m + 1, name);
            ctx->errnum++;
        }
        if (s != NULL) {
            string_flag f = STRING_FLAG__NONE;
            bool_t b = TRUE;
            remove_heading_blank(s);
            remove_trailing_blank(s);
            assert((mode & ~7) == 0);
            if ((mode & STRING_FLAG__NOTEMPTY) && !is_filled_string(s)) {
                print_error("%s:%d:%d: Empty string\n", ctx->iname, lv + 1, mv + 1);
                ctx->errnum++;
                f |= STRING_FLAG__NOTEMPTY;
            }
            if ((mode & STRING_FLAG__NOTVOID) && strcmp(s, "void") == 0) {
                print_error("%s:%d:%d: 'void' not allowed\n", ctx->iname, lv + 1, mv + 1);
                ctx->errnum++;
                f |= STRING_FLAG__NOTVOID;
            }
            if ((mode & STRING_FLAG__IDENTIFIER) && !is_identifier_string(s)) {
                if (!(f & STRING_FLAG__NOTEMPTY)) {
                    print_error("%s:%d:%d: Invalid identifier\n", ctx->iname, lv + 1, mv + 1);
                    ctx->errnum++;
                }
                f |= STRING_FLAG__IDENTIFIER;
            }
            if (*output != NULL) {
                print_error("%s:%d:%d: Multiple %s definition\n", ctx->iname, l + 1, m + 1, name);
                ctx->errnum++;
                b = FALSE;
            }
            if (f == STRING_FLAG__NONE && b) {
                *output = s;
            }
            else {
                free(s); s = NULL;
            }
        }
    }
    return TRUE;
}

static bool_t parse_directive_unsigned_(context *ctx, const char *name, unsigned *output) {
    if (!match_string(ctx, name)) return FALSE;
    match_spaces(ctx);
    int p = ctx->bufpos;
    int lv = ctx->linenum;
    int mv = ctx->bufpos - ctx->linepos;
    if (!match_number(ctx)) {
        print_error("%s:%d:%d: Illegal escape sequence\n", ctx->iname, lv + 1, mv + 1);
        ctx->errnum++;
	}
    match_spaces(ctx);
	*output = atoi(ctx->buffer.buf + p);
    return TRUE;
}

static bool_t parse(context *ctx) {
    fprintf(ctx->sfile, "/* A packrat parser generated by PackCC %s */\n\n", VERSION);
    fprintf(ctx->hfile, "/* A packrat parser generated by PackCC %s */\n\n", VERSION);
    {
        fputs(
            "#ifdef _MSC_VER\n"
            "#define _CRT_SECURE_NO_WARNINGS\n"
            "#endif /* _MSC_VER */\n"
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
			"#include <stdint.h>\n"
			"#include <string.h>\n"
            "\n"
            "#ifndef _MSC_VER\n"
            "#if defined __GNUC__ && defined _WIN32 /* MinGW */\n"
            "static size_t strnlen(const char *str, size_t maxlen) {\n"
            "    size_t i;\n"
            "    for (i = 0; str[i] && i < maxlen; i++);\n"
            "    return i;\n"
            "}\n"
            "#else\n"
            "#include <unistd.h> /* for strnlen() */\n"
            "#endif /* defined __GNUC__ && defined _WIN32 */ \n"
            "#endif /* _MSC_VER */\n"
            "\n",
            ctx->sfile
        );
        fprintf(
            ctx->sfile,
            "#include \"%s\"\n"
            "\n",
            ctx->hname
        );
    }
    {
        fprintf(
            ctx->hfile,
            "#pragma once\n\n"
        );
    }
    {
        bool_t b = TRUE;
        match_spaces(ctx);
        for (;;) {
            int p, l, m;
            if (match_eof(ctx) || match_footer_start(ctx)) break;
            p = ctx->bufpos;
            l = ctx->linenum;
            m = ctx->bufpos - ctx->linepos;
            if (
                parse_directive_include_(ctx, "%source", ctx->sfile, NULL) ||
                parse_directive_include_(ctx, "%header", ctx->hfile, NULL) ||
                parse_directive_include_(ctx, "%common", ctx->sfile, ctx->hfile) ||
                parse_directive_string_(ctx, "%auxil", &ctx->atype, STRING_FLAG__NOTEMPTY | STRING_FLAG__NOTVOID) ||
                parse_directive_string_(ctx, "%prefix", &ctx->prefix, STRING_FLAG__NOTEMPTY | STRING_FLAG__IDENTIFIER) ||
                parse_directive_unsigned_(ctx, "%input-bsize", &ctx->inputbuffsize) ||
                parse_directive_unsigned_(ctx, "%parse-bsize", &ctx->parsebuffsize)
            ) {
                b = TRUE;
            }
            else if (match_character(ctx, '%')) {
                print_error("%s(%d): %d: Invalid directive\n", ctx->iname, l + 1, m + 1);
                ctx->errnum++;
                match_identifier(ctx);
                match_spaces(ctx);
                b = TRUE;
            }
            else {
                node *n_r = parse_rule(ctx);
                if (n_r == NULL) {
                    if (b) {
                        print_error("%s(%d): %d: Illegal rule syntax\n", ctx->iname, l + 1, m + 1);
                        ctx->errnum++;
                        b = FALSE;
                    }
                    ctx->linenum = l;
                    ctx->linepos = p - m;
                    if (!match_identifier(ctx) && !match_spaces(ctx)) match_character_any(ctx);
                    continue;
                }
                node_array__add(&ctx->rules, n_r);
                b = TRUE;
            }
            commit_buffer(ctx);
        }
        commit_buffer(ctx);
    }
    {
        int i;
        make_rulehash(ctx);
        for (i = 0; i < ctx->rules.len; i++) {
            link_references(ctx, ctx->rules.buf[i]->data.rule.expr);
        }
        for (i = 1; i < ctx->rules.len; i++) {
            if (ctx->rules.buf[i]->data.rule.ref == 0) {
                print_error("%s(%d): %d: Never used rule '%s'\n",
                    ctx->iname, ctx->rules.buf[i]->data.rule.line + 1, ctx->rules.buf[i]->data.rule.col + 1, ctx->rules.buf[i]->data.rule.name);
                ctx->errnum++;
            }
            else if (ctx->rules.buf[i]->data.rule.ref < 0) {
                print_error("%s(%d): %d: Multiple definition of rule '%s'\n",
                    ctx->iname, ctx->rules.buf[i]->data.rule.line + 1, ctx->rules.buf[i]->data.rule.col + 1, ctx->rules.buf[i]->data.rule.name);
                ctx->errnum++;
            }
        }
    }
    {
        int i;
        for (i = 0; i < ctx->rules.len; i++) {
           verify_captures(ctx, ctx->rules.buf[i]->data.rule.expr, NULL);
        }
    }
    if (ctx->debug) {
        int i;
        for (i = 0; i < ctx->rules.len; i++) {
            dump_node(ctx, ctx->rules.buf[i]);
        }
        dump_options(ctx);
    }
    return (ctx->errnum == 0) ? TRUE : FALSE;
}

static code_reach generate_matching_string_code(generated *gen, const char *value, int onfail, int indent, bool_t bare) {
    int n = (value != NULL) ? (int)strlen(value) : 0;
    if (n > 0) {
        char s[5];
        if (n > 1)
		{
            int i;
            if (!bare) {
                write_characters(gen->stream, ' ', indent);
                fputs("{\n", gen->stream);
                indent += 4;
            }
			write_characters(gen->stream, ' ', indent);
			fputs("if (", gen->stream);
            fprintf(gen->stream, "pcc_refill_buffer(ctx, %d) < %d\n", n, n);
            write_characters(gen->stream, ' ', indent);
            fprintf(gen->stream, ") goto L%04d;\n", onfail);

			write_characters(gen->stream, ' ', indent);
            fputs("const char *s = ctx->buffer.buf + ctx->pos;\n", gen->stream);
			
			write_characters(gen->stream, ' ', indent);
			fputs("if (", gen->stream);
            for (i = 0; i < n - 1; i++) {
				if ( i > 0 )
					write_characters(gen->stream, ' ', indent + 4);
                fprintf(gen->stream, "s[%d] != '%s' ||\n", i, escape_character(value[i], &s));
            }
            write_characters(gen->stream, ' ', indent + 4);
            fprintf(gen->stream, "s[%d] != '%s'\n", i, escape_character(value[i], &s));
            write_characters(gen->stream, ' ', indent);
            fprintf(gen->stream, ") goto L%04d;\n", onfail);
            write_characters(gen->stream, ' ', indent);
            fprintf(gen->stream, "ctx->pos += %d;\n", n);
            if (!bare) {
                indent -= 4;
                write_characters(gen->stream, ' ', indent);
                fputs("}\n", gen->stream);
            }
            return CODE_REACH__BOTH;
       }
       else {
            write_characters(gen->stream, ' ', indent);
            fputs("if (\n", gen->stream);
            write_characters(gen->stream, ' ', indent + 4);
            fputs("pcc_refill_buffer(ctx, 1) < 1 ||\n", gen->stream);
            write_characters(gen->stream, ' ', indent + 4);
            fprintf(gen->stream, "ctx->buffer.buf[ctx->pos] != '%s'\n", escape_character(value[0], &s));
            write_characters(gen->stream, ' ', indent);
            fprintf(gen->stream, ") goto L%04d;\n", onfail);
            write_characters(gen->stream, ' ', indent);
            fputs("ctx->pos++;\n", gen->stream);
            return CODE_REACH__BOTH;
	   }
    }
    else {
        /* no code to generate */
        return CODE_REACH__ALWAYS_SUCCEED;
    }
}

static code_reach generate_matching_charclass_code(generated *gen, const char *value, int onfail, int indent, bool_t bare) {
    if (value != NULL) {
        size_t n = strlen(value);
        if (n > 0) {
            char s[5], t[5];
            if (n > 1) {
                bool_t a = (value[0] == '^') ? TRUE : FALSE;
                size_t i = a ? 1 : 0;
                if (i + 1 == n) { /* fulfilled only if a == TRUE */
                    write_characters(gen->stream, ' ', indent);
                    fputs("if (\n", gen->stream);
                    write_characters(gen->stream, ' ', indent + 4);
                    fputs("pcc_refill_buffer(ctx, 1) < 1 ||\n", gen->stream);
                    write_characters(gen->stream, ' ', indent + 4);
                    fprintf(gen->stream, "ctx->buffer.buf[ctx->pos] == '%s'\n", escape_character(value[i], &s));
                    write_characters(gen->stream, ' ', indent);
                    fprintf(gen->stream, ") goto L%04d;\n", onfail);
                    write_characters(gen->stream, ' ', indent);
                    fputs("ctx->pos++;\n", gen->stream);
                    return CODE_REACH__BOTH;
                }
                else {
                    if (!bare) {
                        write_characters(gen->stream, ' ', indent);
                        fputs("{\n", gen->stream);
                        indent += 4;
                    }
                    write_characters(gen->stream, ' ', indent);
                    fputs("char c;\n", gen->stream);
                    write_characters(gen->stream, ' ', indent);
                    fprintf(gen->stream, "if (pcc_refill_buffer(ctx, 1) < 1) goto L%04d;\n", onfail);
                    write_characters(gen->stream, ' ', indent);
                    fputs("c = ctx->buffer.buf[ctx->pos];\n", gen->stream);
                    if (i + 3 == n && value[i + 1] == '-') {
                        write_characters(gen->stream, ' ', indent);
                        fprintf(gen->stream,
                            a ? "if (c >= '%s' && c <= '%s') goto L%04d;\n"
                              : "if (!(c >= '%s' && c <= '%s')) goto L%04d;\n",
                            escape_character(value[i], &s), escape_character(value[i + 2], &t), onfail);
                    }
                    else {
                        write_characters(gen->stream, ' ', indent);
                        fputs(a ? "if (\n" : "if (!(\n", gen->stream);
                        for (; i < n; i++) {
                            write_characters(gen->stream, ' ', indent + 4);
                            if (i + 2 < n && value[i + 1] == '-') {
                                fprintf(gen->stream, "(c >= '%s' && c <= '%s')%s\n",
                                    escape_character(value[i], &s), escape_character(value[i + 2], &t), (i + 3 == n) ? "" : " ||");
                                i += 2;
                            }
                            else {
                                fprintf(gen->stream, "c == '%s'%s\n",
                                    escape_character(value[i], &s), (i + 1 == n) ? "" : " ||");
                            }
                        }
                        write_characters(gen->stream, ' ', indent);
                        fprintf(gen->stream, a ? ") goto L%04d;\n" : ")) goto L%04d;\n", onfail);
                    }
                    write_characters(gen->stream, ' ', indent);
                    fputs("ctx->pos++;\n", gen->stream);
                    if (!bare) {
                        indent -= 4;
                        write_characters(gen->stream, ' ', indent);
                        fputs("}\n", gen->stream);
                    }
                    return CODE_REACH__BOTH;
                }
            }
            else {
                write_characters(gen->stream, ' ', indent);
                fputs("if (\n", gen->stream);
                write_characters(gen->stream, ' ', indent + 4);
                fputs("pcc_refill_buffer(ctx, 1) < 1 ||\n", gen->stream);
                write_characters(gen->stream, ' ', indent + 4);
                fprintf(gen->stream, "ctx->buffer.buf[ctx->pos] != '%s'\n", escape_character(value[0], &s));
                write_characters(gen->stream, ' ', indent);
                fprintf(gen->stream, ") goto L%04d;\n", onfail);
                write_characters(gen->stream, ' ', indent);
                fputs("ctx->pos++;\n", gen->stream);
                return CODE_REACH__BOTH;
            }
        }
        else {
            write_characters(gen->stream, ' ', indent);
            fprintf(gen->stream, "goto L%04d;\n", onfail);
            return CODE_REACH__ALWAYS_FAIL;
        }
    }
    else {
        write_characters(gen->stream, ' ', indent);
        fprintf(gen->stream, "if (pcc_refill_buffer(ctx, 1) < 1) goto L%04d;\n", onfail);
        write_characters(gen->stream, ' ', indent);
        fputs("ctx->pos++;\n", gen->stream);
        return CODE_REACH__BOTH;
    }
}

static code_reach generate_code(generated *gen, const node *node, int onfail, int indent, bool_t bare);

static code_reach generate_quantifying_code(generated *gen, const node *expr, int min, int max, int onfail, int indent, bool_t bare) {
    if (max > 1 || max < 0) {
        code_reach r;
        if (!bare) {
            write_characters(gen->stream, ' ', indent);
            fputs("{\n", gen->stream);
            indent += 4;
        }
        if (min > 0) {
            write_characters(gen->stream, ' ', indent);
            fputs("int p = ctx->pos;\n", gen->stream);
        }
        write_characters(gen->stream, ' ', indent);
        fputs("int i;\n", gen->stream);
        write_characters(gen->stream, ' ', indent);
        if (max < 0)
            fputs("for (i = 0;; i++) {\n", gen->stream);
        else
            fprintf(gen->stream, "for (i = 0; i < %d; i++) {\n", max);
        {
            int l = ++gen->label;
            r = generate_code(gen, expr, l, indent + 4, TRUE);
            write_characters(gen->stream, ' ', indent);
            fputs("}\n", gen->stream);
            if (r != CODE_REACH__ALWAYS_SUCCEED) {
                write_characters(gen->stream, ' ', indent - 4);
                fprintf(gen->stream, "L%04d:;\n", l);
            }
            else if (max < 0) {
                print_error("Warning: Infinite loop detected in generated code\n");
            }
        }
        if (min > 0) {
            write_characters(gen->stream, ' ', indent);
            fprintf(gen->stream, "if (i < %d) {\n", min);
            write_characters(gen->stream, ' ', indent + 4);
            fputs("ctx->pos = p;\n", gen->stream);
            write_characters(gen->stream, ' ', indent + 4);
            fprintf(gen->stream, "goto L%04d;\n", onfail);
            write_characters(gen->stream, ' ', indent);
            fputs("}\n", gen->stream);
        }
        if (!bare) {
            indent -= 4;
            write_characters(gen->stream, ' ', indent);
            fputs("}\n", gen->stream);
        }
        return (min > 0) ? ((r == CODE_REACH__ALWAYS_FAIL) ? CODE_REACH__ALWAYS_FAIL : CODE_REACH__BOTH) : CODE_REACH__ALWAYS_SUCCEED;
    }
    else if (max == 1) {
        if (min > 0) {
            return generate_code(gen, expr, onfail, indent, bare);
        }
        else {
            int l = ++gen->label;
            if (generate_code(gen, expr, l, indent, bare) != CODE_REACH__ALWAYS_SUCCEED) {
                write_characters(gen->stream, ' ', indent - 4);
                fprintf(gen->stream, "L%04d:;\n", l);
            }
            return CODE_REACH__ALWAYS_SUCCEED;
        }
    }
    else {
        /* no code to generate */
        return CODE_REACH__ALWAYS_SUCCEED;
    }
}

static code_reach generate_predicating_code(generated *gen, const node *expr, bool_t neg, int onfail, int indent, bool_t bare) {
    code_reach r;
    if (!bare) {
        write_characters(gen->stream, ' ', indent);
        fputs("{\n", gen->stream);
        indent += 4;
    }
    write_characters(gen->stream, ' ', indent);
    fputs("int p = ctx->pos;\n", gen->stream);
    if (neg) {
        int l = ++gen->label;
        r = generate_code(gen, expr, l, indent, FALSE);
        if (r != CODE_REACH__ALWAYS_FAIL) {
            write_characters(gen->stream, ' ', indent);
            fputs("ctx->pos = p;\n", gen->stream);
            write_characters(gen->stream, ' ', indent);
            fprintf(gen->stream, "goto L%04d;\n", onfail);
        }
        if (r != CODE_REACH__ALWAYS_SUCCEED) {
            write_characters(gen->stream, ' ', indent - 4);
            fprintf(gen->stream, "L%04d:;\n", l);
            write_characters(gen->stream, ' ', indent);
            fputs("ctx->pos = p;\n", gen->stream);
        }
        switch (r) {
        case CODE_REACH__ALWAYS_SUCCEED: r = CODE_REACH__ALWAYS_FAIL; break;
        case CODE_REACH__ALWAYS_FAIL: r = CODE_REACH__ALWAYS_SUCCEED; break;
        case CODE_REACH__BOTH: break;
        }
    }
    else {
        int l = ++gen->label;
        int m = ++gen->label;
        r = generate_code(gen, expr, l, indent, FALSE);
        if (r != CODE_REACH__ALWAYS_FAIL) {
            write_characters(gen->stream, ' ', indent);
            fputs("ctx->pos = p;\n", gen->stream);
        }
        if (r == CODE_REACH__BOTH) {
            write_characters(gen->stream, ' ', indent);
            fprintf(gen->stream, "goto L%04d;\n", m);
        }
        if (r != CODE_REACH__ALWAYS_SUCCEED) {
            write_characters(gen->stream, ' ', indent - 4);
            fprintf(gen->stream, "L%04d:;\n", l);
            write_characters(gen->stream, ' ', indent);
            fputs("ctx->pos = p;\n", gen->stream);
            write_characters(gen->stream, ' ', indent);
            fprintf(gen->stream, "goto L%04d;\n", onfail);
        }
        if (r == CODE_REACH__BOTH) {
            write_characters(gen->stream, ' ', indent - 4);
            fprintf(gen->stream, "L%04d:;\n", m);
        }
    }
    if (!bare) {
        indent -= 4;
        write_characters(gen->stream, ' ', indent);
        fputs("}\n", gen->stream);
    }
    return r;
}

static code_reach generate_sequential_code(generated *gen, const node_array *nodes, int onfail, int indent, bool_t bare) {
    bool_t b = FALSE;
    int i;
    for (i = 0; i < nodes->len; i++) {
        switch (generate_code(gen, nodes->buf[i], onfail, indent, FALSE)) {
        case CODE_REACH__ALWAYS_FAIL:
            if (i < nodes->len - 1) {
                write_characters(gen->stream, ' ', indent);
                fputs("/* unreachable codes omitted */\n", gen->stream);
            }
            return CODE_REACH__ALWAYS_FAIL;
        case CODE_REACH__ALWAYS_SUCCEED:
            break;
        default:
            b = TRUE;
        }
    }
    return b ? CODE_REACH__BOTH : CODE_REACH__ALWAYS_SUCCEED;
}

static code_reach generate_alternative_code(generated *gen, const node_array *nodes, int onfail, int indent, bool_t bare) {
    bool_t b = FALSE;
    int i, m = ++gen->label;
    if (!bare) {
        write_characters(gen->stream, ' ', indent);
        fputs("{\n", gen->stream);
        indent += 4;
    }
    write_characters(gen->stream, ' ', indent);
    fputs("int p = ctx->pos;\n", gen->stream);
    write_characters(gen->stream, ' ', indent);
    fputs("int n = chunk->thunks.len;\n", gen->stream);
    for (i = 0; i < nodes->len; i++) {
        bool_t c = (i < nodes->len - 1) ? TRUE : FALSE;
        int l = ++gen->label;
        switch (generate_code(gen, nodes->buf[i], l, indent, FALSE)) {
        case CODE_REACH__ALWAYS_SUCCEED:
            if (c) {
                write_characters(gen->stream, ' ', indent);
                fputs("/* unreachable codes omitted */\n", gen->stream);
            }
            if (b) {
                write_characters(gen->stream, ' ', indent - 4);
                fprintf(gen->stream, "L%04d:;\n", m);
            }
            if (!bare) {
                indent -= 4;
                write_characters(gen->stream, ' ', indent);
                fputs("}\n", gen->stream);
            }
            return CODE_REACH__ALWAYS_SUCCEED;
        case CODE_REACH__ALWAYS_FAIL:
            break;
        default:
            b = TRUE;
            write_characters(gen->stream, ' ', indent);
            fprintf(gen->stream, "goto L%04d;\n", m);
        }
        write_characters(gen->stream, ' ', indent - 4);
        fprintf(gen->stream, "L%04d:;\n", l);
        write_characters(gen->stream, ' ', indent);
        fputs("ctx->pos = p;\n", gen->stream);
        write_characters(gen->stream, ' ', indent);
        fputs("pcc_thunk_array__revert(ctx, &chunk->thunks, n);\n", gen->stream);
        if (!c) {
            write_characters(gen->stream, ' ', indent);
            fprintf(gen->stream, "goto L%04d;\n", onfail);
        }
    }
    if (b) {
        write_characters(gen->stream, ' ', indent - 4);
        fprintf(gen->stream, "L%04d:;\n", m);
    }
    if (!bare) {
        indent -= 4;
        write_characters(gen->stream, ' ', indent);
        fputs("}\n", gen->stream);
    }
    return b ? CODE_REACH__BOTH : CODE_REACH__ALWAYS_FAIL;
}

static code_reach generate_capturing_code(generated *gen, const node *expr, int index, int onfail, int indent, bool_t bare) {
    code_reach r;
    if (!bare) {
        write_characters(gen->stream, ' ', indent);
        fputs("{\n", gen->stream);
        indent += 4;
    }
    write_characters(gen->stream, ' ', indent);
    fputs("int p = ctx->pos, q;\n", gen->stream);
    r = generate_code(gen, expr, onfail, indent, FALSE);
    write_characters(gen->stream, ' ', indent);
    fputs("q = ctx->pos;\n", gen->stream);
    write_characters(gen->stream, ' ', indent);
    fprintf(gen->stream, "chunk->capts.buf[%d].range.start = p;\n", index);
    write_characters(gen->stream, ' ', indent);
    fprintf(gen->stream, "chunk->capts.buf[%d].range.end = q;\n", index);
    if (!bare) {
        indent -= 4;
        write_characters(gen->stream, ' ', indent);
        fputs("}\n", gen->stream);
    }
    return r;
}

static code_reach generate_expanding_code(generated *gen, int index, int onfail, int indent, bool_t bare) {
    if (!bare) {
        write_characters(gen->stream, ' ', indent);
        fputs("{\n", gen->stream);
        indent += 4;
    }
    write_characters(gen->stream, ' ', indent);
    fprintf(gen->stream, "int n = chunk->capts.buf[%d].range.end - chunk->capts.buf[%d].range.start;\n", index, index);
    write_characters(gen->stream, ' ', indent);
    fprintf(gen->stream, "if (pcc_refill_buffer(ctx, n) < n) goto L%04d;\n", onfail);
    write_characters(gen->stream, ' ', indent);
    fputs("if (n > 0) {\n", gen->stream);
    write_characters(gen->stream, ' ', indent + 4);
    fputs("const char *p = ctx->buffer.buf + ctx->pos;\n", gen->stream);
    write_characters(gen->stream, ' ', indent + 4);
    fprintf(gen->stream, "const char *q = ctx->buffer.buf + chunk->capts.buf[%d].range.start;\n", index);
    write_characters(gen->stream, ' ', indent + 4);
    fputs("int i;\n", gen->stream);
    write_characters(gen->stream, ' ', indent + 4);
    fputs("for (i = 0; i < n; i++) {\n", gen->stream);
    write_characters(gen->stream, ' ', indent + 8);
    fprintf(gen->stream, "if (p[i] != q[i]) goto L%04d;\n", onfail);
    write_characters(gen->stream, ' ', indent + 4);
    fputs("}\n", gen->stream);
    write_characters(gen->stream, ' ', indent + 4);
    fputs("ctx->pos += n;\n", gen->stream);
    write_characters(gen->stream, ' ', indent);
    fputs("}\n", gen->stream);
    if (!bare) {
        indent -= 4;
        write_characters(gen->stream, ' ', indent);
        fputs("}\n", gen->stream);
    }
    return CODE_REACH__BOTH;
}

code_reach generate_thunking_action_code(
    generated *gen, int index, const node_const_array *vars, const node_const_array *capts, bool_t error, int onfail, int indent, bool_t bare
) {
    assert(gen->rule->type == NODE_RULE);
    if (!bare) {
        write_characters(gen->stream, ' ', indent);
        fputs("{\n", gen->stream);
        indent += 4;
    }
    write_characters(gen->stream, ' ', indent);
    fprintf(gen->stream, "pcc_thunk_t *thunk = pcc_thunk__create_leaf(ctx, pcc_action_%s_%d, %d);\n",
        gen->rule->data.rule.name, index, gen->rule->data.rule.capts.len);
    {
        int i;
        for (i = 0; i < capts->len; i++) {
            assert(capts->buf[i]->type == NODE_CAPTURE);
            write_characters(gen->stream, ' ', indent);
            fprintf(gen->stream, "thunk->data.leaf.capts.buf[%d] = &(chunk->capts.buf[%d]);\n",
                capts->buf[i]->data.capture.index, capts->buf[i]->data.capture.index);
        }
        write_characters(gen->stream, ' ', indent);
        fputs("thunk->data.leaf.capt0.range.start = chunk->pos;\n", gen->stream);
        write_characters(gen->stream, ' ', indent);
        fputs("thunk->data.leaf.capt0.range.end = ctx->pos;\n", gen->stream);
    }
    if (error) {
        write_characters(gen->stream, ' ', indent);
        fputs("thunk->data.leaf.action(ctx, thunk);\n", gen->stream);
    }
    else {
        write_characters(gen->stream, ' ', indent);
        fputs("pcc_thunk_array__add(ctx, &chunk->thunks, thunk);\n", gen->stream);
    }
    if (!bare) {
        indent -= 4;
        write_characters(gen->stream, ' ', indent);
        fputs("}\n", gen->stream);
    }
    return CODE_REACH__ALWAYS_SUCCEED;
}

code_reach generate_thunking_error_code(
    generated *gen, const node *expr, int index, const node_const_array *vars, const node_const_array *capts, int onfail, int indent, bool_t bare
) {
    code_reach r;
    int l = ++gen->label;
    int m = ++gen->label;
    assert(gen->rule->type == NODE_RULE);
    if (!bare) {
        write_characters(gen->stream, ' ', indent);
        fputs("{\n", gen->stream);
        indent += 4;
    }
    r = generate_code(gen, expr, l, indent, TRUE);
    write_characters(gen->stream, ' ', indent);
    fprintf(gen->stream, "goto L%04d;\n", m);
    write_characters(gen->stream, ' ', indent - 4);
    fprintf(gen->stream, "L%04d:;\n", l);
    generate_thunking_action_code(gen, index, vars, capts, TRUE, l, indent, FALSE);
    write_characters(gen->stream, ' ', indent);
    fprintf(gen->stream, "goto L%04d;\n", onfail);
    write_characters(gen->stream, ' ', indent - 4);
    fprintf(gen->stream, "L%04d:;\n", m);
    if (!bare) {
        indent -= 4;
        write_characters(gen->stream, ' ', indent);
        fputs("}\n", gen->stream);
    }
    return r;
}

static code_reach generate_code(generated *gen, const node *node, int onfail, int indent, bool_t bare) {
    if (node == NULL) {
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    }
    switch (node->type) {
    case NODE_RULE:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    case NODE_REFERENCE:
        write_characters(gen->stream, ' ', indent);
        fprintf(gen->stream, "if (!pcc_apply_rule(ctx, pcc_evaluate_rule_%s, &chunk->thunks)) goto L%04d;\n",
            node->data.reference.name, onfail);
        return CODE_REACH__BOTH;
    case NODE_STRING:
        return generate_matching_string_code(gen, node->data.string.value, onfail, indent, bare);
    case NODE_CHARCLASS:
        return generate_matching_charclass_code(gen, node->data.charclass.value, onfail, indent, bare);
    case NODE_QUANTITY:
        return generate_quantifying_code(gen, node->data.quantity.expr, node->data.quantity.min, node->data.quantity.max, onfail, indent, bare);
    case NODE_PREDICATE:
        return generate_predicating_code(gen, node->data.predicate.expr, node->data.predicate.neg, onfail, indent, bare);
    case NODE_SEQUENCE:
        return generate_sequential_code(gen, &node->data.sequence.nodes, onfail, indent, bare);
    case NODE_ALTERNATE:
        return generate_alternative_code(gen, &node->data.alternate.nodes, onfail, indent, bare);
    case NODE_CAPTURE:
        return generate_capturing_code(gen, node->data.capture.expr, node->data.capture.index, onfail, indent, bare);
    case NODE_EXPAND:
        return generate_expanding_code(gen, node->data.expand.index, onfail, indent, bare);
    case NODE_ACTION:
        return generate_thunking_action_code(
            gen, node->data.action.index, &node->data.action.vars, &node->data.action.capts, FALSE, onfail, indent, bare
        );
    case NODE_ERROR:
        return generate_thunking_error_code(
            gen, node->data.error.expr, node->data.error.index, &node->data.error.vars, &node->data.error.capts, onfail, indent, bare
        );
    default:
        print_error("Internal error [%d]\n", __LINE__);
        exit(-1);
    }
}

static bool_t generate(context *ctx) {
    const char *at = get_auxil_type(ctx);
    bool_t ap = is_pointer_type(at);
    FILE *stream = ctx->sfile;
    {
        fputs(
            "#ifndef PCC_ARRAYSIZE\n"
            "#define PCC_ARRAYSIZE 2\n"
            "#endif /* PCC_ARRAYSIZE */\n"
            "\n"
            "enum pcc_bool_t {\n"
            "    PCC_FALSE = 0,\n"
            "    PCC_TRUE\n"
            "};\n"
            "\n"
            "struct pcc_char_array_t {\n"
            "    using item_t = char ;\n"
            "    item_t *buf;\n"
            "    int max;\n"
            "    int len;\n"
			"};\n"
            "\n"
            "struct pcc_range_t {\n"
            "    int start;\n"
            "    int end;\n"
            "};\n"
            "\n",
            stream
        );
        fprintf(
            stream,
            "using pcc_auxil_t = %s;\n"
            "\n",
            at
        );
        fprintf(
            stream,
            "using pcc_context_t = pcc_%s_Context_t;\n"
            "\n",
			get_prefix(ctx)
        );
        fputs(
            "struct pcc_capture_t {\n"
            "    pcc_range_t range;\n"
            "};\n"
            "\n"
            "struct pcc_capture_table_t {\n"
            "    using item_t = pcc_capture_t;\n"
            "    item_t *buf;\n"
            "    int max;\n"
            "    int len;\n"
            "};\n"
            "\n"
            "struct pcc_capture_const_table_t {\n"
            "    using item_t = const pcc_capture_t*;\n"
            "    item_t *buf;\n"
            "    int max;\n"
            "    int len;\n"
            "};\n"
            "\n"
            "struct pcc_thunk_t;\n"
            "struct pcc_thunk_array_t;\n"
            "\n",
            stream
        );
        fprintf(
            stream,
            "typedef void (*pcc_action_t)(pcc_context_t*, pcc_thunk_t *);\n"
            "\n"
        );
        fputs(
            "enum pcc_thunk_type_t {\n"
            "    PCC_THUNK_LEAF,\n"
            "    PCC_THUNK_NODE,\n"
            "};\n"
            "\n"
            "struct pcc_thunk_leaf_t {\n"
            "    pcc_capture_const_table_t capts;\n"
            "    pcc_capture_t capt0;\n"
            "    pcc_action_t action;\n"
            "};\n"
            "\n"
            "struct pcc_thunk_node_t {\n"
            "    const pcc_thunk_array_t *thunks; /* just a reference */\n"
            "};\n"
            "\n"
            "union pcc_thunk_data_t {\n"
            "    pcc_thunk_leaf_t leaf;\n"
            "    pcc_thunk_node_t node;\n"
            "};\n"
            "\n"
            "struct pcc_thunk_t {\n"
            "    pcc_thunk_type_t type;\n"
            "    pcc_thunk_data_t data;\n"
            "};\n"
            "\n"
            "struct pcc_thunk_array_t {\n"
			"    using item_t = pcc_thunk_t*;\n"
            "    item_t *buf;\n"
            "    int max;\n"
            "    int len;\n"
            "};\n"
            "\n"
            "struct pcc_thunk_chunk_t {\n"
            "    pcc_capture_table_t capts;\n"
            "    pcc_thunk_array_t thunks;\n"
            "    int pos;\n"
            "};\n"
            "\n"
            "struct pcc_lr_entry_t;\n"
            "\n"
            "enum pcc_lr_answer_type_t {\n"
            "    PCC_LR_ANSWER_LR,\n"
            "    PCC_LR_ANSWER_CHUNK,\n"
            "};\n"
            "\n"
            "union pcc_lr_answer_data_t {\n"
            "    pcc_lr_entry_t *lr;\n"
            "    pcc_thunk_chunk_t *chunk;\n"
            "};\n"
            "\n"
            "struct pcc_lr_answer_t;\n"
            "\n"
            "struct pcc_lr_answer_t {\n"
            "    pcc_lr_answer_type_t type;\n"
            "    pcc_lr_answer_data_t data;\n"
            "    int pos;\n"
            "    pcc_lr_answer_t *hold;\n"
            "};\n"
            "\n",
            stream
        );
        fprintf(
            stream,
            "using pcc_rule_t = pcc_thunk_chunk_t* (*)(pcc_context_t *);\n"
            "\n"
        );
        fputs(
            "struct pcc_rule_set_t {\n"
			"    using item_t = pcc_rule_t;\n"
            "    item_t *buf;\n"
            "    int max;\n"
            "    int len;\n"
            "};\n"
            "\n"
            "struct pcc_lr_head_t;\n"
            "\n"
            "struct pcc_lr_head_t {\n"
            "    pcc_rule_t rule;\n"
            "    pcc_rule_set_t invol;\n"
            "    pcc_rule_set_t eval;\n"
            "    pcc_lr_head_t *hold;\n"
            "};\n"
            "\n"
            "struct pcc_lr_memo_t {\n"
            "    pcc_rule_t rule;\n"
            "    pcc_lr_answer_t *answer;\n"
            "};\n"
            "\n"
            "struct pcc_lr_memo_map_t {\n"
			"    using item_t = pcc_lr_memo_t;\n"
            "    item_t *buf;\n"
            "    int max;\n"
            "    int len;\n"
            "};\n"
            "\n"
            "struct pcc_lr_table_entry_t {\n"
            "    pcc_lr_head_t *head; /* just a reference */\n"
            "    pcc_lr_memo_map_t memos;\n"
            "    pcc_lr_answer_t *hold_a;\n"
            "    pcc_lr_head_t *hold_h;\n"
            "};\n"
            "\n"
            "struct pcc_lr_table_t {\n"
			"    using item_t = pcc_lr_table_entry_t*;\n"
            "    item_t *buf;\n"
            "    int max;\n"
            "    int len;\n"
            "};\n"
            "\n"
            "struct pcc_lr_entry_t {\n"
            "    pcc_rule_t rule;\n"
            "    pcc_thunk_chunk_t *seed; /* just a reference */\n"
            "    pcc_lr_head_t *head; /* just a reference */\n"
            "};\n"
            "\n"
            "struct pcc_lr_stack_t {\n"
			"    using item_t = pcc_lr_entry_t*;\n"
            "    item_t *buf;\n"
            "    int max;\n"
            "    int len;\n"
            "};\n"
            "\n",
            stream
        );
        fprintf(
            stream,
            "struct pcc_%s_Context_t {\n"
            "    using status_t = pcc_%s_Status;\n"
            "    int pos;\n"
            "    int64_t cnt;\n"
            "    status_t status;\n"
			"    size_t errorPosition;\n"
			"    char errorMessage[256];\n"
			"    pcc_char_array_t buffer;\n"
			"    pcc_char_array_t bump;\n"
            "    pcc_lr_table_t lrtable;\n"
            "    pcc_lr_stack_t lrstack;\n"
            "    pcc_auxil_t auxil;\n"
            "};\n"
            "\n",
			get_prefix(ctx), get_prefix(ctx)
        );
        fputs(
            "static void pcc_error(pcc_context_t* ctx, pcc_context_t::status_t stt, size_t pos, const char* msg) {\n"
			"    ctx->status = stt;\n"
			"    ctx->errorPosition = pos;\n"
			"    strcpy_s(ctx->errorMessage, sizeof(ctx->errorMessage), msg);\n"
            "}\n"
            "\n"
            "static void pcc_error(pcc_context_t* ctx, pcc_context_t::status_t stt, const char* msg) {\n"
			"    ctx->status = stt;\n"
			"    ctx->errorPosition = ctx->cnt + ctx->pos;\n"
			"    strcpy_s(ctx->errorMessage, sizeof(ctx->errorMessage), msg);\n"
            "}\n"
            "\n"
            "static void* pcc_malloc(pcc_context_t* ctx, size_t len) {\n"
			"    uintptr_t ps = (uintptr_t)(ctx->bump.buf) + ctx->bump.len;\n"
			"    uintptr_t px = (uintptr_t)(ctx->bump.buf) + ctx->bump.max;\n"
			"    uintptr_t pa = ((ps+7) & (~7));\n"
			"    uintptr_t pe = pa + len;\n"
			"    if(pe+4096 > px)\n"
			"        return pcc_error(ctx,pcc_context_t::status_t::ParsingBufferOverflowed, \"Parsing buffer overflowed!\"), nullptr;\n"
			"    ctx->bump.len += (int)(pe-ps);\n"
			"    return (void*)pa;\n"
            "}\n"
            "\n"
            "static void* pcc_realloc(pcc_context_t* ctx, void* ptr, size_t len) {\n"
			"    if (!ptr) return pcc_malloc(ctx, len);\n"
			"    if (!len) return nullptr;\n"
			"    void* p = pcc_malloc(ctx, len);\n"
			"    if (p == nullptr)\n"
			"        return nullptr;\n"
			"    ::memcpy(p, ptr, (len < ctx->bump.len ? len : ctx->bump.len));\n"
			"    return p;\n"
            "}\n"
            "\n"
			"template< typename T >\n"
            "static void pcc_realloc_buffer(pcc_context_t* ctx, T* t, int len) {\n"
			"    int _max = t->max;\n"
            "    if (t->max <= 0) t->max = 1;\n"
            "    while (t->max < len) t->max <<= 1;\n"
			"    if( t->max != _max )\n"
			"        t->buf = (T::item_t*) pcc_realloc(ctx, (void*)t->buf, t->max * sizeof(T::item_t));\n"
            "}\n"
            "\n"
            "static void pcc_char_array__init(pcc_context_t* ctx, pcc_char_array_t *array, char* addr, int max) {\n"
            "    array->len = 0;\n"
			"    array->max = max;\n"
            "    array->buf = addr;\n"
            "}\n"
            "\n"
            "static void pcc_char_array__clear(pcc_context_t* ctx, pcc_char_array_t *array) {\n"
            "    array->len = 0;\n"
            "}\n"
            "\n"
            "static void pcc_char_array__add(pcc_context_t* ctx, pcc_char_array_t *array, char ch) {\n"
            "    array->buf[array->len++] = ch;\n"
            "}\n"
            "\n"
            "static void pcc_capture_table__init(pcc_context_t* ctx, pcc_capture_table_t *table, int max) {\n"
            "    table->len = 0;\n"
            "    table->max = max;\n"
            "    table->buf = (pcc_capture_t *)pcc_malloc(ctx, table->max * sizeof(pcc_capture_t));\n"
            "}\n"
            "\n"
            "static void pcc_capture_table__resize(pcc_context_t* ctx, pcc_capture_table_t *table, int len) {\n"
            "    int i;\n"
            "    pcc_realloc_buffer(ctx, table,len);\n"
            "    for (i = table->len; i < len; i++) {\n"
            "        table->buf[i].range.start = 0;\n"
            "        table->buf[i].range.end = 0;\n"
            "    }\n"
            "    table->len = len;\n"
            "}\n"
            "\n"
            "static void pcc_capture_const_table__init(pcc_context_t* ctx, pcc_capture_const_table_t *table, int max) {\n"
            "    table->len = 0;\n"
            "    table->max = max;\n"
            "    table->buf = (const pcc_capture_t **)pcc_malloc(ctx, table->max * sizeof(const pcc_capture_t *));\n"
            "}\n"
            "\n"
            "static void pcc_capture_const_table__resize(pcc_context_t* ctx, pcc_capture_const_table_t *table, int len) {\n"
            "    int i;\n"
            "    pcc_realloc_buffer(ctx, table,len);\n"
            "    for (i = table->len; i < len; i++) table->buf[i] = NULL;\n"
            "    table->len = len;\n"
            "}\n"
            "\n"
            "static pcc_thunk_t *pcc_thunk__create_leaf(pcc_context_t* ctx, pcc_action_t action, int captc) {\n"
            "    pcc_thunk_t *thunk = (pcc_thunk_t *)pcc_malloc(ctx, sizeof(pcc_thunk_t));\n"
            "    thunk->type = PCC_THUNK_LEAF;\n"
            "    pcc_capture_const_table__init(ctx, &thunk->data.leaf.capts, captc);\n"
            "    pcc_capture_const_table__resize(ctx, &thunk->data.leaf.capts, captc);\n"
            "    thunk->data.leaf.capt0.range.start = 0;\n"
            "    thunk->data.leaf.capt0.range.end = 0;\n"
            "    thunk->data.leaf.action = action;\n"
            "    return thunk;\n"
            "}\n"
            "\n"
            "static pcc_thunk_t *pcc_thunk__create_node(pcc_context_t* ctx, const pcc_thunk_array_t *thunks) {\n"
            "    pcc_thunk_t *thunk = (pcc_thunk_t *)pcc_malloc(ctx, sizeof(pcc_thunk_t));\n"
            "    thunk->type = PCC_THUNK_NODE;\n"
            "    thunk->data.node.thunks = thunks;\n"
             "    return thunk;\n"
            "}\n"
            "\n"
            "static void pcc_thunk_array__init(pcc_context_t* ctx, pcc_thunk_array_t *array, int max) {\n"
            "    array->len = 0;\n"
            "    array->max = max;\n"
            "    array->buf = (pcc_thunk_t **)pcc_malloc(ctx, array->max * sizeof(pcc_thunk_t *));\n"
            "}\n"
            "\n"
            "static void pcc_thunk_array__add(pcc_context_t* ctx, pcc_thunk_array_t *array, pcc_thunk_t *thunk) {\n"
            "    pcc_realloc_buffer(ctx, array,array->len+1);\n"
            "    array->buf[array->len++] = thunk;\n"
            "}\n"
            "\n"
            "static void pcc_thunk_array__revert(pcc_context_t* ctx, pcc_thunk_array_t *array, int len) {\n"
            "    if (array->len > len) {\n"
            "        array->len = len;\n"
            "    }\n"
            "}\n"
            "\n"
            "static pcc_thunk_chunk_t *pcc_thunk_chunk__create(pcc_context_t* ctx) {\n"
            "    pcc_thunk_chunk_t *chunk = (pcc_thunk_chunk_t *)pcc_malloc(ctx, sizeof(pcc_thunk_chunk_t));\n"
            "    pcc_capture_table__init(ctx, &chunk->capts, PCC_ARRAYSIZE);\n"
            "    pcc_thunk_array__init(ctx, &chunk->thunks, PCC_ARRAYSIZE);\n"
            "    chunk->pos = 0;\n"
            "    return chunk;\n"
            "}\n"
            "\n"
            "static void pcc_rule_set__init(pcc_context_t* ctx, pcc_rule_set_t *set, int max) {\n"
            "    set->len = 0;\n"
            "    set->max = max;\n"
            "    set->buf = (pcc_rule_t *)pcc_malloc(ctx, set->max * sizeof(pcc_rule_t));\n"
            "}\n"
            "\n"
            "static int pcc_rule_set__index(pcc_context_t* ctx, const pcc_rule_set_t *set, pcc_rule_t rule) {\n"
            "    int i;\n"
            "    for (i = 0; i < set->len; i++) {\n"
            "        if (set->buf[i] == rule) return i;\n"
            "    }\n"
            "    return -1;\n"
            "}\n"
            "\n"
            "static pcc_bool_t pcc_rule_set__add(pcc_context_t* ctx, pcc_rule_set_t *set, pcc_rule_t rule) {\n"
            "    int i = pcc_rule_set__index(ctx, set, rule);\n"
            "    if (i >= 0) return PCC_FALSE;\n"
            "    pcc_realloc_buffer(ctx, set,set->len+1);\n"
            "    set->buf[set->len++] = rule;\n"
            "    return PCC_TRUE;\n"
            "}\n"
            "\n"
            "static pcc_bool_t pcc_rule_set__remove(pcc_context_t* ctx, pcc_rule_set_t *set, pcc_rule_t rule) {\n"
            "    int i = pcc_rule_set__index(ctx, set, rule);\n"
            "    if (i < 0) return PCC_FALSE;\n"
            "    memmove(set->buf + i, set->buf + (i + 1), (set->len - (i + 1)) * sizeof(pcc_rule_t));\n"
            "    return PCC_TRUE;\n"
            "}\n"
            "\n"
            "static void pcc_rule_set__clear(pcc_context_t* ctx, pcc_rule_set_t *set) {\n"
            "    set->len = 0;\n"
            "}\n"
            "\n"
            "static void pcc_rule_set__copy(pcc_context_t* ctx, pcc_rule_set_t *set, const pcc_rule_set_t *src) {\n"
            "    int i;\n"
            "    pcc_rule_set__clear(ctx, set);\n"
            "    for (i = 0; i < src->len; i++) {\n"
            "        pcc_rule_set__add(ctx, set, src->buf[i]);\n"
            "    }\n"
            "}\n"
            "\n"
            "static pcc_lr_head_t *pcc_lr_head__create(pcc_context_t* ctx, pcc_rule_t rule) {\n"
            "    pcc_lr_head_t *head = (pcc_lr_head_t *)pcc_malloc(ctx, sizeof(pcc_lr_head_t));\n"
            "    head->rule = rule;\n"
            "    pcc_rule_set__init(ctx, &head->invol, PCC_ARRAYSIZE);\n"
            "    pcc_rule_set__init(ctx, &head->eval, PCC_ARRAYSIZE);\n"
            "    head->hold = NULL;\n"
            "    return head;\n"
            "}\n"
            "\n"
            "static pcc_lr_answer_t *pcc_lr_answer__create(pcc_context_t* ctx, pcc_lr_answer_type_t type, int pos) {\n"
            "    pcc_lr_answer_t *answer = (pcc_lr_answer_t *)pcc_malloc(ctx, sizeof(pcc_lr_answer_t));\n"
            "    answer->type = type;\n"
            "    answer->pos = pos;\n"
            "    answer->hold = NULL;\n"
            "    switch (answer->type) {\n"
            "    case PCC_LR_ANSWER_LR:\n"
            "        answer->data.lr = NULL;\n"
            "        break;\n"
            "    case PCC_LR_ANSWER_CHUNK:\n"
            "        answer->data.chunk = NULL;\n"
            "        break;\n"
            "    default: /* unknown */\n"
            "        answer = NULL;\n"
            "    }\n"
            "    return answer;\n"
            "}\n"
            "\n"
            "static void pcc_lr_answer__set_chunk(pcc_context_t* ctx, pcc_lr_answer_t *answer, pcc_thunk_chunk_t *chunk) {\n"
            "    pcc_lr_answer_t *a = pcc_lr_answer__create(ctx, answer->type, answer->pos);\n"
            "    switch (answer->type) {\n"
            "    case PCC_LR_ANSWER_LR:\n"
            "        a->data.lr = answer->data.lr;\n"
            "        break;\n"
            "    case PCC_LR_ANSWER_CHUNK:\n"
            "        a->data.chunk = answer->data.chunk;\n"
            "        break;\n"
            "    default: /* unknown */\n"
            "        break;\n"
            "    }\n"
            "    a->hold = answer->hold;\n"
            "    answer->hold = a;\n"
            "    answer->type = PCC_LR_ANSWER_CHUNK;\n"
            "    answer->data.chunk = chunk;\n"
            "}\n"
            "\n"
            "static void pcc_lr_memo_map__init(pcc_context_t* ctx, pcc_lr_memo_map_t *map, int max) {\n"
            "    map->len = 0;\n"
            "    map->max = max;\n"
            "    map->buf = (pcc_lr_memo_t *)pcc_malloc(ctx, map->max * sizeof(pcc_lr_memo_t));\n"
            "}\n"
            "\n"
            "static int pcc_lr_memo_map__index(pcc_context_t* ctx, pcc_lr_memo_map_t *map, pcc_rule_t rule) {\n"
            "    int i;\n"
            "    for (i = 0; i < map->len; i++) {\n"
            "        if (map->buf[i].rule == rule) return i;\n"
            "    }\n"
            "    return -1;\n"
            "}\n"
            "\n"
            "static void pcc_lr_memo_map__put(pcc_context_t* ctx, pcc_lr_memo_map_t *map, pcc_rule_t rule, pcc_lr_answer_t *answer) {\n"
            "    int i = pcc_lr_memo_map__index(ctx, map, rule);\n"
            "    if (i >= 0) {\n"
            "        map->buf[i].answer = answer;\n"
            "    }\n"
            "    else {\n"
            "        pcc_realloc_buffer(ctx, map,map->len+1);\n"
            "        map->buf[map->len].rule = rule;\n"
            "        map->buf[map->len].answer = answer;\n"
            "        map->len++;\n"
            "    }\n"
            "}\n"
            "\n"
            "static pcc_lr_answer_t *pcc_lr_memo_map__get(pcc_context_t* ctx, pcc_lr_memo_map_t *map, pcc_rule_t rule) {\n"
            "    int i = pcc_lr_memo_map__index(ctx, map, rule);\n"
            "    return (i >= 0) ? map->buf[i].answer : NULL;\n"
            "}\n"
            "\n"
            "static pcc_lr_table_entry_t *pcc_lr_table_entry__create(pcc_context_t* ctx) {\n"
            "    pcc_lr_table_entry_t *entry = (pcc_lr_table_entry_t *)pcc_malloc(ctx, sizeof(pcc_lr_table_entry_t));\n"
            "    entry->head = NULL;\n"
            "    pcc_lr_memo_map__init(ctx, &entry->memos, PCC_ARRAYSIZE);\n"
            "    entry->hold_a = NULL;\n"
            "    entry->hold_h = NULL;\n"
            "    return entry;\n"
            "}\n"
            "\n"
            "static void pcc_lr_table__init(pcc_context_t* ctx, pcc_lr_table_t *table, int max) {\n"
            "    table->len = 0;\n"
            "    table->max = max;\n"
            "    table->buf = (pcc_lr_table_entry_t **)pcc_malloc(ctx, table->max * sizeof(pcc_lr_table_entry_t *));\n"
            "}\n"
            "\n"
            "static void pcc_lr_table__resize(pcc_context_t* ctx, pcc_lr_table_t *table, int len) {\n"
            "    int i;\n"
            "    pcc_realloc_buffer(ctx, table,len);\n"
            "    for (i = table->len; i < len; i++) table->buf[i] = NULL;\n"
            "    table->len = len;\n"
            "}\n"
            "\n"
            "static void pcc_lr_table__set_head(pcc_context_t* ctx, pcc_lr_table_t *table, int index, pcc_lr_head_t *head) {\n"
            "    if (index >= table->len) pcc_lr_table__resize(ctx, table, index + 1);\n"
            "    if (table->buf[index] == NULL) table->buf[index] = pcc_lr_table_entry__create(ctx);\n"
            "    table->buf[index]->head = head;\n"
            "}\n"
            "\n"
            "static void pcc_lr_table__hold_head(pcc_context_t* ctx, pcc_lr_table_t *table, int index, pcc_lr_head_t *head) {\n"
            "    if (index >= table->len) pcc_lr_table__resize(ctx, table, index + 1);\n"
            "    if (table->buf[index] == NULL) table->buf[index] = pcc_lr_table_entry__create(ctx);\n"
            "    head->hold = table->buf[index]->hold_h;\n"
            "    table->buf[index]->hold_h = head;\n"
            "}\n"
            "\n"
            "static void pcc_lr_table__set_answer(pcc_context_t* ctx, pcc_lr_table_t *table, int index, pcc_rule_t rule, pcc_lr_answer_t *answer) {\n"
            "    if (index >= table->len) pcc_lr_table__resize(ctx, table, index + 1);\n"
            "    if (table->buf[index] == NULL) table->buf[index] = pcc_lr_table_entry__create(ctx);\n"
            "    pcc_lr_memo_map__put(ctx, &table->buf[index]->memos, rule, answer);\n"
            "}\n"
            "\n"
            "static void pcc_lr_table__hold_answer(pcc_context_t* ctx, pcc_lr_table_t *table, int index, pcc_lr_answer_t *answer) {\n"
            "    if (index >= table->len) pcc_lr_table__resize(ctx, table, index + 1);\n"
            "    if (table->buf[index] == NULL) table->buf[index] = pcc_lr_table_entry__create(ctx);\n"
            "    answer->hold = table->buf[index]->hold_a;\n"
            "    table->buf[index]->hold_a = answer;\n"
            "}\n"
            "\n"
            "static pcc_lr_head_t *pcc_lr_table__get_head(pcc_context_t* ctx, pcc_lr_table_t *table, int index) {\n"
            "    if (index >= table->len || table->buf[index] == NULL) return NULL;\n"
            "    return table->buf[index]->head;\n"
            "}\n"
            "\n"
            "static pcc_lr_answer_t *pcc_lr_table__get_answer(pcc_context_t* ctx, pcc_lr_table_t *table, int index, pcc_rule_t rule) {\n"
            "    if (index >= table->len || table->buf[index] == NULL) return NULL;\n"
            "    return pcc_lr_memo_map__get(ctx, &table->buf[index]->memos, rule);\n"
            "}\n"
            "\n"
            "static void pcc_lr_table__shift(pcc_context_t* ctx, pcc_lr_table_t *table, int count) {\n"
            "    if (count > table->len) count = table->len;\n"
            "    memmove(table->buf, table->buf + count, (table->len - count) * sizeof(pcc_lr_table_entry_t *));\n"
            "    table->len -= count;\n"
            "}\n"
            "\n"
            "static pcc_lr_entry_t *pcc_lr_entry__create(pcc_context_t* ctx, pcc_rule_t rule) {\n"
            "    pcc_lr_entry_t *lr = (pcc_lr_entry_t *)pcc_malloc(ctx, sizeof(pcc_lr_entry_t));\n"
            "    lr->rule = rule;\n"
            "    lr->seed = NULL;\n"
            "    lr->head = NULL;\n"
            "    return lr;\n"
            "}\n"
            "\n"
            "static void pcc_lr_stack__init(pcc_context_t* ctx, pcc_lr_stack_t *stack, int max) {\n"
            "    stack->len = 0;\n"
            "    stack->max = max;\n"
            "    stack->buf = (pcc_lr_entry_t **)pcc_malloc(ctx, stack->max * sizeof(pcc_lr_entry_t *));\n"
            "}\n"
            "\n"
            "static void pcc_lr_stack__push(pcc_context_t* ctx, pcc_lr_stack_t *stack, pcc_lr_entry_t *lr) {\n"
            "    pcc_realloc_buffer(ctx, stack,stack->len+1);\n"
            "    stack->buf[stack->len++] = lr;\n"
            "}\n"
            "\n"
            "static pcc_lr_entry_t *pcc_lr_stack__pop(pcc_context_t* ctx, pcc_lr_stack_t *stack) {\n"
            "    return stack->buf[--stack->len];\n"
            "}\n"
            "\n",
            stream
        );
        fprintf(
            stream,
            "static int pcc_refill_buffer(pcc_context_t *ctx, int num) {\n"
        );
        fputs(
            "    int n, c;\n"
            "    n = ctx->buffer.len - ctx->pos;\n"
            "    if (n >= num) return n;\n"
			"    if (ctx->buffer.len+16 > ctx->buffer.max) pcc_error(ctx, pcc_context_t::status_t::InputBufferOverflowed, \"Input buffer overflowed!\");\n"
            "    if (ctx->status != pcc_context_t::status_t::Ok) return n;\n"
			"    while (ctx->buffer.len < ctx->pos + num) {\n"
            "        c = PCC_GETCHAR(ctx->auxil);\n"
            "        if (c == -1) {\n"
			"            break; }\n"
            "        else if (c == -2) {\n"
			"            pcc_error(ctx, pcc_context_t::status_t::InputError, \"Input Error!\");\n"
			"            break; }\n"
            "        pcc_char_array__add(ctx, &ctx->buffer, (char)c);\n"
            "    }\n"
            "    return ctx->buffer.len - ctx->pos;\n"
            "}\n"
            "\n",
            stream
        );
        fprintf(
            stream,
            "static void pcc_commit_buffer(pcc_context_t *ctx) {\n"
        );
        fputs(
            "    memmove(ctx->buffer.buf, ctx->buffer.buf + ctx->pos, ctx->buffer.len - ctx->pos);\n"
            "    ctx->buffer.len -= ctx->pos;\n"
			"    pcc_lr_table__shift(ctx, &ctx->lrtable, ctx->pos);\n"
			"    ctx->cnt += ctx->pos;\n"
            "    ctx->pos = 0;\n"
            "}\n"
            "\n",
            stream
        );
        fprintf(
            stream,
            "static pcc_bool_t pcc_apply_rule(pcc_context_t *ctx, pcc_rule_t rule, pcc_thunk_array_t *thunks) {\n"
        );
        fputs(
			"    if (ctx->status != pcc_context_t::status_t::Ok) return PCC_FALSE;\n"
            "    pcc_thunk_chunk_t *c = NULL;\n"
            "    int p = ctx->pos;\n"
            "    pcc_bool_t b = PCC_TRUE;\n"
            "    pcc_lr_answer_t *a = pcc_lr_table__get_answer(ctx, &ctx->lrtable, p, rule);\n"
            "    pcc_lr_head_t *h = pcc_lr_table__get_head(ctx, &ctx->lrtable, p);\n"
            "    if (h != NULL) {\n"
            "        if (a == NULL && rule != h->rule && pcc_rule_set__index(ctx, &h->invol, rule) < 0) {\n"
            "            b = PCC_FALSE;\n"
            "            c = NULL;\n"
            "        }\n"
            "        else if (pcc_rule_set__remove(ctx, &h->eval, rule)) {\n"
            "            b = PCC_FALSE;\n"
            "            c = rule(ctx);\n"
            "            a = pcc_lr_answer__create(ctx, PCC_LR_ANSWER_CHUNK, ctx->pos);\n"
            "            a->data.chunk = c;\n"
            "            pcc_lr_table__hold_answer(ctx, &ctx->lrtable, p, a);\n"
            "        }\n"
            "    }\n"
            "    if (b) {\n"
            "        if (a != NULL) {\n"
            "            ctx->pos = a->pos;\n"
            "            switch (a->type) {\n"
            "            case PCC_LR_ANSWER_LR:\n"
            "                if (a->data.lr->head == NULL) {\n"
            "                    a->data.lr->head = pcc_lr_head__create(ctx, rule);\n"
            "                    pcc_lr_table__hold_head(ctx, &ctx->lrtable, p, a->data.lr->head);\n"
            "                }\n"
            "                {\n"
            "                    int i;\n"
            "                    for (i = ctx->lrstack.len - 1; i >= 0; i--) {\n"
            "                        if (ctx->lrstack.buf[i]->head == a->data.lr->head) break;\n"
            "                        ctx->lrstack.buf[i]->head = a->data.lr->head;\n"
            "                        pcc_rule_set__add(ctx, &a->data.lr->head->invol, ctx->lrstack.buf[i]->rule);\n"
            "                    }\n"
            "                }\n"
            "                c = a->data.lr->seed;\n"
            "                break;\n"
            "            case PCC_LR_ANSWER_CHUNK:\n"
            "                c = a->data.chunk;\n"
            "                break;\n"
            "            default: /* unknown */\n"
            "                break;\n"
            "            }\n"
            "        }\n"
            "        else {\n"
            "            pcc_lr_entry_t *e = pcc_lr_entry__create(ctx, rule);\n"
            "            pcc_lr_stack__push(ctx, &ctx->lrstack, e);\n"
            "            a = pcc_lr_answer__create(ctx, PCC_LR_ANSWER_LR, p);\n"
            "            a->data.lr = e;\n"
            "            pcc_lr_table__set_answer(ctx, &ctx->lrtable, p, rule, a);\n"
            "            c = rule(ctx);\n"
            "            pcc_lr_stack__pop(ctx, &ctx->lrstack);\n"
            "            a->pos = ctx->pos;\n"
            "            if (e->head == NULL) {\n"
            "                pcc_lr_answer__set_chunk(ctx, a, c);\n"
            "            }\n"
            "            else {\n"
            "                e->seed = c;\n"
            "                h = a->data.lr->head;\n"
            "                if (h->rule != rule) {\n"
            "                    c = a->data.lr->seed;\n"
            "                    a = pcc_lr_answer__create(ctx, PCC_LR_ANSWER_CHUNK, ctx->pos);\n"
            "                    a->data.chunk = c;\n"
            "                    pcc_lr_table__hold_answer(ctx, &ctx->lrtable, p, a);\n"
            "                }\n"
            "                else {\n"
            "                    pcc_lr_answer__set_chunk(ctx, a, a->data.lr->seed);\n"
            "                    if (a->data.chunk == NULL) {\n"
            "                        c = NULL;\n"
            "                    }\n"
            "                    else {\n"
            "                        pcc_lr_table__set_head(ctx, &ctx->lrtable, p, h);\n"
            "                        for (;;) {\n"
            "                            ctx->pos = p;\n"
            "                            pcc_rule_set__copy(ctx, &h->eval, &h->invol);\n"
            "                            c = rule(ctx);\n"
            "                            if (c == NULL || ctx->pos <= a->pos) break;\n"
            "                            pcc_lr_answer__set_chunk(ctx, a, c);\n"
            "                            a->pos = ctx->pos;\n"
            "                        }\n"
            "                        pcc_lr_table__set_head(ctx, &ctx->lrtable, p, NULL);\n"
            "                        ctx->pos = a->pos;\n"
            "                        c = a->data.chunk;\n"
            "                    }\n"
            "                }\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "    if (c == NULL) return PCC_FALSE;\n"
            "    pcc_thunk_array__add(ctx, thunks, pcc_thunk__create_node(ctx, &c->thunks));\n"
            "    return PCC_TRUE;\n"
            "}\n"
            "\n",
            stream
        );
        fprintf(
            stream,
            "static void pcc_do_action(pcc_context_t *ctx, const pcc_thunk_array_t *thunks) {\n"
        );
        fputs(
            "    int i;\n"
            "    for (i = 0; i < thunks->len; i++) {\n"
            "        pcc_thunk_t *thunk = thunks->buf[i];\n"
            "        switch (thunk->type) {\n"
            "        case PCC_THUNK_LEAF:\n"
            "            thunk->data.leaf.action(ctx, thunk);\n"
            "            break;\n"
            "        case PCC_THUNK_NODE:\n"
            "            pcc_do_action(ctx, thunk->data.node.thunks);\n"
            "            break;\n"
            "        default: /* unknown */\n"
            "            break;\n"
            "        }\n"
            "    }\n"
            "}\n"
            "\n",
            stream
        );
        {
            int i, j, k;
            for (i = 0; i < ctx->rules.len; i++) {
                const node_rule *r = &ctx->rules.buf[i]->data.rule;
                for (j = 0; j < r->codes.len; j++) {
                    const char *s;
                    int d;
                    const node_const_array *v, *c;
                    switch (r->codes.buf[j]->type) {
                    case NODE_ACTION:
                        s = r->codes.buf[j]->data.action.value;
                        d = r->codes.buf[j]->data.action.index;
                        v = &r->codes.buf[j]->data.action.vars;
                        c = &r->codes.buf[j]->data.action.capts;
                        break;
                    case NODE_ERROR:
                        s = r->codes.buf[j]->data.error.value;
                        d = r->codes.buf[j]->data.error.index;
                        v = &r->codes.buf[j]->data.error.vars;
                        c = &r->codes.buf[j]->data.error.capts;
                        break;
                    default:
                        print_error("Internal error [%d]\n", __LINE__);
                        exit(-1);
                    }
                    fprintf(
                        stream,
                        "static void pcc_action_%s_%d(pcc_context_t *__pcc_ctx, pcc_thunk_t *__pcc_in) {\n",
                        r->name, d
                    );
                    fputs(
                        "#define ctx (__pcc_ctx)\n"
                        "#define auxil (__pcc_ctx->auxil)\n",
                        stream
                    );
					fprintf(
						stream,
						"#define _rname %s\n",
						r->name
					);
					fprintf(
						stream,
						"#define _rcall on_%s\n",
						r->name
					);
					fprintf(
						stream,
						"#define _renter on_%s_enter\n",
						r->name
					);
					fprintf(
						stream,
						"#define _rleave on_%s_leave\n",
						r->name
					);
					fprintf(
						stream,
						"#define _ri %d\n",
						d
					);
                     fputs(
                        "#define _0s  (__pcc_in->data.leaf.capt0.range.start)\n"
                        "#define _0e  (__pcc_in->data.leaf.capt0.range.end)\n"
                        "#define _0sp (__pcc_ctx->buffer.buf + _0s)\n"
                        "#define _0ep (__pcc_ctx->buffer.buf + _0e)\n"
						"#define _0sc (__pcc_ctx->cnt + _0s)\n"
						"#define _0ec (__pcc_ctx->cnt + _0e)\n",
						stream
                    );
                    for (k = 0; k < c->len; k++) {
                        assert(c->buf[k]->type == NODE_CAPTURE);
                        fprintf(
                            stream,
                            "#define _%ds (__pcc_in->data.leaf.capts.buf[%d]->range.start)\n",
                            c->buf[k]->data.capture.index + 1,
                            c->buf[k]->data.capture.index
                        );
                        fprintf(
                            stream,
                            "#define _%de (__pcc_in->data.leaf.capts.buf[%d]->range.end)\n",
                            c->buf[k]->data.capture.index + 1,
                            c->buf[k]->data.capture.index
                        );
                        fprintf(
                            stream,
                            "#define _%dsp (__pcc_ctx->buffer.buf + _%ds)\n",
                            c->buf[k]->data.capture.index + 1,
                            c->buf[k]->data.capture.index + 1
                        );
                        fprintf(
                            stream,
                            "#define _%dep (__pcc_ctx->buffer.buf + _%de)\n",
                            c->buf[k]->data.capture.index + 1,
                            c->buf[k]->data.capture.index + 1
                        );
						fprintf(
							stream,
							"#define _%dsc (__pcc_ctx->cnt + _%ds)\n",
							c->buf[k]->data.capture.index + 1,
							c->buf[k]->data.capture.index + 1
						);
						fprintf(
							stream,
							"#define _%dec (__pcc_ctx->cnt + _%de)\n",
							c->buf[k]->data.capture.index + 1,
							c->buf[k]->data.capture.index + 1
						);
					}
					fputs(
						"\n\t#ifdef PCC_SETPOS\n"
						"\tPCC_SETPOS(0,_0sc,_0ec);\n",
						stream
					);
					for (k = 0; k < c->len; k++) {
						assert(c->buf[k]->type == NODE_CAPTURE);
						fprintf(
							stream,
							"\tPCC_SETPOS(%d,_%dsc,_%dec);\n",
							k+1,
							c->buf[k]->data.capture.index + 1,
							c->buf[k]->data.capture.index + 1
						);
					}
					fputs(
						"\t#endif // PCC_SETPOS\n\n",
						stream
					);
                    write_code_block(stream, s, strlen(s), 4);
					fputs(
						"\n\t#ifdef PCC_CLEARPOS\n"
						"\tPCC_CLEARPOS();\n"
						"\t#endif // PCC_CLEARPOS\n\n",
						stream
					);
					for (k = c->len - 1; k >= 0; k--) {
                        assert(c->buf[k]->type == NODE_CAPTURE);
						fprintf(
							stream,
							"#undef _%dec\n",
							c->buf[k]->data.capture.index + 1
						);
						fprintf(
							stream,
							"#undef _%dsc\n",
							c->buf[k]->data.capture.index + 1
						);
						fprintf(
                            stream,
                            "#undef _%dep\n",
                            c->buf[k]->data.capture.index + 1
                        );
                        fprintf(
                            stream,
                            "#undef _%dsp\n",
                            c->buf[k]->data.capture.index + 1
                        );
                        fprintf(
                            stream,
                            "#undef _%de\n",
                            c->buf[k]->data.capture.index + 1
                        );
                        fprintf(
                            stream,
                            "#undef _%ds\n",
                            c->buf[k]->data.capture.index + 1
                        );
                    }
                    fputs(
						"#undef _0ec\n"
						"#undef _0sc\n"
						"#undef _0ep\n"
                        "#undef _0sp\n"
                        "#undef _0e\n"
                        "#undef _0s\n",
                        stream
                    );
                    fputs(
						"#undef _ri\n"
						"#undef _rname\n"
						"#undef _rcall\n"
						"#undef _renter\n"
						"#undef _rleave\n"
                        "#undef auxil\n"
                        "#undef ctx\n",
                        stream
                    );
                    fputs(
                        "}\n"
                        "\n",
                        stream
                    );
                }
            }
        }
        {
            int i;
            for (i = 0; i < ctx->rules.len; i++) {
                fprintf(
                    stream,
                    "static pcc_thunk_chunk_t *pcc_evaluate_rule_%s(pcc_context_t *ctx);\n",
                    ctx->rules.buf[i]->data.rule.name
                );
            }
            fputs(
                "\n",
                stream
            );
            for (i = 0; i < ctx->rules.len; i++) {
                code_reach r;
                generated g;
                g.stream = stream;
                g.rule = ctx->rules.buf[i];
                g.label = 0;
                fprintf(
                    stream,
                    "static pcc_thunk_chunk_t *pcc_evaluate_rule_%s(pcc_context_t *ctx) {\n",
                    ctx->rules.buf[i]->data.rule.name
                );
                fputs(
                    "    pcc_thunk_chunk_t *chunk = pcc_thunk_chunk__create(ctx);\n"
                    "    chunk->pos = ctx->pos;\n",
                    stream
                );
                fprintf(
                    stream,
                    "    pcc_capture_table__resize(ctx, &chunk->capts, %d);\n",
                    ctx->rules.buf[i]->data.rule.capts.len
                );
                r = generate_code(&g, ctx->rules.buf[i]->data.rule.expr, 0, 4, FALSE);
                fputs(
                    "    return chunk;\n",
                    stream
                );
                if (r != CODE_REACH__ALWAYS_SUCCEED) {
                    fputs(
                        "L0000:;\n"
                        "    return NULL;\n",
                        stream
                    );
                }
                fputs(
                    "}\n"
                    "\n",
                    stream
                );
            }
        }
        fprintf(
            stream,
			"pcc_%s_Context_t* pcc_%s_create_in_place(%s inauxil, void* inaddr, int insz, int ininputsz) {\n"
			"    assert(ininputsz > 1024);\n"
			"    assert(insz > ininputsz*8);\n"
			"    pcc_context_t* ctx = (pcc_context_t*)inaddr;\n"
            "    ctx->pos = 0;\n"
            "    ctx->cnt = 0;\n"
            "    ctx->auxil = inauxil;\n"
            "    ctx->status = pcc_%s_Status::Ok;\n"
            "    ctx->errorPosition = 0;\n"
            "    ctx->errorMessage[0] = 0;\n"
			"    char* buffer_start = (char*)(ctx+1);\n"
			"    char* bump_start = buffer_start + ininputsz;\n"
			"    int bump_sz = insz - ininputsz - sizeof(pcc_context_t);\n"
			"    assert(bump_sz > 1024);\n"
			"    pcc_char_array__init(ctx, &ctx->buffer, buffer_start, ininputsz);\n"
			"    pcc_char_array__init(ctx, &ctx->bump, bump_start, bump_sz);\n"
            "    return ctx;\n"
            "}\n\n",
            get_prefix(ctx), get_prefix(ctx), at, get_prefix(ctx)
        );
        fprintf(
            stream,
            "%s pcc_%s_get_auxil(pcc_%s_Context_t* ctx) {\n"
			"    return ctx->auxil;\n"
            "}\n\n",
            at, get_prefix(ctx), get_prefix(ctx)
        );
        fprintf(
            stream,
            "const char* pcc_%s_get_input_pointer(pcc_%s_Context_t* ctx) {\n"
			"    return ctx->buffer.buf + ctx->pos;\n"
            "}\n\n",
            get_prefix(ctx), get_prefix(ctx)
        );
        fprintf(
            stream,
            "int64_t pcc_%s_get_input_position(pcc_%s_Context_t* ctx) {\n"
			"    return ctx->cnt + ctx->pos;\n"
            "}\n\n",
            get_prefix(ctx), get_prefix(ctx)
        );
        fprintf(
            stream,
            "pcc_%s_Status pcc_%s_get_status(pcc_%s_Context_t* ctx) {\n"
			"    return ctx->status;\n"
            "}\n\n",
            get_prefix(ctx), get_prefix(ctx), get_prefix(ctx)
        );
        fprintf(
            stream,
            "size_t pcc_%s_get_error_position(pcc_%s_Context_t* ctx) {\n"
			"    return ctx->errorPosition;\n"
            "}\n\n",
            get_prefix(ctx), get_prefix(ctx)
        );
        fprintf(
            stream,
            "const char* pcc_%s_get_error_message(pcc_%s_Context_t* ctx) {\n"
			"    return ctx->errorMessage;\n"
            "}\n\n",
            get_prefix(ctx), get_prefix(ctx)
        );
		fprintf(
            stream,
            "pcc_%s_Status pcc_%s_parse(pcc_%s_Context_t* ctx) {\n"
			"    if(ctx->status != pcc_context_t::status_t::Ok) return ctx->status;\n"
			"    pcc_char_array__clear(ctx, &ctx->bump);\n"
            "    pcc_thunk_array_t thunks;\n"
            "    pcc_thunk_array__init(ctx, &thunks, PCC_ARRAYSIZE);\n"
            "    pcc_lr_table__init(ctx, &ctx->lrtable, PCC_ARRAYSIZE);\n"
            "    pcc_lr_stack__init(ctx, &ctx->lrstack, PCC_ARRAYSIZE);\n",
           get_prefix(ctx), get_prefix(ctx), get_prefix(ctx)
		);
        if (ctx->rules.len > 0) {
            fprintf(
                stream,
                "    if (pcc_apply_rule(ctx, pcc_evaluate_rule_%s, &thunks))\n",
                ctx->rules.buf[0]->data.rule.name
            );
            fputs(
                "        pcc_do_action(ctx, &thunks);\n"
                "    else if(ctx->status == pcc_context_t::status_t::Ok)\n"
                "        pcc_error(ctx, pcc_context_t::status_t::MatchError, \"Match Error!\");\n"
                "    pcc_commit_buffer(ctx);\n",
                stream
            );
        }
        fputs(
			"    if(ctx->status == pcc_context_t::status_t::Ok)\n"
            "        if(pcc_refill_buffer(ctx, 1)==0)\n"
			"            ctx->status = pcc_context_t::status_t::Completed;\n"
			"    return ctx->status;\n"
            "}\n"
            "\n",
            stream
        );
    }
    {
        fprintf(
            ctx->hfile,
			"enum struct pcc_%s_Status\n"
			"{\n"
			"\tOk = 0,\n"
			"\tCompleted = 1,\n"
			"\tMatchError = -1,\n"
			"\tParseError = -2,\n"
			"\tInputError = -3,\n"
			"\tInputBufferOverflowed = -4,\n"
			"\tParsingBufferOverflowed = -5,\n"
			"};\n\n",
            get_prefix(ctx)
        );
        fprintf(
            ctx->hfile,
			"enum struct pcc_%s_Default : size_t\n"
			"{\n"
			"\tInput_BufferSize = %d << 10,\n"
			"\tParse_BufferSize = %d << 10,\n"
			"\tTotal_bufferSize = Input_BufferSize + Parse_BufferSize\n"
			"};\n\n",
            get_prefix(ctx), ctx->inputbuffsize, ctx->parsebuffsize
        );
        fprintf(
            ctx->hfile,
            "struct pcc_%s_Context_t;\n\n"
            "pcc_%s_Context_t* pcc_%s_create_in_place (%s, void* addr, int sz, int inputsz);\n"
            "const char* pcc_%s_get_input_pointer (pcc_%s_Context_t*);\n"
            "int64_t pcc_%s_get_input_position (pcc_%s_Context_t*);\n"
            "pcc_%s_Status pcc_%s_get_status (pcc_%s_Context_t*);\n"
            "size_t pcc_%s_get_error_position (pcc_%s_Context_t*);\n"
            "const char* pcc_%s_get_error_message (pcc_%s_Context_t*);\n"
            "pcc_%s_Status pcc_%s_parse (pcc_%s_Context_t*);\n"
			"\n",
            get_prefix(ctx), get_prefix(ctx), get_prefix(ctx),
			at,
			get_prefix(ctx), get_prefix(ctx), get_prefix(ctx), get_prefix(ctx),
			get_prefix(ctx), get_prefix(ctx), get_prefix(ctx), get_prefix(ctx),
			get_prefix(ctx), get_prefix(ctx), get_prefix(ctx), get_prefix(ctx),
			get_prefix(ctx), get_prefix(ctx)
        );
    }
    {
        match_eol(ctx);
        if (!match_eof(ctx)) fputc('\n', stream);
        commit_buffer(ctx);
        while (refill_buffer(ctx, ctx->buffer.max) > 0) {
            int n = (ctx->buffer.buf[ctx->buffer.len - 1] == '\r') ? ctx->buffer.len - 1 : ctx->buffer.len;
            write_text(stream, ctx->buffer.buf, n);
            ctx->bufpos = n;
            commit_buffer(ctx);
        }
    }
    return (ctx->errnum == 0) ? TRUE : FALSE;
}

static void print_version(FILE *output) {
    fprintf(output, "%s version %s\n", g_cmdname, VERSION);
    fprintf(output, "Copyright (c) 2014 Arihiro Yoshida. All rights reserved.\n");
}

static void print_usage(FILE *output) {
    fprintf(output, "Usage: %s [OPTIONS] [FILE]\n", g_cmdname);
    fprintf(output, "Generates a packrat parser for C.\n");
    fprintf(output, "\n");
    fprintf(output, "  -o BASENAME  specify a base name of output source and header files\n");
    fprintf(output, "  -d           with debug information\n");
    fprintf(output, "  -h           print this help message and exit\n");
    fprintf(output, "  -v           print the version and exit\n");
}

int main(int argc, char **argv) {
    const char *iname = NULL;
    const char *oname = NULL;
    bool_t debug = FALSE;
#ifdef _MSC_VER
#ifdef _DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
#endif
#endif
    g_cmdname = extract_filename(argv[0]);
    {
        const char *fname = NULL;
        const char *opt_o = NULL;
        bool_t opt_d = FALSE;
        bool_t opt_h = FALSE;
        bool_t opt_v = FALSE;
        int i;
        for (i = 1; i < argc; i++) {
            if (argv[i][0] != '-') {
                break;
            }
            else if (strcmp(argv[i] + 1, "-") == 0) {
                i++; break;
            }
            else if (argv[i][1] == 'o') {
                const char *o = (argv[i][2] != '\0') ? argv[i] + 2 : (++i < argc) ?  argv[i] : NULL;
                if (o == NULL) {
                    print_error("Output base name missing\n");
                    fprintf(stderr, "\n");
                    print_usage(stderr);
                    exit(1);
                }
                if (opt_o != NULL) {
                    print_error("Extra output base name '%s'\n", o);
                    fprintf(stderr, "\n");
                    print_usage(stderr);
                    exit(1);
                }
                opt_o = o;
            }
            else if (strcmp(argv[i] + 1, "d") == 0) {
                opt_d = TRUE;
            }
            else if (strcmp(argv[i] + 1, "h") == 0) {
                opt_h = TRUE;
            }
            else if (strcmp(argv[i] + 1, "v") == 0) {
                opt_v = TRUE;
            }
            else {
                print_error("Invalid option '%s'\n", argv[i]);
                fprintf(stderr, "\n");
                print_usage(stderr);
                exit(1);
            }
        }
        switch (argc - i) {
        case 0:
            break;
        case 1:
            fname = argv[i];
            break;
        default:
            print_error("Multiple input files\n");
            fprintf(stderr, "\n");
            print_usage(stderr);
            exit(1);
        }
        if (opt_h || opt_v) {
            if (opt_v) print_version(stdout);
            if (opt_v && opt_h) fprintf(stdout, "\n");
            if (opt_h) print_usage(stdout);
            exit(0);
        }
        iname = (fname != NULL && fname[0] != '\0') ? fname : NULL;
        oname = (opt_o != NULL && opt_o[0] != '\0') ? opt_o : NULL;
        debug = opt_d;
    }
    {
        context *ctx = create_context(iname, oname, debug);
        int b = parse(ctx) && generate(ctx);
        destroy_context(ctx);
        if (!b) exit(10);
    }
    return 0;
}
