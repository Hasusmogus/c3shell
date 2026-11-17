/* sh: a small shell language, for the prompt and for scripts run with 'sh'.
 *
 *   cmd1; cmd2   cmd1 && cmd2   cmd1 || cmd2   ! cmd   # comments
 *   NAME=value  $NAME ${NAME} $? $# $0..$9 $@  $((arithmetic))
 *   'single' "double $quotes" \escapes          cmd > file   cmd >> file
 *   if/elif/else/fi  while/until ... do/done  for NAME in ...; do ...; done
 *   builtins: echo test [ true false : sleep read set unset export shift
 *             exit break continue sh . source
 *
 * The device runs no processes, so there are no pipes, $(...), background
 * jobs or subshells. The text is parsed into a small tree and then run. */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "c3shell.h"

#define SH_FIELDS     64            /* words in one command, after expansion */
#define SH_WORD_MAX   1024          /* one word, after expansion */
#define SH_NEST_MAX   20            /* if/while/for inside each other */
#define SH_DEPTH_MAX  4             /* scripts running scripts */
#define SH_VARS       48
#define SH_VAL_MAX    1024
#define SH_SCRIPT_MAX C3_VI_MAX     /* the largest script sh will read */

/* ================= variables ================= */

struct shstate {
    struct { char name[32]; char *val; } v[SH_VARS];
    int last;                       /* $? */
};

static struct shstate *state(session_t *s)
{
    if (!s->sh)
        s->sh = calloc(1, sizeof *s->sh);
    return s->sh;
}

void sh_free(session_t *s)
{
    if (!s->sh)
        return;
    for (int i = 0; i < SH_VARS; i++)
        free(s->sh->v[i].val);
    free(s->sh);
    s->sh = NULL;
}

static bool name_ok(const char *n, size_t len)
{
    if (len == 0 || len >= 32 || !(isalpha((unsigned char)n[0]) || n[0] == '_'))
        return false;
    for (size_t i = 1; i < len; i++)
        if (!(isalnum((unsigned char)n[i]) || n[i] == '_'))
            return false;
    return true;
}

static const char *var_get(session_t *s, const char *name)
{
    struct shstate *st = state(s);
    for (int i = 0; st && i < SH_VARS; i++)
        if (st->v[i].val && strcmp(st->v[i].name, name) == 0)
            return st->v[i].val;
    return NULL;
}

static int var_set(session_t *s, const char *name, const char *val)
{
    struct shstate *st = state(s);
    int slot = -1;
    if (!st)
        return -1;
    for (int i = 0; i < SH_VARS; i++) {
        if (st->v[i].val && strcmp(st->v[i].name, name) == 0) {
            slot = i;
            break;
        }
        if (!st->v[i].val && slot < 0)
            slot = i;
    }
    if (slot < 0) {
        tn_printf(s, "sh: %s: too many variables (at most %d)\n", name, SH_VARS);
        return -1;
    }
    size_t l = strlen(val);
    char *copy = malloc(l > SH_VAL_MAX ? SH_VAL_MAX + 1 : l + 1);
    if (!copy)
        return -1;
    memcpy(copy, val, l > SH_VAL_MAX ? SH_VAL_MAX : l);
    copy[l > SH_VAL_MAX ? SH_VAL_MAX : l] = 0;
    free(st->v[slot].val);
    snprintf(st->v[slot].name, sizeof st->v[slot].name, "%s", name);
    st->v[slot].val = copy;
    return 0;
}

static void var_unset(session_t *s, const char *name)
{
    struct shstate *st = state(s);
    for (int i = 0; st && i < SH_VARS; i++)
        if (st->v[i].val && strcmp(st->v[i].name, name) == 0) {
            free(st->v[i].val);
            st->v[i].val = NULL;
        }
}

/* ================= lexer ================= */

enum { T_EOF, T_WORD, T_NL, T_SEMI, T_AND, T_OR, T_GT, T_APPEND, T_ERR };

typedef struct {
    const char *p;
    int   tok;
    char *word;                     /* T_WORD: the raw text, quotes and all */
    int   line;
    bool  incomplete;               /* the text ended inside a quote or a construct */
    char  err[96];
    int   nest;
} lex_t;

static void lex_error(lex_t *L, const char *msg)
{
    if (!L->err[0])
        snprintf(L->err, sizeof L->err, "line %d: %s", L->line, msg);
    L->tok = T_ERR;
}

/* p points at the '$' of "$((...))": just past the closing "))", or NULL if there is none. */
static const char *skip_arith(const char *p)
{
    int depth = 0;
    for (p += 1; *p; p++) {
        if (*p == '(')
            depth++;
        else if (*p == ')' && --depth == 0)
            return p + 1;
    }
    return NULL;
}

static void next(lex_t *L)
{
    free(L->word);
    L->word = NULL;
    if (L->tok == T_ERR)
        return;
    for (;;) {
        while (*L->p == ' ' || *L->p == '\t' || *L->p == '\r')
            L->p++;
        if (L->p[0] == '\\' && L->p[1] == '\n') {   /* line continuation */
            L->p += 2;
            L->line++;
            continue;
        }
        if (*L->p == '#') {
            while (*L->p && *L->p != '\n')
                L->p++;
            continue;
        }
        break;
    }
    const char *p = L->p;
    switch (*p) {
    case 0:    L->tok = T_EOF; return;
    case '\n': L->tok = T_NL; L->p++; L->line++; return;
    case ';':  L->tok = T_SEMI; L->p++; return;
    case '&':
        if (p[1] == '&') {
            L->tok = T_AND;
            L->p += 2;
        } else {
            lex_error(L, "background jobs (&) are not supported");
        }
        return;
    case '|':
        if (p[1] == '|') {
            L->tok = T_OR;
            L->p += 2;
        } else {
            lex_error(L, "pipes (|) are not supported");
        }
        return;
    case '>':
        L->tok = p[1] == '>' ? T_APPEND : T_GT;
        L->p += p[1] == '>' ? 2 : 1;
        return;
    case '<': lex_error(L, "input redirection (<) is not supported"); return;
    case '(': case ')': lex_error(L, "subshells ( ) are not supported"); return;
    }
    /* a word */
    while (*p && !strchr(" \t\r\n;&|<>()", *p)) {
        if (*p == '\\') {
            if (!p[1]) {
                L->incomplete = true;
                L->tok = T_EOF;
                return;
            }
            if (p[1] == '\n')
                L->line++;
            p += 2;
        } else if (*p == '\'') {
            const char *e = strchr(p + 1, '\'');
            if (!e) {
                L->incomplete = true;
                L->tok = T_EOF;
                return;
            }
            for (const char *c = p; c < e; c++)
                L->line += *c == '\n';
            p = e + 1;
        } else if (*p == '"') {
            for (p++; *p && *p != '"'; p++) {
                if (*p == '\\' && p[1])
                    p++;
                else if (*p == '$' && p[1] == '(' && p[2] == '(') {
                    const char *e = skip_arith(p);
                    if (!e)
                        break;
                    p = e - 1;
                } else if (*p == '$' && p[1] == '(') {
                    lex_error(L, "command substitution $(...) is not supported");
                    return;
                }
                L->line += *p == '\n';
            }
            if (*p != '"') {
                L->incomplete = true;
                L->tok = T_EOF;
                return;
            }
            p++;
        } else if (*p == '$' && p[1] == '(') {
            if (p[2] != '(') {
                lex_error(L, "command substitution $(...) is not supported");
                return;
            }
            const char *e = skip_arith(p);
            if (!e) {
                L->incomplete = true;
                L->tok = T_EOF;
                return;
            }
            p = e;
        } else if (*p == '`') {
            lex_error(L, "command substitution `...` is not supported");
            return;
        } else {
            p++;
        }
    }
    size_t n = (size_t)(p - L->p);
    L->word = malloc(n + 1);
    if (!L->word) {
        lex_error(L, "out of memory");
        return;
    }
    memcpy(L->word, L->p, n);
    L->word[n] = 0;
    L->p = p;
    L->tok = T_WORD;
}

static bool is_kw(lex_t *L, const char *kw)
{
    return L->tok == T_WORD && strcmp(L->word, kw) == 0;
}

/* ================= parser ================= */

enum { N_CMD, N_SEQ, N_AND, N_OR, N_NOT, N_IF, N_WHILE, N_UNTIL, N_FOR };

typedef struct node {
    int    type;
    struct node *a, *b, *c;         /* SEQ/AND/OR: a b; IF: cond then else; WHILE: cond body; FOR: body in b */
    char **w;                       /* CMD: words (the first nassign are NAME=value); FOR: the list */
    int    nw, nassign;
    char  *redir;                   /* CMD: > or >> target (raw) */
    bool   append;
    char  *var;                     /* FOR */
    bool   all_args;                /* FOR without "in": "$@" */
} node_t;

/* Sequences (a; b; c ...) are freed with a loop, so a long script needs no
 * more stack to free than a short one. */
static void node_free(node_t *n)
{
    while (n) {
        node_t *rest = NULL;
        node_free(n->a);
        node_free(n->c);
        if (n->type == N_SEQ)
            rest = n->b;
        else
            node_free(n->b);
        for (int i = 0; i < n->nw; i++)
            free(n->w[i]);
        free(n->w);
        free(n->redir);
        free(n->var);
        free(n);
        n = rest;
    }
}

static node_t *node_new(lex_t *L, int type)
{
    node_t *n = calloc(1, sizeof *n);
    if (!n)
        lex_error(L, "out of memory");
    else
        n->type = type;
    return n;
}

static node_t *node2(lex_t *L, int type, node_t *a, node_t *b)
{
    node_t *n = node_new(L, type);
    if (!n) {
        node_free(a);
        node_free(b);
        return NULL;
    }
    n->a = a;
    n->b = b;
    return n;
}

static bool failed(lex_t *L) { return L->tok == T_ERR || L->incomplete; }

static bool push_word(lex_t *L, node_t *n)
{
    if (n->nw >= SH_FIELDS) {
        lex_error(L, "too many words in one command");
        return false;
    }
    char **w = realloc(n->w, sizeof *w * (size_t)(n->nw + 1));
    if (!w) {
        lex_error(L, "out of memory");
        return false;
    }
    n->w = w;
    n->w[n->nw++] = L->word;
    L->word = NULL;
    return true;
}

/* more input is needed here: at the end of the text, that means "incomplete" */
static void want(lex_t *L, const char *what)
{
    char msg[64];
    if (L->tok == T_EOF) {
        L->incomplete = true;
        return;
    }
    snprintf(msg, sizeof msg, "%s expected", what);
    lex_error(L, msg);
}

static bool expect_kw(lex_t *L, const char *kw)
{
    if (is_kw(L, kw)) {
        next(L);
        return true;
    }
    char what[16];
    snprintf(what, sizeof what, "'%s'", kw);
    want(L, what);
    return false;
}

static node_t *parse_list(lex_t *L, const char *const *stops);

static bool is_stop(lex_t *L, const char *const *stops)
{
    for (int i = 0; stops && stops[i]; i++)
        if (is_kw(L, stops[i]))
            return true;
    return false;
}

static bool is_assignment(const char *w)
{
    const char *eq = strchr(w, '=');
    return eq && name_ok(w, (size_t)(eq - w));
}

static node_t *parse_simple(lex_t *L)
{
    node_t *n = node_new(L, N_CMD);
    bool started = false;
    while (n && !failed(L)) {
        if (L->tok == T_WORD) {
            bool assign = !started && is_assignment(L->word);
            if (!push_word(L, n))
                break;
            if (assign)
                n->nassign++;
            else
                started = true;
            next(L);
        } else if (L->tok == T_GT || L->tok == T_APPEND) {
            n->append = L->tok == T_APPEND;
            next(L);
            if (L->tok != T_WORD) {
                want(L, "a file name after >");
                break;
            }
            free(n->redir);
            n->redir = L->word;
            L->word = NULL;
            next(L);
        } else {
            break;
        }
    }
    if (failed(L)) {
        node_free(n);
        return NULL;
    }
    return n;
}

static node_t *parse_if(lex_t *L)
{
    static const char *const s_then[] = { "then", NULL }, *const s_body[] = { "elif", "else", "fi", NULL },
                             *const s_fi[] = { "fi", NULL };
    node_t *n = node_new(L, N_IF);
    if (!n)
        return NULL;
    next(L);                                   /* if / elif */
    n->a = parse_list(L, s_then);
    if (!failed(L) && !n->a)
        lex_error(L, "if without a condition");
    if (!failed(L) && expect_kw(L, "then"))
        n->b = parse_list(L, s_body);
    if (!failed(L)) {
        if (is_kw(L, "elif")) {
            if (++L->nest > SH_NEST_MAX)       /* each elif is one more level */
                lex_error(L, "if/while/for nested too deeply");
            else
                n->c = parse_if(L);            /* ends with its own fi */
            L->nest--;
        } else if (is_kw(L, "else")) {
            next(L);
            n->c = parse_list(L, s_fi);
            if (!failed(L))
                expect_kw(L, "fi");
        } else {
            expect_kw(L, "fi");
        }
    }
    if (failed(L)) {
        node_free(n);
        return NULL;
    }
    return n;
}

static node_t *parse_while(lex_t *L)
{
    static const char *const s_do[] = { "do", NULL }, *const s_done[] = { "done", NULL };
    node_t *n = node_new(L, is_kw(L, "until") ? N_UNTIL : N_WHILE);
    if (!n)
        return NULL;
    next(L);
    n->a = parse_list(L, s_do);
    if (!failed(L) && !n->a)
        lex_error(L, "while without a condition");
    if (!failed(L) && expect_kw(L, "do"))
        n->b = parse_list(L, s_done);
    if (!failed(L))
        expect_kw(L, "done");
    if (failed(L)) {
        node_free(n);
        return NULL;
    }
    return n;
}

static node_t *parse_for(lex_t *L)
{
    static const char *const s_done[] = { "done", NULL };
    node_t *n = node_new(L, N_FOR);
    if (!n)
        return NULL;
    next(L);
    if (L->tok != T_WORD || !name_ok(L->word, strlen(L->word))) {
        want(L, "a variable name after for");
        goto fail;
    }
    n->var = L->word;
    L->word = NULL;
    next(L);
    if (is_kw(L, "in")) {
        next(L);
        while (L->tok == T_WORD)
            if (!push_word(L, n))
                goto fail;
            else
                next(L);
    } else {
        n->all_args = true;
    }
    if (L->tok == T_SEMI)
        next(L);
    while (L->tok == T_NL)
        next(L);
    if (failed(L) || !expect_kw(L, "do"))
        goto fail;
    n->b = parse_list(L, s_done);
    if (!failed(L) && expect_kw(L, "done"))
        return n;
fail:
    node_free(n);
    return NULL;
}

static node_t *parse_command(lex_t *L)
{
    if (L->tok == T_WORD) {
        node_t *n = NULL;
        bool compound = is_kw(L, "if") || is_kw(L, "while") || is_kw(L, "until") || is_kw(L, "for");
        if (compound && ++L->nest > SH_NEST_MAX) {
            lex_error(L, "if/while/for nested too deeply");
            return NULL;
        }
        if (is_kw(L, "if"))
            n = parse_if(L);
        else if (is_kw(L, "while") || is_kw(L, "until"))
            n = parse_while(L);
        else if (is_kw(L, "for"))
            n = parse_for(L);
        else if (is_kw(L, "then") || is_kw(L, "elif") || is_kw(L, "else") || is_kw(L, "fi") || is_kw(L, "do") ||
                 is_kw(L, "done") || is_kw(L, "in")) {
            char msg[48];
            snprintf(msg, sizeof msg, "unexpected '%s'", L->word);
            lex_error(L, msg);
            return NULL;
        } else
            return parse_simple(L);
        if (compound)
            L->nest--;
        return n;
    }
    if (L->tok == T_GT || L->tok == T_APPEND)
        return parse_simple(L);
    want(L, "a command");
    return NULL;
}

static node_t *parse_not(lex_t *L)
{
    if (is_kw(L, "!")) {
        next(L);
        node_t *c = parse_command(L);
        return c ? node2(L, N_NOT, c, NULL) : NULL;
    }
    return parse_command(L);
}

#define SH_ANDOR_MAX 64     /* && / || in one chain (each is a level of the tree) */

static node_t *parse_andor(lex_t *L)
{
    node_t *x = parse_not(L);
    int ops = 0;
    while (x && (L->tok == T_AND || L->tok == T_OR)) {
        int type = L->tok == T_AND ? N_AND : N_OR;
        if (++ops > SH_ANDOR_MAX) {
            lex_error(L, "too many && and || in a row");
            node_free(x);
            return NULL;
        }
        next(L);
        while (L->tok == T_NL)
            next(L);
        node_t *y = parse_not(L);
        if (!y) {
            node_free(x);
            return NULL;
        }
        x = node2(L, type, x, y);
    }
    return x;
}

/* Commands separated by ; and newlines, up to (not including) one of the stop words. */
static node_t *parse_list(lex_t *L, const char *const *stops)
{
    node_t *head = NULL, **last = &head;       /* a; b; c  ->  SEQ(a, SEQ(b, c)): run with a loop */
    for (;;) {
        while (L->tok == T_NL || L->tok == T_SEMI)
            next(L);
        if (L->tok == T_EOF || failed(L) || is_stop(L, stops))
            break;
        node_t *x = parse_andor(L);
        if (!x) {
            node_free(head);
            return NULL;
        }
        if (*last) {
            node_t *seq = node2(L, N_SEQ, *last, x);
            if (!seq) {
                *last = NULL;                   /* node2 freed it */
                node_free(head);
                return NULL;
            }
            *last = seq;
            last = &seq->b;
        } else {
            *last = x;
        }
        if (L->tok != T_NL && L->tok != T_SEMI && L->tok != T_EOF && !is_stop(L, stops)) {
            lex_error(L, L->tok == T_WORD ? "unexpected word" : "unexpected symbol");
            node_free(head);
            return NULL;
        }
    }
    return head;
}

static node_t *parse(const char *text, lex_t *L)
{
    memset(L, 0, sizeof *L);
    L->p = text;
    L->line = 1;
    next(L);
    node_t *n = parse_list(L, NULL);
    if (!failed(L) && L->tok != T_EOF)
        lex_error(L, L->tok == T_WORD ? "unexpected word" : "unexpected symbol");
    free(L->word);
    L->word = NULL;
    if (failed(L)) {
        node_free(n);
        return NULL;
    }
    return n;
}

bool sh_incomplete(const char *text)
{
    lex_t L;
    node_free(parse(text, &L));
    return L.incomplete && L.tok != T_ERR;
}

/* ================= running ================= */

typedef struct {
    session_t *s;
    int    argc;                    /* positional parameters: argv[0] is $0 */
    char **argv;
    int    depth;                   /* scripts running scripts */
    int    loops;                   /* loops we are inside of */
    int    brk, cont;               /* break / continue pending (levels) */
    bool   exiting;
} ctx_t;

static int run(ctx_t *x, node_t *n);

static bool stopping(ctx_t *x)
{
    session_t *s = x->s;
    return x->exiting || x->brk || x->cont || s->intr || s->closed || s->logout;
}

/* ---- expansion ---- */

typedef struct {
    char  *b;
    size_t n, cap;
} sbuf_t;

static void sb_add(sbuf_t *b, const char *p, size_t n)
{
    if (b->n + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 64;
        while (cap < b->n + n + 1)
            cap *= 2;
        if (cap > SH_WORD_MAX + 1)
            cap = SH_WORD_MAX + 1;
        if (b->n + 1 >= cap)
            return;                             /* full: the rest is cut off */
        char *nb = realloc(b->b, cap);
        if (!nb)
            return;
        b->b = nb;
        b->cap = cap;
    }
    if (n > b->cap - 1 - b->n)
        n = b->cap - 1 - b->n;
    memcpy(b->b + b->n, p, n);
    b->n += n;
    b->b[b->n] = 0;
}

static void sb_addc(sbuf_t *b, char c) { sb_add(b, &c, 1); }

typedef struct {
    char **v;
    int    n;
} fields_t;

static void fields_free(fields_t *f)
{
    for (int i = 0; i < f->n; i++)
        free(f->v[i]);
    free(f->v);
    f->v = NULL;
    f->n = 0;
}

static int field_add(ctx_t *x, fields_t *f, const char *str)
{
    if (f->n >= SH_FIELDS) {
        tn_printf(x->s, "sh: too many words in one command (at most %d)\n", SH_FIELDS);
        return -1;
    }
    char **v = realloc(f->v, sizeof *v * (size_t)(f->n + 1));
    char *c = strdup(str ? str : "");
    if (!v || !c) {
        free(c);
        if (v)
            f->v = v;
        return -1;
    }
    f->v = v;
    f->v[f->n++] = c;
    return 0;
}

/* ---- $((arithmetic)) ---- */

typedef struct {
    const char *p;
    ctx_t *x;
    const char *err;
} ar_t;

static long ar_or(ar_t *a);

static void ar_ws(ar_t *a)
{
    while (*a->p == ' ' || *a->p == '\t' || *a->p == '\n')
        a->p++;
}

static long ar_primary(ar_t *a)
{
    ar_ws(a);
    if (*a->p == '(') {
        a->p++;
        long v = ar_or(a);
        ar_ws(a);
        if (*a->p == ')')
            a->p++;
        else
            a->err = "missing )";
        return v;
    }
    if (*a->p == '-' || *a->p == '+' || *a->p == '!') {
        char op = *a->p++;
        long v = ar_primary(a);
        return op == '-' ? -v : op == '!' ? !v : v;
    }
    if (isdigit((unsigned char)*a->p))
        return strtol(a->p, (char **)&a->p, 0);
    if (*a->p == '$')
        a->p++;
    const char *s = a->p;
    while (isalnum((unsigned char)*a->p) || *a->p == '_')
        a->p++;
    if (a->p == s) {
        a->err = "number or variable expected";
        return 0;
    }
    char name[32];
    snprintf(name, sizeof name, "%.*s", (int)(a->p - s), s);
    const char *v = isdigit((unsigned char)name[0])
                        ? (atoi(name) < a->x->argc ? a->x->argv[atoi(name)] : NULL)
                        : var_get(a->x->s, name);
    return v ? strtol(v, NULL, 0) : 0;
}

static long ar_mul(ar_t *a)
{
    long v = ar_primary(a);
    for (;;) {
        ar_ws(a);
        char op = *a->p;
        if (op != '*' && op != '/' && op != '%')
            return v;
        a->p++;
        long r = ar_primary(a);
        if (op != '*' && r == 0) {
            a->err = "division by zero";
            return 0;
        }
        v = op == '*' ? v * r : op == '/' ? v / r : v % r;
    }
}

static long ar_add(ar_t *a)
{
    long v = ar_mul(a);
    for (;;) {
        ar_ws(a);
        if (*a->p != '+' && *a->p != '-')
            return v;
        char op = *a->p++;
        long r = ar_mul(a);
        v = op == '+' ? v + r : v - r;
    }
}

static long ar_cmp(ar_t *a)
{
    long v = ar_add(a);
    for (;;) {
        ar_ws(a);
        const char *p = a->p;
        int op = 0;
        if (p[0] == '<' && p[1] == '=') op = 'l', a->p += 2;
        else if (p[0] == '>' && p[1] == '=') op = 'g', a->p += 2;
        else if (p[0] == '=' && p[1] == '=') op = '=', a->p += 2;
        else if (p[0] == '!' && p[1] == '=') op = '!', a->p += 2;
        else if (p[0] == '<') op = '<', a->p++;
        else if (p[0] == '>') op = '>', a->p++;
        else return v;
        long r = ar_add(a);
        v = op == 'l' ? v <= r : op == 'g' ? v >= r : op == '=' ? v == r : op == '!' ? v != r : op == '<' ? v < r : v > r;
    }
}

static long ar_and(ar_t *a)
{
    long v = ar_cmp(a);
    for (ar_ws(a); a->p[0] == '&' && a->p[1] == '&'; ar_ws(a)) {
        a->p += 2;
        long r = ar_cmp(a);
        v = v && r;
    }
    return v;
}

static long ar_or(ar_t *a)
{
    long v = ar_and(a);
    for (ar_ws(a); a->p[0] == '|' && a->p[1] == '|'; ar_ws(a)) {
        a->p += 2;
        long r = ar_and(a);
        v = v || r;
    }
    return v;
}

static void arith(ctx_t *x, const char *expr, size_t len, sbuf_t *out)
{
    char *e = malloc(len + 1), num[24];
    if (!e)
        return;
    memcpy(e, expr, len);
    e[len] = 0;
    ar_t a = { e, x, NULL };
    long v = ar_or(&a);
    ar_ws(&a);
    if (!a.err && *a.p)
        a.err = "unexpected character";
    if (a.err) {
        tn_printf(x->s, "sh: $((%s)): %s\n", e, a.err);
        v = 0;
    }
    free(e);
    snprintf(num, sizeof num, "%ld", v);
    sb_add(out, num, strlen(num));
}

/* After a '$' at *pp: append the value and advance. */
static void dollar(ctx_t *x, const char **pp, sbuf_t *out)
{
    const char *p = *pp;
    char name[32], num[16];
    const char *val = NULL;

    if (p[0] == '(' && p[1] == '(') {
        const char *e = skip_arith(p - 1);     /* p is just past the '$' */
        if (!e) {
            sb_addc(out, '$');
            return;
        }
        arith(x, p + 2, (size_t)(e - 2 - (p + 2)), out);
        *pp = e;
        return;
    }
    if (*p == '{') {
        const char *e = strchr(p, '}');
        if (!e || (size_t)(e - p - 1) >= sizeof name) {
            sb_addc(out, '$');
            return;
        }
        snprintf(name, sizeof name, "%.*s", (int)(e - p - 1), p + 1);
        *pp = e + 1;
    } else if (*p == '?' || *p == '#' || *p == '@' || *p == '*' || isdigit((unsigned char)*p)) {
        name[0] = *p;
        name[1] = 0;
        *pp = p + 1;
    } else if (isalpha((unsigned char)*p) || *p == '_') {
        const char *s = p;
        while (isalnum((unsigned char)*p) || *p == '_')
            p++;
        snprintf(name, sizeof name, "%.*s", (int)(p - s), s);
        *pp = p;
    } else {
        sb_addc(out, '$');                      /* a lone $ */
        return;
    }
    if (strcmp(name, "?") == 0) {
        snprintf(num, sizeof num, "%d", state(x->s) ? state(x->s)->last : 0);
        val = num;
    } else if (strcmp(name, "#") == 0) {
        snprintf(num, sizeof num, "%d", x->argc > 0 ? x->argc - 1 : 0);
        val = num;
    } else if (strcmp(name, "@") == 0 || strcmp(name, "*") == 0) {
        for (int i = 1; i < x->argc; i++) {
            if (i > 1)
                sb_addc(out, ' ');
            sb_add(out, x->argv[i], strlen(x->argv[i]));
        }
        return;
    } else if (isdigit((unsigned char)name[0])) {
        int i = atoi(name);
        val = i < x->argc ? x->argv[i] : NULL;
    } else {
        val = var_get(x->s, name);
    }
    if (val)
        sb_add(out, val, strlen(val));
}

/* Expand one raw word into fields: quotes removed, $ expanded; unquoted
 * expansions are split at spaces when split is set. */
static int expand(ctx_t *x, const char *raw, fields_t *f, bool split)
{
    sbuf_t cur = { 0 };
    bool have = false;                          /* the current field exists (even if empty: "") */
    int rc = 0;

    if (strcmp(raw, "\"$@\"") == 0) {           /* each argument its own word, spaces and all */
        for (int i = 1; i < x->argc && rc == 0; i++)
            rc = field_add(x, f, x->argv[i]);
        return rc;
    }
    for (const char *p = raw; *p && rc == 0;) {
        if (*p == '\\') {
            if (p[1] == '\n') {
                p += 2;
                continue;
            }
            if (p[1]) {
                sb_addc(&cur, p[1]);
                have = true;
                p += 2;
            } else {
                p++;
            }
        } else if (*p == '\'') {
            const char *e = strchr(p + 1, '\'');
            if (!e)
                e = p + strlen(p);
            sb_add(&cur, p + 1, (size_t)(e - p - 1));
            have = true;
            p = *e ? e + 1 : e;
        } else if (*p == '"') {
            have = true;
            for (p++; *p && *p != '"';) {
                if (*p == '\\' && p[1] && strchr("$\"\\`\n", p[1])) {
                    if (p[1] != '\n')
                        sb_addc(&cur, p[1]);
                    p += 2;
                } else if (*p == '$') {
                    p++;
                    dollar(x, &p, &cur);
                } else {
                    sb_addc(&cur, *p++);
                }
            }
            if (*p == '"')
                p++;
        } else if (*p == '$') {
            sbuf_t v = { 0 };
            p++;
            dollar(x, &p, &v);
            for (size_t i = 0; i < v.n && rc == 0; i++) {
                char c = v.b[i];
                if (split && (c == ' ' || c == '\t' || c == '\n')) {
                    if (have || cur.n)
                        rc = field_add(x, f, cur.n ? cur.b : "");
                    cur.n = 0;
                    if (cur.b)
                        cur.b[0] = 0;
                    have = false;
                } else {
                    sb_addc(&cur, c);
                }
            }
            free(v.b);
        } else {
            sb_addc(&cur, *p++);
            have = true;
        }
    }
    if (rc == 0 && (have || cur.n))
        rc = field_add(x, f, cur.n ? cur.b : "");
    free(cur.b);
    return rc;
}

/* A word as one string (assignments, redirection targets). */
static char *expand1(ctx_t *x, const char *raw)
{
    fields_t f = { 0 };
    if (expand(x, raw, &f, false) != 0) {
        fields_free(&f);
        return NULL;
    }
    char *r = f.n ? f.v[0] : strdup("");
    if (f.n)
        f.v[0] = NULL;
    fields_free(&f);
    return r;
}

/* ---- builtins ---- */

static int bi_echo(ctx_t *x, int argc, char **argv)
{
    int i = 1;
    bool nl = true;
    if (argc > 1 && strcmp(argv[1], "-n") == 0) {
        nl = false;
        i = 2;
    }
    for (; i < argc; i++) {
        tn_puts(x->s, argv[i]);
        if (i + 1 < argc)
            tn_puts(x->s, " ");
    }
    if (nl)
        tn_puts(x->s, "\n");
    return 0;
}

static bool to_int(const char *s, long *v)
{
    char *end;
    if (!*s)
        return false;
    *v = strtol(s, &end, 10);
    return *end == 0;
}

static int file_test(ctx_t *x, char op, const char *arg)
{
    char vpath[C3_PATH_MAX], host[C3_HOST_MAX];
    struct stat st;
    if (fs_resolve(x->s, arg, vpath, sizeof vpath) != 0 || fs_host(vpath, host, sizeof host) != 0 ||
        stat(host, &st) != 0)
        return 1;
    switch (op) {
    case 'e': return 0;
    case 'f': return S_ISREG(st.st_mode) ? 0 : 1;
    case 'd': return S_ISDIR(st.st_mode) ? 0 : 1;
    default:  return st.st_size > 0 ? 0 : 1;   /* -s */
    }
}

/* 0 true, 1 false, 2 error */
static int test_eval(ctx_t *x, int argc, char **argv)
{
    for (int i = 0; i < argc; i++)              /* -o binds loosest, then -a */
        if (strcmp(argv[i], "-o") == 0 && i > 0 && i < argc - 1) {
            int l = test_eval(x, i, argv);
            if (l == 2)
                return 2;
            return l == 0 ? 0 : test_eval(x, argc - i - 1, argv + i + 1);
        }
    for (int i = 0; i < argc; i++)
        if (strcmp(argv[i], "-a") == 0 && i > 0 && i < argc - 1) {
            int l = test_eval(x, i, argv);
            if (l != 0)
                return l;
            return test_eval(x, argc - i - 1, argv + i + 1);
        }
    if (argc > 0 && strcmp(argv[0], "!") == 0) {
        int r = test_eval(x, argc - 1, argv + 1);
        return r == 2 ? 2 : !r;
    }
    if (argc == 0)
        return 1;
    if (argc == 1)
        return argv[0][0] ? 0 : 1;
    if (argc == 2) {
        const char *op = argv[0];
        if (strcmp(op, "-n") == 0) return argv[1][0] ? 0 : 1;
        if (strcmp(op, "-z") == 0) return argv[1][0] ? 1 : 0;
        if (op[0] == '-' && strchr("efds", op[1]) && !op[2])
            return file_test(x, op[1], argv[1]);
        tn_printf(x->s, "test: %s: unknown condition\n", op);
        return 2;
    }
    if (argc == 3) {
        const char *a = argv[0], *op = argv[1], *b = argv[2];
        long l, r;
        if (strcmp(op, "=") == 0 || strcmp(op, "==") == 0) return strcmp(a, b) == 0 ? 0 : 1;
        if (strcmp(op, "!=") == 0) return strcmp(a, b) != 0 ? 0 : 1;
        static const char *const nops[] = { "-eq", "-ne", "-lt", "-le", "-gt", "-ge" };
        for (int i = 0; i < 6; i++) {
            if (strcmp(op, nops[i]) != 0)
                continue;
            if (!to_int(a, &l) || !to_int(b, &r)) {
                tn_printf(x->s, "test: %s: a number is needed\n", !to_int(a, &l) ? a : b);
                return 2;
            }
            bool t = i == 0 ? l == r : i == 1 ? l != r : i == 2 ? l < r : i == 3 ? l <= r : i == 4 ? l > r : l >= r;
            return t ? 0 : 1;
        }
        tn_printf(x->s, "test: %s: unknown comparison\n", op);
        return 2;
    }
    tn_puts(x->s, "test: too many arguments\n");
    return 2;
}

static int bi_test(ctx_t *x, int argc, char **argv)
{
    if (strcmp(argv[0], "[") == 0) {
        if (strcmp(argv[argc - 1], "]") != 0) {
            tn_puts(x->s, "[: missing ]\n");
            return 2;
        }
        argc--;
    }
    return test_eval(x, argc - 1, argv + 1);
}

static int bi_true(ctx_t *x, int argc, char **argv)
{
    (void)x;
    (void)argc;
    return strcmp(argv[0], "false") == 0 ? 1 : 0;
}

static int bi_sleep(ctx_t *x, int argc, char **argv)
{
    char *end;
    double secs = argc == 2 ? strtod(argv[1], &end) : -1;
    if (argc != 2 || *end || secs < 0 || secs > 86400) {
        tn_puts(x->s, "usage: sleep seconds   (fractions like 0.5 work)\n");
        return 2;
    }
    for (long ms = (long)(secs * 1000); ms > 0; ms -= 100) {
        port_sleep_ms(ms > 100 ? 100 : (uint32_t)ms);
        if (tn_peek_intr(x->s) || x->s->closed)
            return 130;
    }
    return 0;
}

static int bi_read(ctx_t *x, int argc, char **argv)
{
    const char *prompt = "";
    char line[LINE_MAX_];
    int i = 1;
    if (argc > 2 && strcmp(argv[1], "-p") == 0) {
        prompt = argv[2];
        i = 3;
    }
    for (int k = i; k < argc; k++)
        if (!name_ok(argv[k], strlen(argv[k]))) {
            tn_printf(x->s, "read: %s: not a variable name\n", argv[k]);
            return 2;
        }
    int n = tn_readline(x->s, prompt, line, sizeof line, RL_ECHO, C3_IDLE_TIMEOUT_S);
    if (n < 0)
        return 1;
    if (i == argc)
        return var_set(x->s, "REPLY", line) == 0 ? 0 : 1;
    char *p = line;
    for (int k = i; k < argc; k++) {           /* a word each; the last name takes the rest */
        while (*p == ' ' || *p == '\t')
            p++;
        char *e = p;
        if (k < argc - 1) {
            while (*e && *e != ' ' && *e != '\t')
                e++;
            if (*e)
                *e++ = 0;
        } else {
            e = p + strlen(p);
            while (e > p && (e[-1] == ' ' || e[-1] == '\t'))
                *--e = 0;
        }
        var_set(x->s, argv[k], p);
        p = k < argc - 1 ? e : p + strlen(p);
    }
    return 0;
}

static int bi_set(ctx_t *x, int argc, char **argv)
{
    struct shstate *st = state(x->s);
    (void)argc;
    (void)argv;
    for (int i = 0; st && i < SH_VARS; i++)
        if (st->v[i].val)
            tn_printf(x->s, "%s=%s\n", st->v[i].name, st->v[i].val);
    return 0;
}

static int bi_unset(ctx_t *x, int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
        var_unset(x->s, argv[i]);
    return 0;
}

static int bi_export(ctx_t *x, int argc, char **argv)      /* no environment here: just assign */
{
    for (int i = 1; i < argc; i++) {
        char *eq = strchr(argv[i], '=');
        if (eq && name_ok(argv[i], (size_t)(eq - argv[i]))) {
            *eq = 0;
            if (var_set(x->s, argv[i], eq + 1) != 0)
                return 1;
        }
    }
    return 0;
}

static int bi_shift(ctx_t *x, int argc, char **argv)
{
    long n = 1;
    if (argc > 1 && (!to_int(argv[1], &n) || n < 0)) {
        tn_puts(x->s, "usage: shift [n]\n");
        return 2;
    }
    if (n >= x->argc)
        return 1;
    for (int i = 1; i + n < x->argc; i++)
        x->argv[i] = x->argv[i + n];
    x->argc -= (int)n;
    return 0;
}

static int bi_exit(ctx_t *x, int argc, char **argv)
{
    long n = state(x->s) ? state(x->s)->last : 0;
    if (argc > 1)
        to_int(argv[1], &n);
    x->exiting = true;
    if (x->depth == 0)
        x->s->logout = true;                    /* at the prompt: log out */
    return (int)(n & 0xFF);
}

static int bi_break(ctx_t *x, int argc, char **argv)
{
    long n = 1;
    if (argc > 1 && (!to_int(argv[1], &n) || n < 1)) {
        tn_printf(x->s, "usage: %s [n]\n", argv[0]);
        return 2;
    }
    if (x->loops == 0) {
        tn_printf(x->s, "%s: only inside a loop\n", argv[0]);
        return 1;
    }
    if (n > x->loops)
        n = x->loops;
    if (argv[0][0] == 'b')
        x->brk = (int)n;
    else
        x->cont = (int)n;
    return 0;
}

static int run_text(ctx_t *x, const char *text, const char *name);

/* The script's text, or NULL (and a message). Out of bi_sh's frame, like open_redirect. */
static __attribute__((noinline)) char *load_script(ctx_t *x, const char *cmd, const char *path)
{
    char vpath[C3_PATH_MAX], host[C3_HOST_MAX], *text = NULL;
    size_t len;
    int r = fs_resolve(x->s, path, vpath, sizeof vpath);
    if (r == 0)
        r = fs_host(vpath, host, sizeof host);
    if (r == 0)
        r = fs_read_file(host, &text, &len, SH_SCRIPT_MAX);
    if (r != 0)
        tn_printf(x->s, "%s: %s: %s\n", cmd, path, r == -EFBIG ? "too big to run (32 KB at most)" : strerror(-r));
    return r == 0 ? text : NULL;
}

/* sh file [args] (own $0 $1 ...) and . file / source file (in the current context) */
static int bi_sh(ctx_t *x, int argc, char **argv)
{
    bool source = strcmp(argv[0], "sh") != 0;
    int r;
    if (argc < 2) {
        tn_printf(x->s, "usage: %s\n", source ? ". file" : "sh file [arguments]");
        return 2;
    }
    if (x->depth >= SH_DEPTH_MAX) {
        tn_printf(x->s, "%s: scripts nested too deeply\n", argv[1]);
        return 2;
    }
    char *text = load_script(x, argv[0], argv[1]);
    if (!text)
        return 2;
    char doing[sizeof x->s->doing];
    memcpy(doing, x->s->doing, sizeof doing);
    snprintf(x->s->doing, sizeof x->s->doing, "sh %s", argv[1]);
    if (source) {
        x->depth++;
        r = run_text(x, text, argv[1]);
        x->depth--;
    } else {
        /* its own copy of the argument list: shift rearranges it, and the
         * strings themselves stay owned by the caller's command */
        char **av = malloc(sizeof *av * (size_t)argc);
        if (!av) {
            memcpy(x->s->doing, doing, sizeof doing);
            free(text);
            return 1;
        }
        memcpy(av, argv + 1, sizeof *av * (size_t)(argc - 1));
        av[argc - 1] = NULL;
        ctx_t sub = { .s = x->s, .argc = argc - 1, .argv = av, .depth = x->depth + 1 };
        r = run_text(&sub, text, argv[1]);
        free(av);
    }
    memcpy(x->s->doing, doing, sizeof doing);
    free(text);
    return r;
}

static const struct {
    const char *name;
    int (*fn)(ctx_t *, int, char **);
} builtins[] = {
    { "echo", bi_echo },     { "test", bi_test },   { "[", bi_test },         { "true", bi_true },
    { "false", bi_true },    { ":", bi_true },      { "sleep", bi_sleep },    { "read", bi_read },
    { "set", bi_set },       { "unset", bi_unset }, { "export", bi_export },  { "shift", bi_shift },
    { "exit", bi_exit },     { "break", bi_break }, { "continue", bi_break }, { "sh", bi_sh },
    { ".", bi_sh },          { "source", bi_sh },
};

const char *const sh_builtins[] = { "echo", "test", "true", "false", "sleep", "read", "set", "unset",
                                    "export", "shift", "exit", "break", "continue", "sh", "source", NULL };

/* ---- commands ---- */

/* > file / >> file, in the file area. Kept out of run_cmd so its path buffers
 * are not on the stack while the command runs (scripts nest through run_cmd). */
static __attribute__((noinline)) FILE *open_redirect(ctx_t *x, node_t *n)
{
    session_t *s = x->s;
    char *target = expand1(x, n->redir), vpath[C3_PATH_MAX], host[C3_HOST_MAX];
    int r = target ? fs_resolve(s, target, vpath, sizeof vpath) : -ENOMEM;
    struct stat st;
    FILE *out = NULL;
    if (r == 0)
        r = fs_host(vpath, host, sizeof host);
    if (r == 0 && stat(host, &st) == 0 && S_ISDIR(st.st_mode))
        r = -EISDIR;
    if (r == 0 && !(out = fopen(host, n->append ? "a" : "w")))
        r = -errno;
    if (r != 0)
        tn_printf(s, "sh: %s: %s\n", target ? target : n->redir, strerror(-r));
    free(target);
    return out;
}

static int run_cmd(ctx_t *x, node_t *n)
{
    session_t *s = x->s;
    fields_t f = { 0 };
    int rc = 0;

    if (tn_peek_intr(s) || s->intr)
        return 130;
    for (int i = 0; i < n->nassign; i++) {     /* NAME=value ... */
        char *eq = strchr(n->w[i], '='), name[32];
        snprintf(name, sizeof name, "%.*s", (int)(eq - n->w[i]), n->w[i]);
        char *v = expand1(x, eq + 1);
        if (!v || var_set(s, name, v) != 0)
            rc = 1;
        free(v);
    }
    for (int i = n->nassign; i < n->nw && rc == 0; i++)
        if (expand(x, n->w[i], &f, true) != 0)
            rc = 1;
    if (rc != 0) {
        fields_free(&f);
        return rc;
    }

    FILE *out = NULL;
    void *saved = s->redir;
    if (n->redir) {
        if (!(out = open_redirect(x, n))) {
            fields_free(&f);
            return 1;
        }
        s->redir = out;
    }

    if (f.n > 0) {
        rc = -1;
        for (size_t i = 0; i < sizeof builtins / sizeof builtins[0]; i++)
            if (strcmp(f.v[0], builtins[i].name) == 0) {
                rc = builtins[i].fn(x, f.n, f.v);
                break;
            }
        if (rc == -1)
            rc = shell_command(s, f.n, f.v);
        if (rc == -1) {
            s->redir = saved;                   /* the complaint goes to the terminal */
            tn_printf(s, "%s: unknown command - type 'help'\n", f.v[0]);
            rc = 127;
        }
    }
    s->redir = saved;
    if (out && fclose(out) != 0) {
        tn_printf(s, "sh: %s: could not finish writing (%s)\n", n->redir, strerror(errno));
        rc = rc ? rc : 1;
    }
    fields_free(&f);
    if (s->intr && rc == 0)
        rc = 130;
    return rc;
}

static int run_loop_body(ctx_t *x, node_t *body, int *rc, bool *stop)
{
    x->loops++;
    *rc = run(x, body);
    x->loops--;
    if (x->brk) {
        x->brk--;
        *stop = true;
    } else if (x->cont) {
        if (--x->cont > 0)
            *stop = true;                       /* continue 2: on with an outer loop */
    }
    return *rc;
}

static int run(ctx_t *x, node_t *n)
{
    int rc = 0;
    if (!n)
        return 0;
    switch (n->type) {
    case N_CMD:
        rc = run_cmd(x, n);
        break;
    case N_SEQ:                                 /* a loop, not recursion: long scripts need no more stack */
        for (;;) {
            rc = run(x, n->a);
            if (stopping(x))
                break;
            if (n->b && n->b->type == N_SEQ) {
                n = n->b;
                continue;
            }
            rc = run(x, n->b);
            break;
        }
        break;
    case N_AND:
        rc = run(x, n->a);
        if (rc == 0 && !stopping(x))
            rc = run(x, n->b);
        break;
    case N_OR:
        rc = run(x, n->a);
        if (rc != 0 && !stopping(x))
            rc = run(x, n->b);
        break;
    case N_NOT:
        rc = run(x, n->a) == 0 ? 1 : 0;
        break;
    case N_IF: {
        int c = run(x, n->a);
        if (stopping(x))
            return c;
        rc = c == 0 ? run(x, n->b) : n->c ? run(x, n->c) : 0;
        break;
    }
    case N_WHILE:
    case N_UNTIL:
        for (bool stop = false; !stop;) {
            int c = run(x, n->a);
            if (stopping(x) || (n->type == N_WHILE ? c != 0 : c == 0))
                break;
            run_loop_body(x, n->b, &rc, &stop);
            if (x->exiting || x->s->intr || x->s->closed || x->s->logout)
                break;
        }
        break;
    case N_FOR: {
        fields_t list = { 0 };
        if (n->all_args) {
            for (int i = 1; i < x->argc; i++)
                field_add(x, &list, x->argv[i]);
        } else {
            for (int i = 0; i < n->nw; i++)
                if (expand(x, n->w[i], &list, true) != 0) {
                    fields_free(&list);
                    return 1;
                }
        }
        bool stop = false;
        for (int i = 0; i < list.n && !stop; i++) {
            if (var_set(x->s, n->var, list.v[i]) != 0) {
                rc = 1;
                break;
            }
            run_loop_body(x, n->b, &rc, &stop);
            if (x->exiting || x->s->intr || x->s->closed || x->s->logout)
                break;
        }
        fields_free(&list);
        break;
    }
    }
    if (state(x->s))
        state(x->s)->last = rc;
    return rc;
}

/* Parse, reporting any syntax error; *ok tells an empty script from a broken one. */
static __attribute__((noinline)) node_t *parse_report(ctx_t *x, const char *text, const char *name, bool *ok)
{
    lex_t L;
    node_t *tree = parse(text, &L);
    *ok = tree || !(L.err[0] || L.incomplete);
    if (!*ok)
        tn_printf(x->s, "sh: %s%s%s\n", name ? name : "", name ? ": " : "",
                  L.err[0] ? L.err : "unexpected end (an if, while, for or quote is not closed)");
    return tree;
}

static int run_text(ctx_t *x, const char *text, const char *name)
{
    bool ok;
    node_t *tree = parse_report(x, text, name, &ok);
    if (!ok) {
        if (state(x->s))
            state(x->s)->last = 2;
        return 2;
    }
    int rc = run(x, tree);
    node_free(tree);
    if (x->s->intr && !x->exiting) {
        rc = 130;
        if (state(x->s))
            state(x->s)->last = rc;
    }
    if (x->exiting && x->depth > 0)
        x->exiting = false;                     /* exit ends this script, not its caller */
    return rc;
}

int sh_run(session_t *s, const char *text)
{
    static char name0[] = C3_NAME;
    char *argv0[] = { name0, NULL };
    ctx_t x = { .s = s, .argc = 1, .argv = argv0 };
    return run_text(&x, text, NULL);
}
