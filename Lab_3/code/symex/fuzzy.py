import z3
import multiprocessing
import sys
import collections
import queue
import signal
import operator
import inspect
import builtins
import functools
from dataclasses import dataclass, field

## Our AST structure

class sym_ast(object):
    def __str__(self):
        return str(self._z3expr())

class sym_func_apply(sym_ast):
    def __init__(self, *args):
        for a in args:
            if not isinstance(a, sym_ast):
                raise Exception(
                    "Passing a non-AST node %s %s as argument to %s"
                    % (a, type(a), type(self))
                )
        self.args = args

    def __eq__(self, o):
        if type(self) != type(o):
            return False
        if len(self.args) != len(o.args):
            return False
        return all(sa == oa for (sa, oa) in zip(self.args, o.args))

    def __hash__(self):
        return functools.reduce(operator.xor, [hash(a) for a in self.args])

class sym_unop(sym_func_apply):
    def __init__(self, a):
        super(sym_unop, self).__init__(a)

    @property
    def a(self):
        return self.args[0]

class sym_binop(sym_func_apply):
    def __init__(self, a, b):
        super(sym_binop, self).__init__(a, b)

    @property
    def a(self):
        return self.args[0]

    @property
    def b(self):
        return self.args[1]

class sym_triop(sym_func_apply):
    def __init__(self, a, b, c):
        super(sym_triop, self).__init__(a, b, c)

    @property
    def a(self):
        return self.args[0]

    @property
    def b(self):
        return self.args[1]

    @property
    def c(self):
        return self.args[2]

def z3expr(o):
    assert isinstance(o, sym_ast)
    return o._z3expr()

class const_str(sym_ast):
    def __init__(self, v):
        self.v = v

    def __eq__(self, o):
        if not isinstance(o, const_str):
            return False
        return self.v == o.v

    def __hash__(self):
        return hash(self.v)

    def _z3expr(self):
        return z3.StringVal(self.v)

class const_int(sym_ast):
    def __init__(self, i):
        self.i = i

    def __eq__(self, o):
        if not isinstance(o, const_int):
            return False
        return self.i == o.i

    def __hash__(self):
        return hash(self.i)

    def _z3expr(self):
        return self.i

class const_bool(sym_ast):
    def __init__(self, b):
        self.b = b

    def __eq__(self, o):
        if not isinstance(o, const_bool):
            return False
        return self.b == o.b

    def __hash__(self):
        return hash(self.b)

    def _z3expr(self):
        return self.b

def ast(o):
    if hasattr(o, "_sym_ast"):
        return o._sym_ast()
    if isinstance(o, bool):
        return const_bool(o)
    if isinstance(o, int):
        return const_int(o)
    if isinstance(o, str):
        return const_str(o)
    if isinstance(o, bytes):
        return const_str(o.decode("unicode-escape"))
    raise Exception("Trying to make an AST out of %s %s" % (o, type(o)))

## Logic expressions

class sym_eq(sym_binop):
    def _z3expr(self):
        return z3expr(self.a) == z3expr(self.b)

class sym_and(sym_func_apply):
    def _z3expr(self):
        return z3.And(*[z3expr(a) for a in self.args])

class sym_or(sym_func_apply):
    def _z3expr(self):
        return z3.Or(*[z3expr(a) for a in self.args])

class sym_not(sym_unop):
    def _z3expr(self):
        return z3.Not(z3expr(self.a))

## Arithmetic

class sym_int(sym_ast):
    def __init__(self, id):
        self.id = id

    def __eq__(self, o):
        if not isinstance(o, sym_int):
            return False
        return self.id == o.id

    def __hash__(self):
        return hash(self.id)

    def _z3expr(self):
        return z3.Int(self.id)

class sym_lt(sym_binop):
    def _z3expr(self):
        return z3expr(self.a) < z3expr(self.b)

class sym_gt(sym_binop):
    def _z3expr(self):
        return z3expr(self.a) > z3expr(self.b)

class sym_plus(sym_binop):
    def _z3expr(self):
        return z3expr(self.a) + z3expr(self.b)

class sym_minus(sym_binop):
    def _z3expr(self):
        return z3expr(self.a) - z3expr(self.b)

## Exercise 2: your code here.
## Implement AST nodes for division and multiplication.
class sym_division(sym_binop):
    def _z3expr(self):
        return z3expr(self.a) / z3expr(self.b)

class sym_multiply(sym_binop):
    def _z3expr(self):
        return z3expr(self.a) * z3expr(self.b)

## String operations

class sym_str(sym_ast):
    def __init__(self, id):
        self.id = id

    def __eq__(self, o):
        if not isinstance(o, sym_str):
            return False
        return self.id == o.id

    def __hash__(self):
        return hash(self.id)

    def _z3expr(self):
        return z3.Const(self.id, z3.StringSort())

class sym_concat(sym_binop):
    def _z3expr(self):
        return z3.Concat(z3expr(self.a), z3expr(self.b))

class sym_length(sym_unop):
    def _z3expr(self):
        return z3.Length(z3expr(self.a))

class sym_substring(sym_triop):
    def _z3expr(self):
        return z3.SubString(z3expr(self.a), z3expr(self.b), z3expr(self.c))

class sym_indexof(sym_binop):
    def _z3expr(self):
        return z3.Indexof(z3expr(self.a), z3expr(self.b))

class sym_contains(sym_binop):
    def _z3expr(self):
        return z3.Contains(z3expr(self.a), z3expr(self.b))

class sym_startswith(sym_binop):
    def _z3expr(self):
        return z3.PrefixOf(z3expr(self.b), z3expr(self.a))

class sym_endswith(sym_binop):
    def _z3expr(self):
        return z3.SuffixOf(z3expr(self.b), z3expr(self.a))

class sym_replace(sym_triop):
    def _z3expr(self):
        return z3.Replace(z3expr(self.a), z3expr(self.b), z3expr(self.c))

## Symbolic simplifications

class patname(sym_ast):
    def __init__(self, name, pattern=None):
        self.name = name
        self.pattern = pattern

simplify_patterns = [
    (
        sym_substring(
            patname(
                "a",
                sym_substring(
                    patname("b"),
                    patname("c"),
                    sym_minus(sym_length(patname("b")), patname("c")),
                ),
            ),
            patname("d"),
            sym_minus(sym_length(patname("a")), patname("d")),
        ),
        sym_substring(
            patname("b"),
            sym_plus(patname("c"), patname("d")),
            sym_minus(sym_length(patname("b")), sym_plus(patname("c"), patname("d"))),
        ),
    ),
    (sym_concat(patname("a"), const_str("")), patname("a")),
]

def pattern_match(expr, pat, vars):
    if isinstance(pat, patname):
        if pat.name in vars:
            return expr == vars[pat.name]
        else:
            vars[pat.name] = expr
            if pat.pattern is None:
                return True
            return pattern_match(expr, pat.pattern, vars)

    if type(expr) != type(pat):
        return False

    if not isinstance(expr, sym_func_apply):
        return expr == pat

    if len(expr.args) != len(pat.args):
        return False

    return all(pattern_match(ea, pa, vars) for (ea, pa) in zip(expr.args, pat.args))

def pattern_build(pat, vars):
    if isinstance(pat, patname):
        return vars[pat.name]
    if isinstance(pat, sym_func_apply):
        args = [pattern_build(pa, vars) for pa in pat.args]
        return type(pat)(*args)
    return pat

def simplify(e):
    matched = True
    while matched:
        matched = False
        for (src, dst) in simplify_patterns:
            vars = {}
            if not pattern_match(e, src, vars):
                continue
            e = pattern_build(dst, vars)
            matched = True

    if isinstance(e, sym_func_apply):
        t = type(e)
        args = [simplify(a) for a in e.args]
        return t(*args)

    return e

## Current path constraint

cur_path_constr = None
cur_path_constr_callers = None

def get_caller():
    frame = inspect.currentframe()
    try:
        while True:
            info = inspect.getframeinfo(frame)
            ## Skip stack frames inside the symbolic execution engine,
            ## as well as in the rewritten replacements of dict, %, etc.
            if not info.filename.endswith("fuzzy.py") and not info.filename.endswith(
                "rewriter.py"
            ):
                return (info.filename, info.lineno)
            frame = frame.f_back
    finally:
        del frame

def add_constr(e):
    global cur_path_constr, cur_path_constr_callers
    cur_path_constr.append(simplify(e))
    cur_path_constr_callers.append(get_caller())

## Creating new symbolic names

namectr = 0
def uniqname(id):
    global namectr
    namectr += 1
    return "%s_%d" % (id, namectr)

## Helper for printing Z3-indented expressions

def indent(s, spaces="  "):
    return spaces + str(s).replace("\n", "\n" + spaces)

## Support for forking because z3 uses lots of global variables

## timeout for Z3, in seconds
z3_timeout = 5

def fork_and_check_worker(constr, conn):
    s = z3.Solver()
    s.add(z3expr(constr))
    ok = s.check()
    m = {}
    if ok == z3.sat:
        z3m = s.model()
        for k in z3m:
            v = z3m[k]
            if v.sort() == z3.IntSort():
                m[str(k)] = v.as_long()
            elif v.sort() == z3.StringSort():
                ## There doesn't seem to be a way to get the raw string
                ## value out of Z3..  Instead, we get the escaped string
                ## value.  We need to jump through hoops to unescape it.
                x = v.as_string()
                u = x.encode("latin1").decode("unicode-escape")
                m[str(k)] = u
            else:
                raise Exception("Unknown sort for %s=%s: %s" % (k, v, v.sort()))
    conn.send((ok, m))
    conn.close()

def fork_and_check(constr):
    constr = simplify(constr)

    parent_conn, child_conn = multiprocessing.Pipe()
    p = multiprocessing.Process(target=fork_and_check_worker, args=(constr, child_conn))
    p.start()
    child_conn.close()

    ## timeout after a while..
    def sighandler(signo, stack):
        print("Timed out..")
        # print z3expr(constr).sexpr()
        p.terminate()

    signal.signal(signal.SIGALRM, sighandler)
    signal.alarm(z3_timeout)

    try:
        res = parent_conn.recv()
    except EOFError:
        res = (z3.unknown, None)
    finally:
        signal.alarm(0)

    p.join()
    return res

## Symbolic type replacements

def concolic_bool(sym, v):
    ## Python claims that 'bool' is not an acceptable base type,
    ## so it seems difficult to subclass bool.  Luckily, bool has
    ## only two possible values, so whenever we get a concolic
    ## bool, add its value to the constraint.
    add_constr(sym_eq(sym, ast(v)))
    return v

class concolic_int(int):
    def __new__(cls, sym, v):
        self = super(concolic_int, cls).__new__(cls, v)
        self.__v = v
        self.__sym = sym
        return self

    def __bool__(self):
        return concolic_bool(sym_not(sym_eq(ast(self), ast(0))), self.__v != 0)

    def __eq__(self, o):
        if not isinstance(o, int):
            return False

        if isinstance(o, concolic_int):
            res = self.__v == o.__v
        else:
            res = self.__v == o

        return concolic_bool(sym_eq(ast(self), ast(o)), res)

    def __ne__(self, o):
        return not self.__eq__(o)

    def __hash__(self):
        return self.__v.__hash__()

    def __cmp__(self, o):
        res = int(self.__v).__cmp__(int(o))
        if concolic_bool(sym_lt(ast(self), ast(o)), res < 0):
            return -1
        if concolic_bool(sym_gt(ast(self), ast(o)), res > 0):
            return 1
        return 0

    def __lt__(self, o):
        res = int(self.__v) < int(o)
        return concolic_bool(sym_lt(ast(self), ast(o)), res)

    def __le__(self, o):
        res = int(self.__v) <= int(o)
        return concolic_bool(sym_not(sym_gt(ast(self), ast(o))), res)

    def __gt__(self, o):
        res = int(self.__v) > int(o)
        return concolic_bool(sym_gt(ast(self), ast(o)), res)

    def __ge__(self, o):
        res = int(self.__v) >= int(o)
        return concolic_bool(sym_not(sym_lt(ast(self), ast(o))), res)

    def __add__(self, o):
        if isinstance(o, concolic_int):
            res = self.__v + o.__v
        else:
            res = self.__v + o
        return concolic_int(sym_plus(ast(self), ast(o)), res)

    def __radd__(self, o):
        res = o + self.__v
        return concolic_int(sym_plus(ast(o), ast(self)), res)

    def __sub__(self, o):
        if isinstance(o, concolic_int):
            res = self.__v - o.__v
        else:
            res = self.__v - o
        return concolic_int(sym_minus(ast(self), ast(o)), res)

    def __rsub__(self, o):
        res = o - self.__v
        return concolic_int(sym_minus(ast(o), ast(self)), res)

    ## Exercise 2: your code here.
    ## Implement symbolic division and multiplication.
    def __mul__(self, o):
        if isinstance(o, concolic_int):
            res = self.__v * o.__v
        else:
            res = self.__v * o
        return concolic_int(sym_multiply(ast(self), ast(o)), res)

    def __rmul__(self, o):
        res = o * self.__v
        return concolic_int(sym_multiply(ast(o), ast(self)), res)

    def __floordiv__(self, o):
        if isinstance(o, concolic_int):
            res = self.__v // o.__v
        else:
            res = self.__v // o
        return concolic_int(sym_division(ast(self), ast(o)), res)

    def __rfloordiv__(o, self):
        res = o // self.__v
        return concolic_int(sym_division(ast(o), ast(self)), res)

    def _sym_ast(self):
        return self.__sym

class concolic_str(str):
    def __new__(cls, sym, v):
        assert type(v) == str
        self = super(concolic_str, cls).__new__(cls, v)
        self.__v = v
        self.__sym = sym
        return self

    def __eq__(self, o):
        if not isinstance(o, str):
            return False

        if isinstance(o, concolic_str):
            res = self.__v == o.__v
        else:
            res = self.__v == o

        return concolic_bool(sym_eq(ast(self), ast(o)), res)

    def __ne__(self, o):
        return not self.__eq__(o)

    def __hash__(self):
        return self.__v.__hash__()

    def __add__(self, o):
        if isinstance(o, concolic_str):
            res = self.__v + o.__v
        else:
            res = self.__v + o
        return concolic_str(sym_concat(ast(self), ast(o)), res)

    def __radd__(self, o):
        res = o + self.__v
        return concolic_str(sym_concat(ast(o), ast(self)), res)

    def __bool__(self):
        return concolic_bool(sym_not(sym_eq(ast(self), ast(""))), self.__v != "")

    ## Exercise 7: your code here.
    ## Implement symbolic versions of string length (override __len__)
    ## and contains (override __contains__).
    def __len__(self):
        return concolic_int(sym_length(ast(self)), len(self.__v))

    def __contains__(self, o):
        if(isinstance(o, concolic_str)):
            res = (o.__v in self.__v)
        else:
            res = o in self.__v
        return concolic_bool(sym_contains(ast(self), ast(o)), res)

    def startswith(self, o):
        res = self.__v.startswith(o)
        return concolic_bool(sym_startswith(ast(self), ast(o)), res)

    def endswith(self, o):
        res = self.__v.endswith(o)
        return concolic_bool(sym_endswith(ast(self), ast(o)), res)

    def __getitem__(self, idx):
        res = self.__v[idx]
        if isinstance(idx, slice):
            if idx.step is not None:
                # Stepping not supported symbolically.
                return res

            i = idx.start
            if i is None:
                i = 0
            elif i < 0:
                i += self.__len__()

            j = idx.stop
            if j is None:
                j = self.__len__()
            elif j < 0:
                j += self.__len__()

            return concolic_str(sym_substring(ast(self), ast(i), ast(j - i)), res)
        else:
            return concolic_str(sym_substring(ast(self), ast(idx), ast(1)), res)

    def find(self, ch):
        res = self.__v.find(ch)
        return concolic_int(sym_indexof(ast(self), ast(ch)), res)

    def encode(self, encoding=sys.getdefaultencoding(), errors="strict"):
        ## As a hack, we pretend that strings and bytes are one-to-one..
        return concolic_bytes(
            self.__sym, self.__v.encode(encoding=encoding, errors=errors)
        )

    def __str__(self):
        return self

    def lstrip(self, chars=" \t\n\r"):
        for ch in chars:
            if self.startswith(chars):
                return self[1:].lstrip(chars)
        return self

    def split(self, sep=None, maxsplit=-1):
        vres = self.__v.split(sep, maxsplit)
        if type(sep) != str:
            return vres
        if maxsplit != 1:
            return vres

        if sep not in self:
            return [self]

        name = "split_%s_%s" % (self.__sym, sep)
        l = mk_str(name + "_l", vres[0])
        r = mk_str(name + "_r", vres[1])
        if (l + sep + r != self) or (sep in l):
            ## nonsensical assignment of concrete values; just return
            ## the real result to keep executing.
            return vres

        return [l, r]

    def rsplit(self, sep=None, maxsplit=-1):
        vres = self.__v.rsplit(sep, maxsplit)
        if type(sep) != str:
            return vres
        if maxsplit != 1:
            return vres

        if sep not in self:
            return [self]

        name = "rsplit_%s_%s" % (self.__sym, sep)
        l = mk_str(name + "_l", vres[0])
        r = mk_str(name + "_r", vres[1])
        if (l + sep + r != self) or (sep in r):
            ## nonsensical assignment of concrete values; just return
            ## the real result to keep executing.
            return vres

        return [l, r]

    def upper(self):
        ## XXX an incorrect overloading that gets us past werkzeug's use
        ## of .upper() on the HTTP method name..
        return self

    def _sym_ast(self):
        return self.__sym

class concolic_bytes(bytes):
    def __new__(cls, sym, v):
        assert type(v) == bytes
        self = super(concolic_bytes, cls).__new__(cls, v)
        self.__v = v
        self.__sym = sym
        return self

    def __eq__(self, o):
        if not isinstance(o, bytes):
            return False

        if isinstance(o, concolic_bytes):
            res = self.__v == o.__v
        else:
            res = self.__v == o

        return concolic_bool(sym_eq(ast(self), ast(o)), res)

    def __ne__(self, o):
        return not self.__eq__(o)

    def __hash__(self):
        return self.__v.__hash__()

    def __add__(self, o):
        if isinstance(o, concolic_bytes):
            res = self.__v + o.__v
        else:
            res = self.__v + o
        return concolic_bytes(sym_concat(ast(self), ast(o)), res)

    def __radd__(self, o):
        res = o + self.__v
        return concolic_bytes(sym_concat(ast(o), ast(self)), res)

    ## Exercise 7: your code here.
    ## Implement symbolic versions of bytes length (override __len__)
    ## and contains (override __contains__).
    def __len__(self):
        return concolic_int(sym_length(ast(self)), len(self.__v))

    def __contains__(self, o):
        if(isinstance(o, concolic_bytes)):
            res = (o.__v in self.__v)
        else:
            res = o in self.__v
        return concolic_bool(sym_contains(ast(self), ast(o)), res)

    def startswith(self, o):
        res = self.__v.startswith(o)
        return concolic_bool(sym_startswith(ast(self), ast(o)), res)

    def endswith(self, o):
        res = self.__v.endswith(o)
        return concolic_bool(sym_endswith(ast(self), ast(o)), res)

    def __getitem__(self, idx):
        res = self.__v[idx]
        if isinstance(idx, slice):
            if idx.step is not None:
                # Stepping not supported symbolically.
                return res

            i = idx.start
            if i is None:
                i = 0
            elif i < 0:
                i += self.__len__()

            j = idx.stop
            if j is None:
                j = self.__len__()
            elif j < 0:
                j += self.__len__()

            return concolic_bytes(sym_substring(ast(self), ast(i), ast(j - i)), res)
        else:
            return concolic_bytes(sym_substring(ast(self), ast(idx), ast(1)), res)

    def find(self, ch):
        res = self.__v.find(ch)
        return concolic_int(sym_indexof(ast(self), ast(ch)), res)

    def decode(self, encoding=sys.getdefaultencoding(), errors="strict"):
        ## As a hack, we pretend that strings and bytes are one-to-one..
        return concolic_str(
            self.__sym, self.__v.decode(encoding=encoding, errors=errors)
        )

    def lstrip(self, chars=b" \t\n\r"):
        for ch in chars:
            if self.startswith(chars):
                return self[1:].lstrip(chars)
        return self

    def split(self, sep=None, maxsplit=-1):
        vres = self.__v.split(sep, maxsplit)
        if type(sep) != bytes:
            return vres
        if maxsplit != 1:
            return vres

        if sep not in self:
            return [self]

        name = "splitb_%s_%s" % (self.__sym, sep)
        l = mk_bytes(name + "_l", vres[0])
        r = mk_bytes(name + "_r", vres[1])
        if (l + sep + r != self) or (sep in l):
            ## nonsensical assignment of concrete values; just return
            ## the real result to keep executing.
            return vres

        return [l, r]

    def rsplit(self, sep=None, maxsplit=-1):
        vres = self.__v.rsplit(sep, maxsplit)
        if type(sep) != bytes:
            return vres
        if maxsplit != 1:
            return vres

        if sep not in self:
            return [self]

        name = "rsplitb_%s_%s" % (self.__sym, sep)
        l = mk_bytes(name + "_l", vres[0])
        r = mk_bytes(name + "_r", vres[1])
        if (l + sep + r != self) or (sep in r):
            ## nonsensical assignment of concrete values; just return
            ## the real result to keep executing.
            return vres

        return [l, r]

    def upper(self):
        ## XXX an incorrect overloading that gets us past werkzeug's use
        ## of .upper() on the HTTP method name..
        return self

    def _sym_ast(self):
        return self.__sym

## Override some builtins..

old_len = builtins.len
def xlen(o):
    if isinstance(o, concolic_str):
        return o.__len__()
    return old_len(o)
builtins.len = xlen

## ConcreteValues

# During concolic execution, new variables will be added to
# current_concrete_values, which is an instance of ConcreteValues.
# This variable is global because application code, the concolic
# Execution engine, and test code, all create new variables.  We make
# it global so that we don't have to modify application code.  At the
# start of a concolic execution we will set this variable to the
# concrete values to be used.

current_concrete_values = None

# ConcreteValues maintains a dictionary of variables name to values.
# If a variable is created and it doesn't exist, we use a default
# value for the variable (0 for int and '' for string).
class ConcreteValues(object):
    def __init__(self):
        self.concrete_values = {}

    def __str__(self):
        return str(self.concrete_values)

    def canonical_rep(self):
        return sorted(self.concrete_values.items())

    def add(self, id, v):
        self.concrete_values[id] = v

    def var_names(self):
        return self.concrete_values.keys()

    def mk_int(self, id, initval):
        if id not in self.concrete_values:
            self.concrete_values[id] = initval
        return concolic_int(sym_int(id), self.concrete_values[id])

    def mk_str(self, id, initval):
        if id not in self.concrete_values:
            self.concrete_values[id] = initval
        return concolic_str(sym_str(id), self.concrete_values[id])

    def mk_bytes(self, id, initval):
        if id not in self.concrete_values:
            self.concrete_values[id] = initval
        return concolic_bytes(sym_str(id), self.concrete_values[id])

    def mk_global(self):
        global current_concrete_values
        current_concrete_values = self

    def inherit(self, o):
        for id in o.concrete_values:
            if id not in self.concrete_values:
                self.concrete_values[id] = o.concrete_values[id]

# Wrapper functions to allow application code to create new
# variables. They will be added to the current global current
# concrete values.
def mk_int(id, initval):
    global current_concrete_values
    return current_concrete_values.mk_int(id, initval)


def mk_str(id, initval):
    global current_concrete_values
    return current_concrete_values.mk_str(id, initval)


def mk_bytes(id, initval):
    global current_concrete_values
    return current_concrete_values.mk_bytes(id, initval)

## Track ConcreteValues that should be tried later

@dataclass(order=True)
class PrioritizedConcreteValues:
    priority: int
    item: ConcreteValues = field(compare=False)

class InputQueue(object):
    def __init__(self):
        ## Each ConcreteValues has a priority (lower is "more important"),
        ## which is useful when there's too many inputs to process.  We
        ## start with an empty ConcreteValues.
        self.inputs = queue.PriorityQueue()
        self.inputs.put(PrioritizedConcreteValues(0, ConcreteValues()))

        ## "branchcount" is a map from call site (filename and line number)
        ## to the number of branches we have already explored at that site.
        ## This is used to choose priorities for inputs.
        self.branchcount = collections.defaultdict(int)

    def empty(self):
        return self.inputs.empty()

    def get(self):
        priovalue = self.inputs.get()
        return priovalue.item

    def add(self, new_values, caller):
        prio = self.branchcount[caller]
        self.branchcount[caller] += 1
        self.inputs.put(PrioritizedConcreteValues(prio, new_values))

# Concolically execute testfunc with the given concrete_values. It
# returns the value testfunc computes for the given concrete_values
# and the branches it encountered to compute that result.
def concolic_exec_input(testfunc, concrete_values, verbose=0):
    global cur_path_constr, cur_path_constr_callers
    cur_path_constr = []
    cur_path_constr_callers = []

    if verbose > 0:
        print("Trying concrete value:", concrete_values)

    # make the concrete_value global so that new variables created
    # by testfunc(), directly or indirectly, will be added to
    # concrete_values.
    concrete_values.mk_global()
    v = testfunc()

    if verbose > 1:
        print("Test generated", len(cur_path_constr), "branches:")
        for (c, caller) in zip(cur_path_constr, cur_path_constr_callers):
            print(indent(z3expr(c)), "@", "%s:%d" % (caller[0], caller[1]))

    return (v, cur_path_constr, cur_path_constr_callers)

# Compute a new constraint by negating the branch condition of the
# b-th branch in branch_conds. This constraint can be used to force
# the concolic execution to explore the other side of branch b.
def concolic_force_branch(b, branch_conds, branch_callers, verbose=1):
    ## Compute an AST expression for the constraints necessary
    ## to go the other way on branch b.  You can use existing
    ## logical AST combinators like sym_not(), sym_and(), etc.
    ##
    ## Note that some of the AST combinators take separate positional
    ## arguments. In Python, to unpack a list into separate positional
    ## arguments, use the '*' operator documented at
    ## https://docs.python.org/3/tutorial/controlflow.html#unpacking-argument-lists

    constraint = None

    for i in range(0, b):
        if constraint == None:
            constraint = branch_conds[i]
        else:
            constraint = sym_and(constraint, branch_conds[i])
    if constraint == None:
        constraint = sym_not(branch_conds[b])
    else:
        constraint = sym_and(constraint, sym_not(branch_conds[b]))

    if verbose > 2:
        callers = branch_callers[b]
        print("Trying to branch at %s:%d:" % (callers[0], callers[1]))
        if constraint is not None:
            print(indent(z3expr(constraint).sexpr()))

    if constraint is None:
        return const_bool(True)
    else:
        return constraint

# Given a constraint, ask Z3 to compute concrete values that make that
# constraint true. It returns a new ConcreteValues instance with those
# values.  Z3 produces variables that don't show up in our
# applications and in our constraints; we filter those by accepting
# only variables names that appear in ok_names.
def concolic_find_input(constraint, ok_names, verbose=0):
    ## Invoke Z3, along the lines of:
    ##
    ##     (ok, model) = fork_and_check(constr)
    ##
    ## If Z3 was able to find example inputs that solve this
    ## constraint (i.e., ok == z3.sat), make a new input set
    ## containing the values from Z3's model, and return it.
    (ok, model) = fork_and_check(constraint)
    if ok == z3.sat:
        v = ConcreteValues()
        for name, val in model.items():
            if name in ok_names:
                v.add(name, val)
        return True, v
    return False, ConcreteValues()

# Concolic execute func for many different paths and return all
# computed results for those different paths.
def concolic_execs(func, maxiter=100, verbose=0):
    ## "checked" is the set of constraints we already sent to Z3 for
    ## checking.  use this to eliminate duplicate paths.
    checked = set()

    ## output values
    outs = []

    ## list of inputs we should try to explore.
    inputs = InputQueue()
    
    iter = 0
    while iter < maxiter and not inputs.empty():
        iter += 1
        concrete_values = inputs.get()
        (r, branch_conds, branch_callers) = concolic_exec_input(
            func, concrete_values, verbose
        )
        if r not in outs:
            outs.append(r)

        ## Exercise 6: your code here.
        ##
        ## Here's a possible plan of attack:
        ##
        ## - Iterate over the set of branches returned by concolic_exec_input.
        ##
        ## - Use concolic_force_branch() to construct a constraint over
        ##   the inputs for taking the other side of that branch.
        ##
        ## - If this constraint is already in the "checked" set, skip
        ##   it (otherwise, add it to prevent further duplicates).
        ##
        ## - Use concolic_find_input() to construct a new input to test,
        ##   based on the above constraint.
        ##
        ## - Since Z3 might not assign values to every variable
        ##   (such as if that variable turns out to be irrelevant to
        ##   the overall constraint), inherit unassigned values from
        ##   the input that we just tried (i.e., concrete_values).
        ##   You can use the inherit() method in ConcreteValues for this.
        ##
        ## - Add the input to the queue for processing, along the lines of:
        ##
        ##     inputs.add(new_values, caller)
        ##
        ##   where caller is the corresponding value from the list of call
        ##   sites returned by concolic_find_input (i.e., branch_callers).

        for i in range(0, len(branch_conds)):
            constr = concolic_force_branch(i, branch_conds, branch_callers)
            if(constr in checked):
                continue
            checked.add(constr)
            (ok, v) = concolic_find_input(constr, concrete_values.var_names())
            if(ok == False):
                continue
            v.inherit(concrete_values)
            inputs.add(v, branch_callers[i])

    if verbose > 0:
        print("Stopping after", iter, "iterations")

    return outs
