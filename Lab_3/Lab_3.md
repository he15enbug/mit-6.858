# Lab 3: Symbolic Execution
- A powerful technique for finding bugs in software: *Symbolic Execution*. It can be used to audit our application for security vulnerabilities
- In this lab, we will develope a symbolic execution system that can take the Zoobar web application and mechanicaly find inputs that trigger different kinds of bugs that can lead to security vulnerabilities
- More precisely, this lab will be building a *Concolic Execution System*
- The [EXE paper](https://css.csail.mit.edu/6.858/2022/readings/exe.pdf) describes a symbolic execution system for C programs. For simplicity, this lab will focus on building a symbolic/concolic execution system for Python programs, by modifying Python objects and overloading specific methods. Much like EXE, we will be using SMT solver to check for satisfiable constraints and come up with example inputs to the program we are testing
- [SMT, Satisfiability Modulo Theories](https://en.wikipedia.org/wiki/Satisfiability_Modulo_Theories) means the solver is able to check constraints that involve both traditional boolean satisfiability expressions as well as constraints that refer to other "theories" like integers, bit vectors, strings, and so on
- In this lab:
    1. We will first familiarize ourselves with the use of Z3, a popular SMT solver, by using it to find a correct way to compute the unsigned (and signed) average of two 32-bit values
    2. We will then create a wrapper for integer operations in Python (much like EXE provides replacements for operations on symbolic values), and implement the core logic of invoking Z3 to explore different possible execution paths
    3. Finally, we will explore how to apply this approach to web applications, which tend to handle strings rather than integer values. We will wrap operations on Python strings, implement symbolic-friendly wrappers around the SQLalchemy database interface, and use the resulting system to find security vulnerabilities in Zoobar

## Getting started
- run `git pull` to fetch the code, and check out the `lab3` branch
    ```
    $ git pull
    ...
    $ git checkout -b lab3 origin/lab3
    ...
    ```
- ensure that the lab 3 source code is running correctly in our VM
    ```
    $ make check
    ./check_lab3.py
    FAIL Exercise 1: unsigned average
    FAIL Challenge 1: signed average
    FAIL Exercise 2: concolic multiply
    FAIL Exercise 2: concolic divide
    FAIL Exercise 2: concolic divide+multiply+add
    FAIL Exercise 3: concrete input for 1234
    FAIL Exercise 4: concolic_find_input constr2
    PASS Exercise 4: concolic_find_input constr3
    FAIL Exercise 5: concolic_force_branch
    FAIL Exercise 6: concolic execution for integers
    FAIL Exercise 7: concolic length
    FAIL Exercise 7: concolic contains
    FAIL Exercise 7: concolic execution for strings
    FAIL Exercise 8: concolic database lookup (str)
    FAIL Exercise 8: concolic database lookup (int)
    FAIL Exercise 9: eval injection not found
    FAIL Exercise 9: balance mismatch not found
    FAIL Exercise 9: zoobar theft not found
    PASS Exercise 10: eval injection not found
    PASS Exercise 10: balance mismatch not found
    PASS Exercise 10: zoobar theft not found
    ```

## Using an SMT solver
- A key piece of machinery used by symbolic execution is an SMT solver. For this lab, we will use the [Z3 solver](https://github.com/Z3Prover/z3). We will invoke Z3 using its Python-based API. And this lab will make use of 
- [Z3Py tutorial](https://ericpony.github.io/z3py-tutorial/guide-examples.htm)
- [Documentation for Z3's Python API](https://z3prover.github.io/api/html/namespacez3py.html)
- As a first step, we will use it to help us implement a seemingly simple but error-prone piece of code: *computing the average of two 32-bit integers*. One naive way to compute the average of `x` and `y` is to use `(x+y)/2`. However, if both `x` and `y` are large, their sum might overflow and wrap around modulo `2^32`. Integer overflow errors are a significant source of security problems for systems code (refer to [KINT paper](https://people.csail.mit.edu/nickolai/papers/wang-kint-2013-06-24.pdf))
- Z3 can help us to get a correct implementation of the average function by checking whether a particular implementation we have in mind is correct. In particular, given a boolean expression, Z3 can tell us whether it's possible to make that boolean expression true (i.e., satisfy it). Moreover, if it's possible to make the expression true, and the expression contains some variables, Z3 will give us an example assignment of values to these variables which makes it true
- See the provided `int-avg.py`. In Z3, the default Python operators for division `/` and righ-shifting `>>` treat bit vectors as signed values, to perform unsigned operations, we should use `z3.UDiv` and `z3.LShR`
    ```
    import z3
    # construct two 32-bit variables called a and b
    a = z3.BitVec('a', 32)
    b = z3.BitVec('b', 32)
    # compute the unsigned average of a and b (treating them as unsigned integers)
    # note that this code does NOT actually perform the addition and division
    # it constructs a symbolic expression representing these operations
    # and Z3 will reason about the possible values of this expression later on
    u_avg = z3.UDiv(a + b, 2)
    # compute the signed average of a and b
    s_avg = (a + b) / 2
    
    print(u_avg)
    print(s_avg)
    ```
- Then we compute a reference value representing the expected, correct average of `a` and `b`. To compute this reference, we cheat by turning both `a` and `b` into 33-bit integers using `z3.ZeroExt`. This will allow us to get the correct anwser using the naive way
    ```
    az33 = z3.ZeroExt(1, a)
    bz33 = z3.ZeroExt(1, b)
    real_u_avg = z3.Extract(31, 0, z3.UDiv(az33 + bz33, 2))

    as33 = z3.SignExt(1, a)
    bs33 = z3.SignExt(1, b)
    real_s_avg = z3.Extract(31, 0, (as33 + bs33) / 2)
    ```
- To check whether `u_avg` computed the average correctly, we just ask Z3 whether it is possible to satisfy the expression `u_avg != real_u_avg`, it there is a counter-example, `u_avg` is not correct
    ```
    def printable_val(v, signed):
        if type(v) == z3.BitVecNumRef:
            if signed:
                v = v.as_signed_long()
            else:
                v = v.as_long()
        return v

    def printable_model(m, signed):
        vals = {}
        for k in m:
            vals[k] = printable_val(m[k], signed)
        return vals

    def do_check(msg, signed, avg, real_avg):
        e = (avg != real_avg)
        print("Checking", msg, "using Z3 expression:")
        print("    " + str(e).replace("\n", "\n    "))
        solver = z3.Solver()
        solver.add(e)
        ok = solver.check()
        print("  Answer for %s: %s" % (msg, ok))

        if ok == z3.sat:
            m = solver.model()
            print("  Example:", printable_model(m, signed))
            print("  Your average:", printable_val(m.eval(avg), signed))
            print("  Real average:", printable_val(m.eval(real_avg), signed))

    do_check("unsigned avg", False, u_avg, real_u_avg)
    do_check("signed avg", True, s_avg, real_s_avg)
    ```
- This is the result
    ```
    $ ./int-avg.py 
    Checking unsigned avg using Z3 expression:
        UDiv(a + b, 2) !=
        Extract(31, 0, UDiv(ZeroExt(1, a) + ZeroExt(1, b), 2))
      Answer for unsigned avg: sat
      Example: {b: 4292870143, a: 4294967287}
      Your average: 2146435067
      Real average: 4293918715
    Checking signed avg using Z3 expression:
        (a + b)/2 !=
        Extract(31, 0, (SignExt(1, a) + SignExt(1, b))/2)
      Answer for signed avg: sat
      Example: {b: -2147483648, a: -2147483648}
      Your average: 0
      Real average: -2147483648
    ```
- *Exercise 1*: implement a correct function to compute the unsigned average of `a` and `b` using only 32-bit arithmetic by modifying the line `u_avg=` in `int-avg.py`
    - For `a` > `b`, we can compute `((a-b)/2)+b`
    - For `a` < `b`, we can compute `((b-a)/2)+a`
    - Code: `u_avg = z3.If(z3.UGT(a, b), z3.UDiv(a - b, 2) + b, z3.UDiv(b - a, 2) + a)`
    - It is important to use `z3.UGT(a, b)` instead of `a > b`, because `a > b` will treat `a` and `b` as signed values
    - result:
        ```
        Checking unsigned avg using Z3 expression:
            If(UGT(a, b), b, a) + UDiv(If(UGT(a, b), a - b, b - a), 2) !=
            Extract(31, 0, UDiv(ZeroExt(1, a) + ZeroExt(1, b), 2))
          Answer for unsigned avg: unsat
        ```
- *Challenge*: use the correct way to compute the signed average value
    1. `a>=0 and b<=0`, or `a<=0 and b>=0`, `(a+b)/2` will not cause overflow
    2. for other cases, `(a-b)/2+b` will not cause overflow
    - we need to mind the rounding rule
    ```
    condition = z3.Or(z3.And(a <= 0, b >= 0), z3.And(a >= 0, b <= 0))
    pos_ab = z3.And(condition == False, a > 0)

    p_add_op = z3.If(a >= b,     b,     a)
    p_div_op = z3.If(a >= b, a - b, b - a)
    n_add_op = z3.If(a <  b,     b,     a)
    n_div_op = z3.If(a <  b, a - b, b - a)

    p_res = (p_div_op / 2) + p_add_op
    n_res = (n_div_op / 2) + n_add_op

    temp = z3.If(pos_ab, p_res, n_res)
    s_avg = z3.If(condition, (a + b) / 2, temp)
    ```
    - result
        ```
        $ ./int-avg.py 
        Checking unsigned avg using Z3 expression:
            If(UGT(a, b), UDiv(a - b, 2) + b, UDiv(b - a, 2) + a) !=
            Extract(31, 0, UDiv(ZeroExt(1, a) + ZeroExt(1, b), 2))
          Answer for unsigned avg: unsat
        Checking signed avg using Z3 expression:
            If(Or(And(a <= 0, b >= 0), And(a >= 0, b <= 0)),
            (a + b)/2,
            If(And(Or(And(a <= 0, b >= 0), And(a >= 0, b <= 0)) ==
                    False,
                    a > 0),
                If(a >= b, a - b, b - a)/2 + If(a >= b, b, a),
                If(a < b, a - b, b - a)/2 + If(a < b, b, a))) !=
            Extract(31, 0, (SignExt(1, a) + SignExt(1, b))/2)
          Answer for signed avg: unsat
        ```
## Interlude: what are symbolic and concolic execution?
- *Symbolic execution* is an approach for testing a program by observing how the program behaves on different possible inputs. Typically, the goal of symbolic execution is to achieve high *code coverage* or *path coverage* on the program. At a high level, to build a symbolic execution system, we have to address several points:
    1. remember the relation between the input and these intermediate values constructed based on the input. Typically, this is done by allowing variables or memory locations to have either *concrete* or *symbolic* values
    2. determine what control flow decisions (branches) the application makes based on the input. This boils down to constructing a symbolic constriant every time the program branches, describing the boolean condition (in terms of the program's orginal input) under which the program takes some particular branch  (or does not)
    3. for each of the above branches, we need to decide if there's a possible input that will cause the program to execute the other way at a branch. More generally, we often think of entire control flow paths, rather than individual branches in isolation. This helps us to find control flow decisions that we can affect by tweaking the input. All symbolic execution systems rely on some kind of SMT solver to do this
    4. specify what we are looking for in our testing. Typically this is best thought of in terms of some invariant that we care about ensuring in our program. One thing we could look for is crashes (i.e., the invariant is that our program should never crash). Looking for crashes makes a lot of sense in the context of C program, where crashes often indicate memory corruption which is almost certainly a bug and often could be exploit. In higher-level languages like Python, memory corruption bugs are not a problem by design, but we could still look for other kinds of issues, such as Python-level code injection attacks (some part of the input gets passed into `eval()`, for example), or application-specific invariants that matter for security
    5. finally, given all of the control flow paths that are possible to execute, we need to decide which path to actually try. This is important because there can be exponentially many different paths as the size of the program gets larger, and it quickly becomes infeasible to try all of them. Thus, symbolic execution system typically include some kind of *scheduler* or *search strategy* that decides which path is the most promising in terms of finding violations of our invariant. A simple example of a search strategy is trying branches that we haven't tried before, in hopes that it will execute new code that we haven't run yet; this will lead to higher code coverage, and perhaps this new code contains a bug we haven't run into yet

- An alternative to symbolic execution is [fuzzing](https://en.wikipedia.org/wiki/Fuzz_testing). Fuzzing takes a randomized approach: instead of trying to carefully reason about what inputs will trigger different code paths, fuzzing involves constructing concrete random inputs to the program and checking how the program behaves. This has the advantage of being relatively easy, but on the other hand, it can be difficult to construct precise inputs that hit some specific corner case in the code
- One challenge in building a symbolic execution system, such as EXE, is that the system has to know how to execute all possible operations on symbolic values (step 1 and 2 above). In this lab, we are going to interpose at the level of Python objects (in particular, integers and strings). This is challenging for symbolic execution because there are a very large number of operations that one can do on these Python objects, so building a complete symbolic execution system for such a high-level interface would be a tedious process
- There is an easier option, called *Concolic Execution*, which we can think of as somewhere in the middle between completely random fuzzing and full symbolic execution. The idea is that, instead of keeping track of purely symbolic values (as in EXE), we can store both a concrete and a symbolic value for variables that are derived from the input (The name *concolic* is a portmanteau of *concrete* and *symbolic*). Now that we have both a concrete and a symbolic value, we can almost get the best of both worlds
    - For operations that our concolic system knows about, we will run pretty much like symbolic execution (except that we will also propagate the concret part of every value)
    - For other operations, the application will just get the concrete value. For example, if the application writes the variable to a file, or perhaps passes it to some external library that we don't instrument, the code can still execute using the concrete value
- The benefit of concolic execution, for the purpose of this lab, is that we don't need to be complete in terms of supporting operations on symbolic values. As long as we support enough operations to find interesting bugs that we care about in the application, the system will be good enough (and in practice, most bug finding systems are approximate anyway, since it's usually infeasible to find all bugs). The trade-off is of course that, if the application performs some operations we do not support, we will lose track of the symbolic part, and will not be  able to do symbolic-execution-style exploration of those paths. For more about concolic execution, refer to the [DART paper](https://css.csail.mit.edu/6.858/2022/readings/dart.pdf)
## Concolic execution for integers
- To start with, we will implement a concolic execution system for integer values. The skeleton code provided is in `symex/fuzzy.py`. There are several important layers of abstraction that are implemented in `fuzzy.py`
    - **The AST**: instead of using Z3 expression to represent symbolic values, we build our own abstract syntax tree (AST) to represent symbolic expressions. An AST node could be a simple variable (represented by a `sym_str` or `sym_int` object), a const value (represented by a `const_int`, `const_str`, or `const_bool` object), or some function or operator that takes other AST nodes as arguments
        - Every AST node `n` can be converted into a Z3 expression by calling `z3expr(n)`. This works by calling `n.z3expre()`, and every AST node implements the `_z3expr` method that returns the corresponding Z3 representation
        - The reason for introducing our own AST layer, is that we need to perform manipulations on the AST that are difficult to do with Z3's representation. Furthermore, we need to fork off a separate process to invoke Z3's solver, so that in case the Z3 solver takes a really long time, we can time out, kill that process, and assume the constraint is just unsolvable. (In this case, we might miss those paths, but at least we will make progress exploring other paths). Having our own AST allows us to cleanly isolate Z3 state to just the forked process
    - **The concolic wrappers**: to intercept Python-level operations and perform concolic execution, we replace regular Python `int` and `str` objects with concolic subclasses: `concolic_int` inherits from `int`, and `concolic_str` inherits from `str`. Each of these concolic wrappers stores a concrete value (in `self.v`) and a symbolic expression (an AST node, in `self.__sym`). When the application computes some expression derived from a concolic value (e.g., `a+1` where `a` is a `concolic_int`), we need to intercept the operation and return another concolic value containing both the concrete result value and a symbolic expression for how the result was computed
        - To perform this interception, we overload various methods on the `concolic_int` and `concolic_str` classes
        - In principle, we should have a `concolic_bool` that is a subclass of `bool` as well. Unfortunately, `bool` cannot be subclassed in Python. So, we make `concolic_bool` a function that logically pretends that, once you construct a concolic boolean value, the program immediately branches on its value, so `concolic_bool` also adds a constraint to the current path condition. (The constraint is that the symbolic expression of the boolean value is equal to the concrete value). The `concolic_bool` function then returns a concrete boolean value
    - **The concrete inputs**: the inputs to the program being tested under concolic execution are stored in the `concrete_values` dictionary. This dictionary given program inputs string names, and maps each name to the value for that input
        - The reason `concrete_values` is a global variable is that applications create concolic values by invoking `fuzzy.mk_str(name)` or `fuzzy.mk_int(name)` to construct a concolic string or integer, respectively. This returns a new concolic value, whose symbolic part is a fresh AST node corresponding to a variable named `name`, but whose concrete value is looked up in the `concret_values` dictionary. If there is no specific value assigned to that variable in `concrete_values`, the system default to some intial value (`0` for integers and the empty string for strings)
    - **The SMT solver**: the `fork_and_check(c)` function checks whether constraint `c` (an AST) is a satisfiable expression, and returns a pair of values: the satisfiability status `ok`, and the example model (assignment of values to variables) if the constraint is satisfiable. The `ok` variable is from `{z3.sat, z3.unsat, z3.unknown}`. Internally, this function forks off a separate process, tries to run the Z3 solver, but if it takes longer than a few seconds (controlled by `z3_timeout`), it kills the process and returns `z3.unknown`
    - **The current path condition**: when the application executes and makes control flow decisions based on the value of a concolic value, the constraint representing that branch is appended to the `cur_path_constr` list. In order to generate inputs that make a different decision at a point along the path, the required constraint is the union of the constraints before that point in the path, plus the negation of the constraint at that point. To help with debugging and search heuristics, information about the line of code that triggered each branch is added to the `cur_path_constr_callers` list
- *Exercise 2*: Finish the implementation of `concolic_int` by adding support for integer multiply and divide operations. We will need to overload additional methods in the `concolic_int` class, add AST nodes for multiply and divide operations, and implement `_z3expr` appropriately for those AST nodes
    - Run `./check-concolic-int.py` or `make check` to check that our changes to `concolic_int` work correctly
        ```
        $ ./check-concolic-int.py 
        Multiply works
        Divide works
        Divide+multiply+add works
        ```
    - Code
        ```
        # AST nodes for multiplication and division
        class sym_division(sym_binop):
            def _z3expr(self):
                return z3expr(self.a) / z3expr(self.b)
        class sym_multiply(sym_binop):
            def _z3expr(self):
                return z3expr(self.a) * z3expr(self.b)
        ```
        ```
        # overload __mul__, __rmul__, __floordiv__, and __rfloordiv__
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
        ```
- *Exercise 3*: an important component of concolic execution is `concolic_exec_input()` in `fuzzy.py`. The implementation is given, we will use it to build a complete concolic execution system. To understand how to use `concolic_exec_input()`, we should create an input such that we pass the first check in `symex/check-symex-int.py`
    - The first test's code is as follows, we need to provide an input such that `test_f()` returns `1234`, the input should be `'i': 861`
        ```
        def f(x):
            if x == 7:
                return 100
            if x*2 == x+1:
                return 70
            if x > 2000:
                return 80
            if x*2 == 1000:
                return 30000
            if x < 500:
                return 33
            if x // 123 == 7:
                return 1234
            return 40

        def test_f():
            i = fuzzy.mk_int('i', 0)
            v = f(i)
            return v
        v = symex_exercises.make_a_test_case()
        (r, constr, callers) = fuzzy.concolic_exec_input(test_f, v, verbose=1)
        if r == 1234:
            print("Found input for 1234")
        else:
            print("Input produced", r, "instead of 1234")
        ```
    - Modify `symex-exercises.py`
        ```
        def make_a_test_case():
            concrete_values = fuzzy.ConcreteValues()
            ## Your solution here: add the right value to concrete_values
            concrete_values.add('i', 861)
            return concrete_values
        ```
    - Run `./check-symex-int.py` or `make check` to check our solution. We only care about the first check in `check-symex-int.py`
        ```
        $ ./check-symex-int.py 
        Calling f with a specific input..
        Trying concrete value: {'i': 861}
        Found input for 1234
        ...
        ```
- *Exercise 4*: another major component in concolic execution is finding a concrete input for a constraint. Complete the implementation of `concolic_find_input` in `fuzzy.py`, and make sure we pass the second test case of `check-symex-int.py`
    - Modify `fuzzy.py`
        ```
        def concolic_find_input(constraint, ok_names, verbose=0):
            (ok, model) = fork_and_check(constraint)
            if(ok == z3.sat):
                v = ConcreteValues()
                for name, val in model.items():
                    if(name in ok_names):
                        v.add(name, val)
                return True, v
            return False, ConcreteValues()
        ```
    - Test
        ```
        $ make check
        ...
        PASS Exercise 4: concolic_find_input constr2
        PASS Exercise 4: concolic_find_input constr3
        ...
        ```
- *Exercise 5*: A final major component in concolic execution is exploring different branches of execution. Complete the implementation of `concolic_force_branch` in `fuzzy.py`, and pass the final test case of `check-symex-int.py`
    ```
    def concolic_force_branch(b, branch_conds, branch_callers, verbose = 1):
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
            if(constraint == None):
            constraint = branch_conds[i]
            else:
            constraint = sym_and(constraint, branch_conds[i])
        if(constraint == None):
            constraint = sym_not(branch_conds[b])
        else:
            constraint = sym_and(constraint, sym_not(branch_conds[b]))

        if verbose > 2:
            callers = branch_callers[b]
            print('Trying to branch at %s:%d:' % (callers[0], callers[1]))
            if constraint is not None:
            print(indent(z3expr(constraint).sexpr()))

        if constraint is None:
            return const_bool(True)
        else:
            return constraint
    ```
    - Test
        ```
        $ make check
        ...
        PASS Exercise 5: concolic_force_branch
        ...
        ```
- *Exercise 6*: implement concolic execution of a function in `concolic_execs()` in `fuzzy.py`. The goal is to eventually cause every branch of `func` to be executed
    ```
    def concolic_execs(func, maxiter=100, verbose=0):

        checked = set()
        outs = []
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
    ```
    - Test:
        ```
        $ ./check-symex-int.py 
        ...
        Testing f..
        Trying concrete value: {}
        Trying concrete value: {'i': 7}
        Trying concrete value: {'i': 2001}
        Trying concrete value: {'i': 1300}
        Trying concrete value: {'i': 1}
        Trying concrete value: {'i': 861}
        Trying concrete value: {'i': 500}
        Trying concrete value: {'i': 8}
        Trying concrete value: {'i': 615}
        Trying concrete value: {'i': 0}
        Trying concrete value: {'i': 0}
        Trying concrete value: {'i': 0}
        Trying concrete value: {'i': 2}
        Stopping after 13 iterations
        Found all cases for f
        ```
## Concolic execution for strings and Zoobar
