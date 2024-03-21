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
