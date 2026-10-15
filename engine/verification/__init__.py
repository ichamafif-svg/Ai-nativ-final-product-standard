"""Pinned programs (D37): every measure that opens a right, as code pinned by digest in the floors and replayable.

The trusted host (fabric/control/bt/host.py) runs these programs in the isolated runner on inputs it materialises by digest
(exact commits of its own repository, pinned data, stored blobs, recorded evidence) and signs what they return with
the method `programs@<digest of this package>`. Anyone holding the same inputs can run them again and compare: a
fact is a pure function of recorded inputs, not the word of a process. Adding a measure adds a program here, never a
line to fabric/control/bt/. A program reads and computes; it holds no key, sends no effect, and writes nothing but its answer.
"""
