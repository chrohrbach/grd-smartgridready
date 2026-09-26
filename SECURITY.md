# Security

## Reporting a vulnerability

Please report a vulnerability privately, through GitHub's private
vulnerability reporting ("Report a vulnerability" in the repository's
Security tab), and not in a public issue. Please allow time for a fix before
any public disclosure.

## Scope

With `--allow-write`, the bench commands a real building. In scope, among
others:

- a command the bench sends although it should not, or fails to release;
- a credential that reaches the console, a report or a log;
- a verdict that can be wrong: a `PASS` given to an EMS that does not conform,
  or a `FAIL` given to one that does.
