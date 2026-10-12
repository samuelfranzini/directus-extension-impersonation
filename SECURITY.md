# Security Policy

This extension mints access tokens that act as other users, so security reports are taken seriously and handled first.

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability.**

Report it privately to the maintainer, through GitHub's private vulnerability reporting (Security tab → *Report a vulnerability*) when it is enabled for the repository, or directly otherwise.

Please include:

- the affected version and Directus version;
- a description of the issue and its impact;
- steps or a proof of concept to reproduce it;
- any suggested fix, if you have one.

## Scope

In scope: the code of this extension (`src/`) and its release pipeline (`.github/workflows/`).

Out of scope: vulnerabilities in Directus itself (report them to [Directus](https://github.com/directus/directus/security)), in third-party dependencies (report them upstream; the dependency will be updated once a fix is published), and issues requiring a compromised server or administrator account.
