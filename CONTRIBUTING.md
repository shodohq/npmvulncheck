# Contributing to npmvulncheck

Thanks for your interest in improving `npmvulncheck`.
This guide explains how to report issues, propose changes, and submit pull requests.

## Before you start

- Search existing issues before opening a new one.
- For support questions, include full command, options, and output.
- Keep PRs focused on one logical change.

## Development setup

Requirements:

- Node.js `>=18`

Install and run checks:

```bash
npm install
npm run lint
npm test
npm run build
```

Local CLI run:

```bash
npm run dev -- --help
```

## Reporting bugs

Use the bug report issue template and include:

- Clear reproduction steps
- Expected vs actual behavior
- Node.js version, OS, and lockfile type (`npm`/`pnpm`/`yarn`)
- Minimal reproduction repository when possible

## Proposing enhancements

Use the feature request template and explain:

- The user problem and current workaround
- Why the change should be in core
- Expected CLI/API behavior

## Pull requests

Before opening a PR:

- Add or update tests for behavior changes
- Keep docs/help text in sync with behavior
- Run `npm run lint && npm test && npm run build`
- Link related issues (`Fixes #123`)

PR review checklist:

- Backward compatibility impact described
- Edge cases covered by tests
- Error messages and exit codes remain predictable

## Release notes labels

Maintainers use labels to group release notes.
When relevant, add one of these labels to your PR:

- `breaking`
- `enhancement`
- `bug`
- `documentation`
- `maintenance`

## Security issues

Do not open public issues for undisclosed vulnerabilities.
See `SECURITY.md` for private reporting instructions.
