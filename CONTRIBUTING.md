# Contributing to 𐌅𐌋𐌀𐌔𐌊-ᕓꝊ𐌵𐌂𐋅

Thanks for your interest in contributing! Every contribution matters — whether it's a bug report, feature idea, docs fix, or code change.

## Ways to contribute

- **Report bugs** — [open an issue](https://github.com/tn3w/flask-Vouch/issues/new) with steps to reproduce
- **Suggest features** — [start a discussion](https://github.com/tn3w/flask-Vouch/issues/new) describing the use case
- **Fix bugs** — browse [open issues](https://github.com/tn3w/flask-Vouch/issues) and submit a PR
- **Improve docs** — typos, examples, clarifications — all welcome
- **Add integrations** — new framework support or challenge types

## Getting started

```bash
git clone https://github.com/tn3w/flask-Vouch.git
cd flask-Vouch
pytest tests/ -v
```

## Submitting a pull request

1. Fork the repo and create a branch from `main`
2. Write or update tests for your changes
3. Run the test suite: `pytest tests/ -v`
4. Format your code: `isort . && black .`
5. Keep commits focused — one logical change per PR
6. Open the PR with a clear description of what and why

## Code style

- Follow existing patterns in the codebase
- Max 90 characters per line
- No comments unless absolutely necessary — write self-documenting code
- Use early returns and keep nesting below 4 levels
- Format with `black` and `isort`

## Reporting security issues

Please do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## First-time contributors

Look for issues labeled [`good first issue`](https://github.com/tn3w/flask-Vouch/labels/good%20first%20issue) — these are scoped, well-defined tasks ideal for getting familiar with the codebase.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
