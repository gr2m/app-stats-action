# GitHub App Statistics Action

> GitHub Action to retrieve statistics for a GitHub App

[![Build Status](https://github.com/gr2m/app-stats-action/workflows/Test/badge.svg)](https://github.com/gr2m/app-stats-action/actions)

## Usage

```yml
name: App Stats
on:
  push:
    branches:
      - master

jobs:
  log:
    runs-on: ubuntu-latest
    steps:
      - uses: gr2m/app-stats-action@v1.x
        id: stats
        with:
          id: ${{ secrets.APP_ID }}
          private_key: ${{ secrets.PRIVATE_KEY }}
      - run: "echo installations: '${{ steps.stats.outputs.installations }}'"
      - run: "echo repositories: '${{ steps.stats.outputs.repositories }}'"
      - run: "echo suspended: '${{ steps.stats.outputs.suspended_installations }}'"
      - run: "echo most popular repositories: '${{ steps.stats.outputs.popular_repositories }}'"
```

## Debugging

To see additional debug logs, create a secret with the name: `ACTIONS_STEP_DEBUG` and value `true`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## License

[ISC](LICENSE)
