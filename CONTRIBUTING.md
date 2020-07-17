# How to contribute

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md).
By participating in this project you agree to abide by its terms.

## Run action locally

The action requires two environment variables to be set

1. `INPUT_ID`
2. `INPUT_PRIVATE_KEY`

Replace linebreaks with `\n` in your test Apps private key, then set both `INPUT_ID` and `INPUT_PRIVATE_KEY` right when you run `node index.js`

```
INPUT_ID=123 INPUT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nMII...PZaqrmA==\n-----END RSA PRIVATE KEY-----\n" node index.js
```
