# CI gate example - run your test suite inside a cell

```bash
cellrun run -- npm test
```

The cell starts empty, so copy the project in first:

```bash
cellrun run --copy . -- npm test
```

Network is off by default, so tests that need the network should either
use fixtures or opt in explicitly:

```bash
cellrun run --network on --copy . -- npm test
```

Gate tool output before it enters agent context:

```bash
cellrun run --sanitize report.json --copy . -- npm test > report.json
cellrun sanitize report.json   # exit 1 on HIGH findings
```

The script below runs the project's tests in a cell and reports the exit
code, which is the test suite's exit code.
