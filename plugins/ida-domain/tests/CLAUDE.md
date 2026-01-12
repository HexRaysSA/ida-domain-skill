# IDA Domain Examples

## Structure

Each example folder contains:

```
XX_example_name/
├── prompt.txt    # Exercise description and requirements
├── input         # Pre-built binary for analysis (or in build/ subfolder)
└── src/          # Source code (optional, for reference)
```

- `prompt.txt` - Describes the task, expected output, and evaluation criteria
- `input` - The binary to analyze (some examples have it in `build/` instead)
- `SKIP.md` - If present, the example should be skipped (missing dependencies or not yet ready)

## Running an Exercise

Use the `/ida-domain-run-test` command:

```
/ida-domain-run-test 01
```

or with full folder name:

```
/ida-domain-run-test 01_auto_tag_function_roles
```

This will read the prompt, invoke the `ida-domain-scripting` skill, and execute the analysis against the input binary.
