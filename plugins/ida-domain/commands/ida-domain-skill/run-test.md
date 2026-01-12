---
description: Run an ida-domain test from the tests folder
argument-hint: <example-folder> (e.g., 01_auto_tag_function_roles)
allowed-tools: Skill, Bash, Read, Write, Edit, Glob, Grep
---

# IDA Domain Test Runner

## Context

You are solving an IDA Domain exercise. Here is the exercise prompt:

@tests/$ARGUMENTS/prompt.txt

## Binary Location

The input binary for this exercise is located at: `tests/$ARGUMENTS/input`

**CRITICAL WORKFLOW - Follow these steps in order:**

1. **Read prompt.txt** - Read and understand the exercise requirements from the prompt above
2. **ALWAYS use the ida-domain-script-skill** - Always use the skill to solve the exercise. Stop if you don't have
   the skill
3. **Use the input binary** - Execute the scripts against the input binary, never read the binary yourself.
4. **Report the results** - Present the results as specified in the expected output section
5. **Save the script** - Save the generated script and output to `tests/runs/`

Use the Skill tool to invoke `ida-domain-scripting` for writing and executing your analysis scripts.

<IMPORTANT>You can ONLY read prompt.txt and pass the input file to the skill</IMPORTANT>
<IMPORTANT>You can not read anything else from the tests folder</IMPORTANT>

Remember:

- Follow the expected output format specified in the prompt

## Saving Results

After execution, save results to a timestamped folder:

```
tests/runs/YYYYMMDD_HHMMSS/<exercise-folder>/
├── script.py    # The generated IDAPython script
└── output.txt   # The execution output
```

For example: `tests/runs/20250109_143052/01_auto_tag_function_roles/`

## Running Multiple Tests

When asked to run multiple tests, launch each test in a separate subagent running in parallel.

Important: Generate the timestamp once before launching subagents, and pass the same `tests/runs/YYYYMMDD_HHMMSS/`
output folder to all subagents so all results are grouped together in a single run folder.

## Summary Report

After all tests complete (whether single or multiple), **always generate a summary report** displayed as a markdown
table:

```
## Test Run Summary

| # | Test Name | Status | Duration | Key Findings |
|---|-----------|--------|----------|--------------|
| 01 | Example Test One | ✅ SUCCESS | 1m 23s | 150 items found - 60% type A, 40% type B |
| 02 | Example Test Two | ✅ SUCCESS | 45s | 42 patterns identified at 3 locations |
| 03 | Example Test Three | ❌ FAILED | 2m 05s | Script error: missing API function |
|    | **Total** |        | **4m 13s** |  |
```

### Status Values

- `✅ SUCCESS` - Test completed and produced expected output
- `❌ FAILED` - Script error or unexpected output
- `⏭️ SKIPPED` - Test has a SKIP.md file indicating it should be skipped

### Duration

Track the time each test takes from start to completion. Format as:

- Seconds only: `45s`
- Minutes and seconds: `2m 05s`
- Include a **Total** row summing all test durations

### Key Findings

Extract 1-2 key metrics or discoveries from the output, such as:

- Number of items analyzed/found
- Percentages or distributions
- Specific artifacts discovered (addresses, function names, etc.)
- Error reason if failed

### Saving the Report

Save the summary report to the run folder as `SUMMARY.md`:

```
tests/runs/YYYYMMDD_HHMMSS/
├── SUMMARY.md              # The summary report
├── 01_auto_tag_function_roles/
│   ├── script.py
│   └── output.txt
├── 02_callgraph_hotspot_ranking/
│   ├── script.py
│   └── output.txt
└── ...
```
