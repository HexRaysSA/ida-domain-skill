---
description: Run an ida-domain exercise from the examples folder
argument-hint: <example-folder> (e.g., 01_auto_tag_function_roles)
allowed-tools: Skill, Bash, Read, Write, Edit, Glob, Grep
---

# IDA Domain Exercise Runner

## Context

You are solving an IDA Domain exercise. Here is the exercise prompt:

@examples/$ARGUMENTS/prompt.txt

## Binary Location

The input binary for this exercise is located at: `examples/$ARGUMENTS/input`

## Instructions

1. Read and understand the exercise requirements from the prompt above
2. Use the `ida-domain-scripting` skill to solve the exercise
3. Write IDAPython scripts that accomplish the task described
4. Execute the scripts against the input binary
5. Present the results as specified in the expected output section

Use the Skill tool to invoke `ida-domain-scripting` for writing and executing your analysis scripts.

Remember:
- Scripts should be written to `/tmp/ida-domain-*.py`
- Execute via the ida-domain skill's run.py against the input binary at `examples/$ARGUMENTS/input`
- Follow the expected output format specified in the prompt
