# CodeQL Debug Action

Add this action to an existing CodeQL analysis workflow to generate an html report including
* recognized sources and sinks of the standard set of security queries,
* dependencies / frameworks used by the project,
* analysis performance statistics of previous analyses and
* generated log files from previous analyses.

## Example

```yaml
name: "CodeQL Debugging"
on: workflow_dispatch

jobs:
  debug:
    name: CodeQL Debug Job
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        language: [ 'javascript' ]

    steps:
    - name: Checkout repository
      uses: actions/checkout@v2

    - name: Initialize CodeQL
      id: codeqlinit
      uses: github/codeql-action/init@v1
      with:
        languages: ${{ matrix.language }}

    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v1

    - name: Debug Analysis
      uses: zbazztian/codeql-debug@master
      with:
        language: ${{ matrix.language }}

    - name: Upload loc as a Build Artifact
      uses: actions/upload-artifact@v2.2.0
      with:
        name: codeql-debug-results
        path: codeql-debug-results
        retention-days: 30
```

This will add the artifact `codeql-debug-results` which is an archive containing html file(s) for the language(s) that were analyzed.


## Parameters

* `language` (required): The language of the database to create the report for. The currently supported languages are `java`, `javascript` and `go`.
* `db-path` (optional): The path to the database. If omitted, the action will guess where the database is located.
* `codeql-path` (optional): The path to the CodeQL CLI executable. If omitted, the action will guess this path.
