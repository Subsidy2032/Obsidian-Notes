List all files - ls

Find all files with the word pass in them - grep -rnw . -e 'pass' 2>/dev/null

## Flags
-r - recursive
-n - line number
-w - match specific word fully
-e - use PATTERN as the pattern. This can be used to specify multiple search patterns, or to protect a pattern beginning with a hyphen (**\-**)
2>/dev/null - ignore errors by putting them in the null file