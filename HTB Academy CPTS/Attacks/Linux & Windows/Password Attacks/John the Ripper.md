## Modes

### Single Crack Mode

Trying the passwords one by one with additional mangling rules.

### Wordlist mode

Trying the passwords one by one without additional rules, mangling rules can be applied.

### Incremental Mode

Incremental mode is used to crack passwords using character set, it will try matching passwords with all possible combinations from a character set, starting from the shortest one. it is the most effective and time consuming mode.

#### Incremental Mode in John
```shell-session
$ john --incremental <hash_file>
```

Using this command we will read the hashes in the specified hash file and then generate all possible combinations of characters, starting with a single character and incrementing with each iteration. The default character set is `a-zA-Z0-9`.