# Migration guide

Coming from another tool? Here's how to land on `sshenv`.

## From plain env vars in your shell rc

1. `sshenv init --recipient-key ~/.ssh/id_ed25519.pub`
2. For each `export VAR=value` line in your rc, run:
   ```
   sshenv set <profile> VAR --value 'value'
   ```
   Group related vars into a profile (e.g. all AWS vars → `aws-prod`).
3. Remove the `export` lines from your rc.
4. Bind shims for the commands that need them, or wrap your command:
   ```
   sshenv run aws-prod -- aws s3 ls
   # or
   sshenv shims bind aws-prod --command aws
   ```
5. Add `export PATH="$HOME/.sshenv/bin:$PATH"` to your rc.

## From `envchain`

Export each `envchain` namespace to a temporary file, then import:

```sh
for var in $(envchain --list myns); do
  value="$(envchain myns sh -c "printf '%s' \"\$$var\"")"
  sshenv set myns "$var" --value "$value"
done
```

Replace `envchain myns foo` call sites with `sshenv run myns -- foo`
or bind a shim.

## From `op run` (1Password)

`op run` uses a template like `MY_VAR=op://vault/item/field`. Resolve
each entry once and insert the literal value into `sshenv`. Or, if
you want to keep 1Password as your source of truth, just keep using
`op run` — `sshenv` and `op run` don't conflict.

## From `direnv` `.envrc` files

If the secrets were `export FOO=bar` lines in a per-directory `.envrc`,
decide whether to:

1. **Keep direnv for non-secret values** (it's good at that) and move
   just the secret lines into `sshenv`. Replace the `.envrc` secret
   lines with `eval "$(sshenv export my-profile)"`.
2. **Move everything to `sshenv`** and delete the `.envrc`.

Option 1 is usually cleaner because `direnv` excels at per-directory
state and `sshenv` excels at secret storage.

## Multi-host

The vault file is ciphertext; copy it wherever. To add access from a
second machine with a different SSH key:

1. On a machine that can already decrypt: `sshenv add-recipient --key
/path/to/second/machine/id_ed25519.pub`.
2. Copy the updated vault to the second machine.
3. On the second machine, `sshenv doctor` should confirm an identity
   can unwrap.

Bindings (`bindings.toml`) are **local per host**, not synced via the
vault. Each host decides independently what to shim.
