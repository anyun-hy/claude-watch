# OpenAI Force policy migration (v1)

Applies only to the ChatGPT / Codex / OpenAI desktop family. Claude policy
and its existing Force default are unchanged.

Old schema-1 records could carry `gpt_close_*=force` without any proof that
this was an intentional selection in the current Force-capable UI.

## Behavior

- Reading old configuration never writes to disk. Old unapproved OpenAI Force
  values are treated as ordinary `close`, not SIGKILL authorization.
- The status response exposes affected keys as `legacy_openai_force_review`.
  The UI displays a migration review warning.
- The next ordinary settings save normalizes unapproved values to `close`.
- Choosing Force again in the current UI sends an exact per-key
  `--confirm-force` value; approved keys and their policy values are stored
  together in one atomic configuration write (`gpt_force_approved_v1`).
- Unrelated saves preserve only existing valid approvals, never grant more.
- Changing an approved item back to `close` or `warn` revokes its grant.
- New unconfirmed Force selections are rejected. Unknown or malformed
  approval keys cannot grant Force. Existing process-family scope is intact.
- Default OpenAI remains `close`, default Claude remains `force`, and
  unknown disposition codes remain `warn`.

This guards against accidental legacy activation, not deliberate local-file
tampering by an actor who can rewrite the user's configuration. The approved
key list is not a cryptographic signature.

## Validation

```bash
bash tools/test-force-migration-regressions.sh
```

All regressions use temporary data, mocked desktop inventories, and no
native termination, login, installation, or installed settings modifications.
Actual application and macOS runtime acceptance remain separate work.
