# Thanks for this PR

Just one thing before it can merge: a changelog entry, so your change shows up
in CHANGELOG.md for users. The CI gate looks for a file under
`.changes/unreleased/*.yaml`.

## First time? Install changie

If you do not have changie yet (needs Go on your PATH):

```shell
go install github.com/miniscruff/changie@latest
```

## Add a fragment

From the repo root, run:

```shell
changie new
```

You will be prompted for:

- **Kind** - the type of change: `added`, `changed`, `fixed`, `deprecated`,
  `removed`, `security`.
- **Body** - one line, written from a user perspective (what changed, not how).
- **Issue** (optional) - the issue number this closes, if any.

Prefer no prompts? Do it in one shot:

```shell
changie new -k fixed -b "Fix crash when signing the invite response"
```

Commit the new file under `.changes/unreleased/` and push to this branch. The
check re-runs automatically.

## No user-visible change?

Docs, tests, CI, and refactors do not need a fragment. Add the `skip-changelog`
label to this PR instead and the check will pass.

## More help

Full guide: CONTRIBUTING.md and https://changie.dev/guide/quick_start/. Stuck?
Ask in a comment below - happy to help.
