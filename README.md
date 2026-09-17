# coduck

**multiple chatgpt accounts. one codex cli.**

switch between work, personal, and school accounts while keeping your chatgpt
desktop app signed in. your codex settings, instructions, skills, memories, and
local sessions stay shared. your usual `codex` login stays separate.

## install

requires **macos**, **rust 1.90+**, and **codex cli 0.154.0**.

```sh
cargo install --git https://github.com/canu0205/coduck --locked
```

make sure `~/.cargo/bin` is on your `PATH`.

## use

```sh
coduck login work
coduck login personal
coduck list

coduck run work
coduck run personal
coduck run personal --resume SESSION_ID

coduck logout personal
```

each name saves a separate login. closing a session keeps you signed in;
`coduck logout personal` signs out only that profile.

local history is shared. resuming with another account sends that conversation's
context using the selected account.

early macos prototype. other codex versions, named codex configuration profiles,
and ctrl-z suspension are not supported yet.
