# What the agent may do on GitHub

The agent VM holds no GitHub token. The broker on the Mac adds the token to
requests on their way out, so the broker can also decide which requests go
out at all. This page says which ones do, which do not, and what the broker
cannot check.

The deciding is done by [`broker/github_policy.py`](../broker/github_policy.py).
It takes effect once the broker opens GitHub traffic and asks it about each
request, which is phase 4 of [PLAN.md](../PLAN.md). Until then the broker
passes GitHub traffic on unread, as described in
[architecture.md](architecture.md).

## Why

An agent can be tricked by something it reads: a web page, an issue, a file
in a repo. A tricked agent with your GitHub token could delete a repo, give
someone else access, read a secret, or copy your code to a place the attacker
can read.

GitHub limits what a token can do, and you should use a narrow one (see
[the token](#the-token)). The broker does not count on that. It is the first
check, and it works the same whatever token is behind it.

## The short version

| The agent may | The agent may not |
| --- | --- |
| Clone and fetch the repos you list | Reach a repo you did not list |
| Push to the repos you list as `write` | Push to a repo listed as `read` |
| Open, read, edit, comment on, review and close pull requests there | Merge a pull request, unless you allow it for that repo |
| Read issues there, and comment on them | Create, edit or close an issue |
| Read commits, branches, files, checks and Actions runs and logs | Change a repo's settings, delete it, transfer it, fork it or create one |
| | Read or write secrets and variables, deploy keys, webhooks, collaborators |
| Ask who the token belongs to | Change branch protection, create releases, start or stop Actions runs |
| | Use gists, the search API, or anything about your account or organizations |
| | Assign an issue or pull request to anyone |

Anything the broker does not recognise is refused. That includes harmless
requests nobody thought of; the rule is "allowed if known", not "refused if
known to be bad".

One thing to know before the rest: **most `gh pr` commands that change
something are refused**, although the change itself is allowed. `gh` sends
them in a form that names the pull request only by an id, and an id does not
prove which repo it is in. The same change goes through with `gh api`, which
names the repo. [Which `gh` commands work](#which-gh-commands-work) has the
list, and the refusal the agent gets names the command to use instead.

## Listing a repo

The rules are the `github` part of [`broker/rules.yaml`](../broker/rules.yaml),
on the Mac, where the agent cannot change them:

```yaml
github:
  repos:
    - repo: your-name/your-repo
      note: The repo the agent works on.
      access: write
      id: R_kgDOExample1

    - repo: some-org/a-library
      note: Read for reference while working.
      access: read

  other_repos: refuse
```

Each repo has:

| Key | Meaning |
| --- | --- |
| `repo` | One exact repo as `owner/name`. No wildcards, no `.git`. Upper and lower case are treated the same, as GitHub does. |
| `note` | A few words on why the agent needs it. Required, so nobody has to guess later whether the entry can go. |
| `access` | `read`: clone, fetch, and read pull requests, issues and checks. `write`: also push, work on pull requests, and comment. Required; there is no default. |
| `id` | Optional. GitHub's id for the repo. Without it, `gh pr create` is refused for the repo; see below. |
| `merge` | Optional, `true` or `false`. Whether the agent may merge pull requests. Off unless you turn it on, and only with `access: write`. |

Get the `id` with:

```sh
gh repo view your-name/your-repo --json id --jq .id
```

**Why the `id`.** `gh pr create` opens a pull request through GraphQL, a
second API, and names the repo there by its id (`R_kgDO...`), not by owner
and name. The `id` in the rules is how the broker knows which listed repo
that is. A repo listed without `id` works with `git`, with every `gh` command
that reads, and with `gh api`; only `gh pr create` is refused for it, with a
message that says the entry needs an `id`. A pull request can also be opened
without it: `gh api repos/OWNER/REPO/pulls -f title=... -f head=... -f base=...`.

After a change to the file, restart the broker: `nix run .#broker`, or
restart the VM. A mistake in the file stops the broker from starting, with a
message that names the entry and says what to fix. An unknown key is a
mistake, so a typing error cannot quietly change what a rule means.

### Repos that are not listed

`other_repos` says what happens to them:

- **`refuse`** (the default): every request to them is refused.
- **`read-public`**: they may be read, and the request goes out **without the
  token**. GitHub then answers only for public repos. Use this when the agent
  needs to clone dependencies and you do not want to list each one.

Reading and writing are kept apart on purpose. Writing to an unlisted repo is
never allowed by any setting, because that is how data leaves.

Reading is sent without the token for this reason: with the token, "read any
repo" means "read every private repo the token's owner can read", and the
agent could then copy one of those into a listed repo. Without the token
there is nothing private to read. The cost is that GitHub allows only about
60 API requests an hour without a token, and that `gh` commands about an
unlisted repo fail, because GraphQL does not answer without one. `git clone`
and `git fetch` are not affected.

`read-public` still has two costs. The agent can read anything public,
including text written to trick it. And the names of what it reads are seen
by GitHub, and in coarse numbers by the repo's owner, which is a very thin
way to pass information out.

## What is allowed, in detail

### git

Git over HTTPS uses four requests per repo, and the broker allows exactly
those, on `github.com`:

| Request | What it is | Needs |
| --- | --- | --- |
| `GET /OWNER/NAME/info/refs?service=git-upload-pack` | Start of a fetch or clone | `read` |
| `POST /OWNER/NAME/git-upload-pack` | The fetch or clone | `read` |
| `GET /OWNER/NAME/info/refs?service=git-receive-pack` | Start of a push | `write` |
| `POST /OWNER/NAME/git-receive-pack` | The push | `write` |

("upload-pack" is the server uploading to you, so it is the reading one.)

`NAME` may end in `.git`. The rest of `github.com` is the website, which is
refused. So is SSH, which never reaches the broker at all.

A repo's wiki is a separate git repo, `NAME.wiki.git`. It is not covered by
listing the repo, and it cannot be listed.

**Git LFS is refused.** It stores files on other hosts than `github.com`,
which the broker does not pass on.

### The REST API

On `api.github.com`, under `/repos/OWNER/NAME`:

- **Reading** (`GET`, `HEAD`): the repo itself, pull requests, issues,
  commits, branches, files (`contents`, `git`, `readme`, `tarball`,
  `zipball`), `compare`, checks and statuses, labels, milestones, releases,
  tags, deployments, forks, events, and Actions runs, jobs, workflows and
  artifacts, logs included.
- **Changing**, in a `write` repo: creating and editing pull requests;
  comments, reviews, review requests, labels and reactions on them; updating
  a pull request's branch from its base; deleting a branch
  (`DELETE /git/refs/heads/...`).
  In this API a pull request is also an issue with the same number, and its
  comments, labels and reactions are reached under `/issues/N`. The broker
  cannot tell from a number which of the two it is, so comments, labels and
  reactions work on issues as well.
- **Merging** (`PUT /pulls/N/merge`), in a repo with `merge: true`.

Outside `/repos`, five requests are allowed, all reading: `/`, `/user` (who
the token belongs to), `/rate_limit`, `/meta` and `/versions`.

### GraphQL, which is what `gh` mostly uses

A GraphQL request is a small program sent to `api.github.com/graphql`. The
broker reads the program and checks it.

**Queries** (reading) may start at:

| Start | Check |
| --- | --- |
| `repository(owner:, name:)` | The repo is listed. This is nearly everything `gh` reads. |
| `node(id:)` | Only with the id of a listed repo itself. Asking for a pull request, an issue or a comment by its id is refused; see below. |
| `search` | Issues and pull requests only, and the search text names listed repos with `repo:owner/name` and nothing wider. `gh pr list --search` and `gh pr status` use this. |
| `viewer`, `user(login:)` | Only an account's name and id. |
| `rateLimit`, `__type`, `__schema` | About the API itself. |

**Mutations** (changing): one is allowed, `createPullRequest`, which is what
`gh pr create` sends. It names the repo by the repo's id, and that id must be
the `id` of a `write` repo in the rules. If the branch comes from another
repo, that one must be a listed `write` repo too.

Every other mutation is refused, including ones GitHub adds in the future.
GitHub has about 285 of them.

#### Why a pull request cannot be changed by its id

GraphQL names a pull request, an issue, a comment or a review by an id such
as `PR_kwDO...`, and a request to comment on one holds that id and nothing
else: no owner, no repo name, no number.

The id does have a repo's number inside it, next to the pull request's own
number, and an earlier version of this policy believed it. That was wrong.
GitHub finds the pull request by its own number and does not look at the
repo's number at all. An id made of a listed repo's number and the number of
a pull request somewhere else is answered with that other pull request. This
was seen on GitHub, not read in its documentation: the id of a real pull
request with the repo's number replaced by 1 still gave the same pull
request.

So such an id proves nothing about the repo, and the broker cannot keep a
request that rests on one to the allowed repos. A tricked agent could post
your code as a comment on a pull request in any repo the token can write to.
Every mutation that names its target that way is refused, and so is reading
one thing by such an id.

A repo's own id is different. It holds one number, the repo's, and GitHub
has nothing else to go by. That is why `createPullRequest` can be allowed.

The work itself is not lost. The REST API does the same changes with the
repo in the address, where the broker can check it.

### Which `gh` commands work

| Command | From the sandbox | Use instead |
| --- | --- | --- |
| `gh pr create` | Works, in a repo with `id` in the rules | |
| `gh pr list`, `gh pr view`, `gh pr diff`, `gh pr status` | Work | |
| `gh issue list`, `gh issue view`, `gh repo view` | Work | |
| `gh run list`, `gh release list`, `gh label list` | Work | |
| `gh api repos/OWNER/REPO/...` | Works, for what the REST section above allows | |
| `gh pr checks` | Refused: reads by id | `gh pr view NUMBER --json statusCheckRollup` |
| `gh pr comment`, `gh issue comment` | Refused | `gh api repos/OWNER/REPO/issues/NUMBER/comments -f body='TEXT'` |
| `gh pr comment --edit-last` | Refused | `gh api -X PATCH repos/OWNER/REPO/issues/comments/COMMENT_ID -f body='TEXT'` |
| `gh pr edit` | Refused | `gh api -X PATCH repos/OWNER/REPO/pulls/NUMBER -f title='TITLE' -f body='TEXT'` |
| `gh pr edit --add-label` | Refused | `gh api repos/OWNER/REPO/issues/NUMBER/labels -f 'labels[]=LABEL'` |
| `gh pr edit --add-reviewer` | Refused | `gh api repos/OWNER/REPO/pulls/NUMBER/requested_reviewers -f 'reviewers[]=LOGIN'` |
| `gh pr close` | Refused | `gh api -X PATCH repos/OWNER/REPO/pulls/NUMBER -f state=closed` |
| `gh pr reopen` | Refused | `gh api -X PATCH repos/OWNER/REPO/pulls/NUMBER -f state=open` |
| `gh pr review` | Refused | `gh api repos/OWNER/REPO/pulls/NUMBER/reviews -f event=COMMENT -f body='TEXT'` |
| `gh pr update-branch` | Refused | `gh api -X PUT repos/OWNER/REPO/pulls/NUMBER/update-branch` |
| `gh pr merge` | Refused | `gh api -X PUT repos/OWNER/REPO/pulls/NUMBER/merge`, in a repo with `merge: true` |
| `gh pr ready`, `gh pr merge --auto` | Refused | Nothing: GitHub has no request for these that names the repo. Open the pull request ready, or do it yourself. |

`gh pr create` with `--reviewer` or `--label` is expected to open the pull
request and then fail, because `gh` adds those in a second request by id.
This was not tried. Open the pull request without them and add them with the
`gh api` lines above.

In a comment, `NUMBER` is the number of the pull request or issue. In this
API a pull request's comments, labels and reactions are reached under
`/issues/NUMBER`.

The agent does not need this table. When one of these is refused, the text
it gets back names the `gh api` line to use, and the tests check that each
of those lines is itself allowed. Which mutation each `gh` command sends was
recorded for `gh pr create`, `gh pr comment`, `gh pr comment --edit-last` and
`gh pr checks`; for the others it is taken from how `gh` is known to work,
and the refusal does not depend on it: the mutation is refused by its own
name, whichever command sent it.

## What is refused on every repo, and why

These are refused whether or not the repo is listed, and no setting allows
them. The word in the first column is what appears in the broker's log.

| Reason | What | Why |
| --- | --- | --- |
| `repo-settings` | Name, visibility, default branch, topics, pages, environments and other settings | Making a private repo public is the plainest way to leak it. |
| `repo-deletion`, `repo-transfer` | Deleting a repo, or moving it to another owner | Damage that is hard to undo. |
| `repo-creation`, `forks` | Creating a repo, forking one, creating one from a template | A new repo is a new place to put data, outside the list. |
| `repo-by-id` | `/repositories/NUMBER/...` | GitHub serves every repo under its number too, which would get around a list of names. |
| `secrets` | Secrets and variables of Actions, Dependabot, Codespaces and environments, and secret scanning results. Reading too. | They are the keys to everything else. |
| `deploy-keys`, `webhooks`, `collaborators` | Reading or changing any of them | Each gives someone lasting access, or a copy of everything that happens. |
| `branch-protection` | Protection rules, rulesets, renaming a branch | They are what keeps a tricked agent off `main`. |
| `releases` | Creating or changing releases and their files | A release is something other people download and run. |
| `actions` | Starting, re-running, cancelling or configuring Actions | Workflows run with the repo's secrets. Reading runs and logs is allowed. |
| `checks` | Setting commit statuses and checks | The agent could mark its own work as passing. Reading is allowed. |
| `git-data`, `merge-api` | Changing files, commits, branches or merges through the API | `git push` already does this, in a way you can see. One exception: deleting a branch. |
| `issues` | Creating, editing or closing an issue | Not part of the work the sandbox is for. Reading and commenting is allowed. |
| `assignees` | Assigning an issue or pull request | Assigning one to a hosted coding agent starts a second agent outside the sandbox, with a token of its own. |
| `gists` | Everything about gists | A gist is a place to put data outside the allowed repos. |
| `account`, `organizations` | Your account's keys, emails and repo list; anything under `/orgs` | Not the agent's business. |
| `search` | The REST search API | It is not tied to one repo. Search through `gh pr list --search` instead. |
| `git-lfs` | Git LFS | Needs hosts the broker does not pass on. |

## Requests in an odd spelling

There is more than one way to write most requests, and a check that
understands only the usual way can be walked around with an unusual one. The
broker does not try to tidy an odd request into a normal one. It refuses it,
because it sends on exactly what it was given, and the only safe request is
one that GitHub cannot read differently from how the broker read it.

Refused for their spelling, whatever they ask for:

- **Paths** with a doubled or trailing slash, a `.` or `..` part, an encoded
  slash, backslash or `%`, a broken `%` encoding, or any character outside
  plain printable ASCII. A keyword with an encoded letter (`%70ulls` for
  `pulls`) matches nothing and is refused as unknown.
- **Methods** other than `GET`, `HEAD`, `POST`, `PUT`, `PATCH` and `DELETE`,
  spelled exactly so. `OPTIONS` is refused. A header or query that asks for
  another method than the one sent (`X-HTTP-Method-Override`, `_method`) is
  refused.
- **Hosts.** Only `github.com` and `api.github.com`. A request sent to one
  host that names another in its `Host` header is refused, because GitHub
  goes by that name.
- **Bodies** that are compressed, larger than 1 MiB, not UTF-8, not one JSON
  object, without `Content-Type: application/json`, or with a name used
  twice. Two programs can read such a body in two ways. A body that was
  judged is sent on freshly written out from what the broker read, so GitHub
  gets exactly what was judged.
- **GraphQL** text that cannot be read; a body with several requests in it; a
  query string on the GraphQL address.

Things that look like tricks and are handled instead of refused:

- **Upper and lower case** in owner and repo names mean the same repo, as on
  GitHub.
- **A repo named like an API word** (`repos/repos`, `user/gists`) is just a
  repo. Its place in the path says what it is, not its name.
- **Several operations in one GraphQL request.** GitHub runs the one that
  `operationName` picks. The broker requires every one of them to pass, so
  nothing is gained by hiding one behind another.
- **Aliases and fragments.** GraphQL lets a request rename a field in its
  answer, and move fields into a named group that is used elsewhere. The
  broker goes by the real field names and opens every group.
- **Variables and defaults.** A repo name or id may be written into the
  GraphQL text, sent beside it as a variable, or left to a default. The
  broker works out the value the way GitHub will.

## When something is refused

The agent gets `403` with a text that says what was refused and what to ask
you for:

```
Refused by the sandbox broker: other-org/some-repo is not a repo the sandbox may use.

This machine is a sandbox. Its requests to GitHub go through a
broker on the host. The broker adds the GitHub token, and lets
through only what the `github` rules in broker/rules.yaml of the
nixt3 repo on the host allow. Trying again, or sending the same
request in another way or with another tool, will not help.

If the task needs this repo, tell the user. They can list it under
`github: repos:` in that file and restart the broker.
```

The last paragraph depends on the refusal: list the repo, give it `write`,
turn on `merge`, add its `id`, do it yourself (for what no rule allows), or
send the request the plain way. Where another request does the same job and
is allowed, the message says so and gives it as a line to run:

```
Refused by the sandbox broker: the GraphQL mutation `addComment` names what it changes only by an id, and an id does not prove which repo that is in. (`gh pr comment` and `gh issue comment` send it.)

This machine is a sandbox. Its requests to GitHub go through a
broker on the host. The broker adds the GitHub token, and lets
through only what the `github` rules in broker/rules.yaml of the
nixt3 repo on the host allow. Sending this request again will
not help. Another request will, and it is given below.

GitHub finds a pull request, issue, comment or review by its id
whatever repo the id claims to be in, so the broker cannot keep such a
request to the allowed repos. The REST API does the same job with the
repo in the address, and that is allowed in a repo listed with
`access: write`:

    gh api repos/OWNER/REPO/issues/NUMBER/comments -f body='TEXT'

Put your own values where the words are in capitals.
```

Besides the reasons in the table above, the log can show:

| Reason | Meaning |
| --- | --- |
| `repo-not-listed` | The repo is not in the rules. |
| `repo-read-only` | The repo is listed as `read` and the request would change it. |
| `merge` | Merging, in a repo without `merge: true`. |
| `not-recognised` | Not a kind of request the broker knows. |
| `github-host-not-covered` | A host other than `github.com` and `api.github.com`. |
| `graphql-query-not-allowed` | A GraphQL query that starts somewhere else than the allowed places. |
| `graphql-mutation-not-allowed` | A GraphQL mutation other than `createPullRequest`. |
| `graphql-by-id` | A GraphQL request that names a pull request, issue, comment or review only by its id. |
| `graphql-id-not-listed` | A repo's id that is not the `id` of a listed repo. |
| `graphql-account` | More than name and id asked about an account. |
| `graphql-search` | A search that is not kept to listed repos. |
| `graphql-walks-away` | A query that leads from a listed repo to lists of other repos or gists. |
| `graphql-malformed` | GraphQL the broker cannot read, or with the wrong parts. |
| `path-odd`, `query-odd`, `body-odd`, `host-differs`, `header-repeated`, `method-override` | An odd spelling; see above. |
| `policy-error` | The check itself failed on this request. It is refused, never let through. |

A reason is one of these fixed words. Nothing from inside a request is
logged.

## Other GitHub hosts

The policy covers two hosts. The others, and why they are left out:

| Host | Used for | Status |
| --- | --- | --- |
| `github.com` | git | Covered. |
| `api.github.com` | The REST API and GraphQL | Covered. |
| `uploads.github.com` | Uploading files to a release | Refused: releases are refused. Do not list it. |
| `gist.github.com` | Gists, by git and on the web | Refused: gists are refused. Do not list it. |
| `codeload.github.com`, `objects.githubusercontent.com`, `raw.githubusercontent.com` | Downloads of archives, release files, logs and single files | Not covered. GitHub answers some allowed reads by pointing to one of these, and that download then fails. If you list one as a plain destination, it must never be given the token. |

## The token

The broker decides which requests go out. What GitHub then lets those
requests do is down to the token, and a narrow token is the second layer:

- A **fine-grained** token, limited to the repos you list as `write`.
- Permissions **Contents** and **Pull requests**, read and write. Add
  **Issues**, read and write, if the agent should comment on issues.
- **Not** Workflows, Administration, Secrets, or anything about your account.
  Without Workflows, GitHub refuses a push that changes a file under
  `.github/workflows`, which the broker cannot do (see below).

## What the broker cannot see or enforce

Read this part before trusting the rest.

- **What is inside a push.** The broker allows or refuses a push as a whole.
  Which branch it changes, whether it rewrites history, deletes a branch or
  touches a workflow file is inside the upload, and is not looked at. Protect
  `main` with branch protection on GitHub, and leave the Workflows permission
  off the token.
- **What your repo does in response.** A push, a pull request or a comment
  can start whatever the repo is set up to start: Actions workflows, bots
  that act on a comment, a hosted coding agent that answers when mentioned.
  Those run outside the sandbox, often with the repo's secrets. The broker
  refuses the direct ways to start them, but it does not read the text of a
  comment. Check what your workflows do for a pull request from a branch of
  the same repo.
- **A `write` repo is a way out.** The agent can put anything into a repo it
  may push to or comment in. If that repo is public, so is what it puts
  there.
- **Where a GraphQL query goes after its start.** The broker checks where a
  query starts and refuses a handful of well-known steps from there to lists
  of other repos and gists. It does not know GitHub's whole data model, and a
  query that starts at a listed repo may be able to reach other things the
  token can read by a route that is not on the list. This is about reading,
  and a token limited to the listed repos closes it.
- **A repo's id is believed.** `gh pr create` names the repo by an id, and
  the broker reads the repo's number out of it. GitHub does not promise how
  ids are made, though this has held since 2021 and GitHub was seen to go by
  that number. If the make-up changes, the id is no longer understood and
  `gh pr create` is refused until this module is updated; it is not let
  through. No other id is believed.
- **The numbers in a REST address.** `PATCH /repos/OWNER/NAME/issues/comments/ID`
  names a comment by a number that is the same across all of GitHub. The
  broker checks the repo in the address and relies on GitHub to answer only
  for a comment that is in that repo. For reading this was seen to hold: a
  comment, a review comment and a review from another repo, asked for under
  a listed repo's address, each gave "not found". For changing it could not
  be tried without changing someone else's comment, and is taken to work the
  same way.
- **`gh pr ready` and resolving a review thread** cannot be done from the
  sandbox at all. GitHub offers them only in the form that names a pull
  request by id.
- **Search.** The check on search text follows GitHub's search language as
  documented. It is the weakest check here. It is about reading.
- **Mentions and links.** A comment that mentions a person notifies them. One
  that mentions an issue in another repo shows up there as a link, if the
  repo it was written in is public.
- **Volume.** Nothing limits how often an allowed request is made. A tricked
  agent can open many pull requests or write many comments in a `write`
  repo.
- **Reading listed repos.** Everything readable in a listed repo is readable
  by the agent, including Actions logs. Do not list a repo whose logs or
  history hold something the agent should not see.
- **The token's own reach.** If the token can do more than the rules allow,
  the difference is protected by this module alone.
- **Mistakes here.** This is a few thousand lines that read hostile input. It
  refuses what it does not know and what it fails on, and it has tests for
  every item on this page, but it can be wrong.

## Possible later work

**Asking GitHub which repo an id is in.** The `gh pr` commands above are
refused because nothing in the request proves the repo. The broker could
find out: before passing on a change by id, send GitHub a query of its own,
`node(id: ...) { ... on PullRequest { repository { nameWithOwner } } }`, and
let the change through only if the answer is a listed `write` repo. Then
`gh pr comment`, `gh pr edit`, `gh pr close`, `gh pr ready` and the rest
would work as they are.

It is not built, for three reasons. The decision would stop being a pure
function that can be tested without a network, which is what makes it
checkable today. The broker would make requests of its own with the token,
and every one of those needs the same care as the ones it guards. And
between the question and the change there is a gap in which the answer
could, in principle, stop being true. None of these rules it out; it is a
piece of work of its own, in `proxy.py` and not in this module.

## How this was checked against GitHub

- The REST paths come from GitHub's published description of its API
  ([github/rest-api-description](https://github.com/github/rest-api-description)),
  and the GraphQL names from its
  [public schema](https://docs.github.com/en/graphql/overview/public-schema).
- The requests `gh` sends were recorded with `GH_DEBUG=api` from `gh` 2.102
  and are replayed in the tests, with the repo names changed.
- That GitHub serves a repo under `/repositories/NUMBER` as well, treats
  owner and repo names without regard to case, and does not accept `.git`,
  a trailing slash or an encoded letter in an API path was observed against
  a public repo.
- That GitHub ignores the repo's number in the id of a pull request, and
  goes by it in the id of a repo, was observed on this project's repo, after
  a review of this policy found that it had been assumed the other way.
- Each REST request a refusal points to was checked against GitHub's
  description of its API, for the path, the method and the names in the
  body. Commenting and editing a comment that way were also done for real,
  on this policy's own pull request.

The tests are in
[`tests/unit/test_github_policy.py`](../tests/unit/test_github_policy.py).
Run them with `pytest tests/unit`.
