# Verifier

`agent.ts` provides `createVerifier(tools, bindings)`, a one-shot Guild LLM workflow.
It cross-checks feeds, calls `/scan`, reviews captured text when no rule matched,
and appends the scanner verdict. Script opinions stay in the separate review;
they do not silently replace deterministic verdicts.

The default export is a review-only fallback: it accepts the existing scanner
result and optionally captured sources as JSON text, using `prompt.ts`. It has
no tools, so it does not call `/scan`, check feeds or write events. Its review
output is separate from the shared event contract.

**Local build passed** with the CLI-created scaffold and installed Guild SDK 0.7.8.
Guild CLI authentication is valid. Node and Guild were installed outside this
PowerShell session's PATH; on this machine add `C:\Program Files\nodejs`,
`C:\Program Files\Git\usr\bin` and `%APPDATA%\npm` before `npm run build`.
The MCP connection remains unavailable (`resources/list` reports unknown server
`guild`). No public scanner URL or four-operation integration binding was
supplied, so the new workflow has not been tested end to end, uploaded or
published by this run. Earlier Guild test artifacts do not validate this workflow.

Follow the repository's [agent-development skill](../../.claude/skills/agent-dev/SKILL.md)
and [CLI workflow](../../.claude/skills/guild-cli-workflow/SKILL.md) to finish:

1. Keep the existing CLI-created scaffold. If recreating it, select the owning
   account and use
   `guild agent init --owner ACCOUNT --name verifier --template LLM --category development`
   in a temporary directory, then bring its scaffold into this directory while
   retaining the source files. Do not hand-create Guild package or identity files.
2. Provide a public `/scan` URL through the team's deployment. Register its
   OpenAPI operation as a Guild integration; Guild agents cannot use direct fetch.
3. Discover real operation names with `guild integration operation list`.
   Configure four operations with these contracts:

   | Binding | Required behavior |
   |---|---|
   | `scan` | Accept the shared event plus optional `listed_on_feed`; return `/scan`'s event and findings |
   | `checkFeeds` | Exact target URL lookup in trusted feed snapshots; return matches, sources, retrieval timestamps and lookup failures |
   | `readCapture` | Return captured text with URL, filenames, line numbers and timestamp; enforce the fetcher's private-address and size restrictions |
   | `writeEvent` | Append the full eight-field event as a new ClickHouse version; return an explicit write receipt |

   Only `scan` exists as an HTTP endpoint in this repo. The feed lookup, capture
   reader and event writer need actual integrations before this draft can run.
   Feed tools must use cached/synthetic fixtures for local testing; do not fetch
   real malicious targets. The current `/scan` endpoint deletes its temporary
   capture, so `readCapture` cannot assume that capture is still available.
4. Install the integration packages supplied by Guild. Its LLM scaffold provides
   `@guildai/agents-sdk` and TypeScript tooling; these are needed for the agent
   and are separate from Python's dependencies. This run reused the installed
   scaffold dependencies. Import only the discovered operations, pass their tool set
   and actual names to `createVerifier`, and default-export the returned agent
   from the scaffold's entry point. `workflow-prompt.ts` is the executable
   orchestration prompt; `prompt.md` is its readable copy. An earlier Guild server
   build could not resolve Markdown imports, so this agent imports TypeScript prompts.
5. Build with the scaffold's `npm run build`, then use `guild agent test` against
   owned demo pages and synthetic feed/capture fixtures. Inspect the trace for
   exact URL matching, one event write, pass-through fields and failure handling.

No owner, package name or integration operation name is guessed in the draft.
