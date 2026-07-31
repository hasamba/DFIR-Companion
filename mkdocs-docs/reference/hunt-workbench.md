# Hunt Workbench and Query Language

The **Hunt Workbench** runs structured searches inside the open case. It is for questions that are
awkward or impossible to answer with the dashboard's text filter: failed logons for one account,
rare destination addresses, the busiest source hosts, or all high-severity activity in a time
window.

Choose the dataset explicitly before every run:

| Dataset | Contains | AI boundary |
|---|---|---|
| **Forensic timeline** | Graded, in-scope investigative events | Results can be attached to findings or added to the notebook |
| **Super-timeline** | The complete raw imported record, including Info telemetry | Results remain analyst-only; promote individual rows before they can support a finding or enter synthesis context |

Queries read SQLite indexes in bounded cursor pages. The workbench does not load a complete timeline
into browser or server memory. Conditions that can use the time, host, source, severity, event-ID,
IOC, or MITRE indexes are pushed down first; the explanation shown before and after a run says which
indexes are used. Other conditions are checked as each bounded page arrives.

## First queries

Failed authentication for an account during the last two hours, counted by source address:

```text
event.category=authentication
AND user.name="jdoe"
AND event.outcome=failed
AND timestamp during "last 2h"
| group by source.ip
| count
| sort count desc
```

High or Critical activity on either of two hosts:

```text
severity>=High AND (host.name=DC01 OR host.name=WEB01)
```

Rare destinations in the selected dataset:

```text
destination.ip exists | rare destination.ip limit 20
```

Safe regular-expression search:

```text
process.command_line matches /power(shell)?\s+-enc/i
```

Parameterized hunt template:

```text
event.category=authentication
AND user.name=$account
AND timestamp during $window
```

Enter its values in **Parameters** as `account=jdoe, window=last 24h`. Parameter values are stored
with a saved hunt and each execution-history record. They are values, not query fragments, so they
cannot change the grammar.

## Grammar

```text
filter     := expression ( "|" stage )*
expression := NOT expression
            | "(" expression ")"
            | expression AND expression
            | expression OR expression
            | predicate
predicate  := field operator value
operator   := = | != | > | >= | < | <=
            | contains | matches | exists | between | during
value      := quoted string | number | boolean | null
            | bare keyword | $parameter | /safe-regex/flags
stage      := group by field
            | count
            | stats function(field) [by field]
            | rare field [limit N]
            | sort field [asc|desc]
            | limit N
```

`NOT` binds more tightly than `AND`, and `AND` binds more tightly than `OR`. Parentheses override
that order. Equality and ordering are typed: severity uses
`Info < Low < Medium < High < Critical`, numbers compare numerically, and timestamps compare as
time. `contains` is case-insensitive. Equality is exact.

### Time windows

Use `during` with `last` or `past`, followed by a number and unit:

- `timestamp during "last 30m"`
- `timestamp during "past 2h"`
- `timestamp during "last 7d"`

Units are `ms`, `s`, `m`, `h`, `d`, and `w`. An absolute window uses two parseable timestamps:

```text
timestamp during "2026-07-01T00:00:00Z to 2026-07-02T00:00:00Z"
```

The first page fixes the relative-time anchor. Following its **Next page** cursor uses the same
anchor, so a long review cannot shift the result window between pages.

### Pipeline stages

| Stage | Result |
|---|---|
| `group by host.name \| count` | One row per host with a `count` column |
| `count` | One total matched-row count |
| `stats count(), min(destination.port), max(destination.port) by source.ip` | Typed statistics per source address |
| `rare destination.ip limit 10` | Ten least-common non-empty values |
| `sort count desc` | Descending order by the named output column |
| `limit 50` | At most 50 returned rows |

Statistics name their output columns predictably: `count`, `min_destination.port`,
`max_destination.port`, `sum_count`, and so on. `sum` and `avg` are useful for numeric fields.

## Typed field catalogue

The autocomplete menu is generated from the same catalogue the server validates. Aliases are
accepted, but explanations and saved plans use the canonical name.

| Field(s) | Type | Indexed | Meaning / aliases |
|---|---|---:|---|
| `id` | keyword | yes | Stable event ID; alias `event.id` |
| `timestamp`, `original_timestamp` | timestamp | `timestamp` | Normalized time and original pre-alignment time; alias `@timestamp` |
| `description`, `message` | string | no | Summary and retained full source message |
| `severity` | keyword | yes | Critical, High, Medium, Low, or Info |
| `host.name` | keyword | yes | Affected host; alias `asset` |
| `event.source` | keyword | yes | Artifact and source tools; aliases `source`, `artifact` |
| `event.category`, `event.type`, `event.action`, `event.outcome` | keyword | no | Canonical event classification; `outcome` is an alias |
| `user.name`, `user.id`, `user.domain` | keyword | no | Canonical account; `account.*` aliases are accepted |
| `source.ip`, `destination.ip` | keyword | yes | Canonical or legacy network addresses |
| `source.port`, `destination.port` | number | no | Network ports |
| `source.hostname`, `destination.hostname`, `network.protocol` | keyword | no | Network endpoint names and protocol |
| `process.name`, `process.parent.name` | keyword | no | Subject and parent process names |
| `process.pid`, `process.parent.pid` | number | no | Subject and parent process IDs |
| `process.executable`, `process.parent.executable`, `process.command_line` | string | no | Process paths and command line; `process.commandline` is accepted |
| `file.path` | string | yes | File path; alias `path` |
| `file.name` | keyword | no | File name |
| `file.sha256`, `file.md5` | keyword | yes | File hashes; aliases `sha256`, `md5` |
| `registry.key`, `registry.value_name`, `registry.value_data` | string / keyword | no | Registry activity |
| `service.name`, `service.display_name`, `service.executable` | keyword / string | no | Service activity |
| `task.name`, `task.command` | keyword / string | no | Scheduled-task activity |
| `authentication.session_id`, `authentication.protocol` | keyword | no | Authentication context |
| `authentication.logon_type` | number | no | Windows logon type |
| `session.id`, `session.interactive` | keyword / boolean | no | Session identity and interactivity |
| `cloud.provider`, `cloud.principal_id`, `cloud.tenant`, `cloud.region` | keyword | no | Cloud identity and location |
| `cloud.resource` | string | no | Cloud resource |
| `mailbox.sender`, `mailbox.recipient` | keyword | no | Email participants |
| `mailbox.subject` | string | no | Email subject |
| `actor.*`, `subject.*`, `object.*`, `target.*` | keyword / number | no | Canonical entity `kind`, `id`, `name`, `domain`, `address`, and numeric `port` |
| `mitre.technique` | keyword | yes | MITRE ATT&CK technique; alias `mitre` |
| `related.finding_id` | keyword | no | Finding IDs linked to the event |
| `evidence.screenshot` | string | no | Source screenshot paths |
| `count` | number | no | Collapsed occurrence count; defaults to 1 |
| `ioc` | keyword | yes | Any event IP, hash, or path represented in the IOC index |

Canonical fields may be absent on an older or less-structured record. Use `field exists` when a
missing value matters. Legacy event rows are upgraded on read where a deterministic mapping is
available; no prose is invented to fill a field.

## Errors and resource limits

Errors identify the line and column and use stable codes:

| Code | Meaning |
|---|---|
| `empty_query` / `invalid_query` | No usable expression, or the request was not query text |
| `unknown_field` | Field is outside the typed catalogue; nearest valid names are suggested |
| `expected_token`, `expected_operator`, `expected_value` | Grammar is incomplete at the reported location |
| `invalid_operator` | The operator does not apply there, such as `during` on a non-time field |
| `unsafe_regex` | Pattern is too long or uses lookarounds, backreferences, nested quantifiers, or repeated wildcards |
| `missing_parameter` | A `$parameter` was not supplied |
| `invalid_time_window` | A relative or absolute time window could not be parsed |
| `invalid_cursor` | Cursor is malformed or belongs to different query text, parameters, or dataset |
| `resource_limit` | Execution exceeded its bounded time, scan, regex, group, or materialized-row budget |
| `cancelled` | The analyst pressed **Cancel** or closed the request |

Default server limits are 100,000 scanned rows, 5 seconds, 50,000 regex evaluations, 5,000 groups,
10,000 materialized rows for a raw global sort, and 250 rows per storage page. A single response is
limited to 1,000 rows. These limits make an expensive query fail visibly instead of degrading the
case server. Regex patterns are limited to 256 characters and deliberately reject constructs with
poor worst-case behavior.

## Saved hunts and result actions

**Save hunt** stores the name, exact query, selected dataset, author, and parameters with the case.
Each execution adds its time, analyst, status, parameters, match/scan counts, and duration. The
history is newest-first and bounded. Saved hunts travel with investigation snapshots and survive
synthesis.

Results can be:

- viewed as a table, chronological timeline, or chart;
- cursor-paged without changing the query's relative-time anchor;
- exported as formula-safe CSV;
- added to the analyst notebook with selected event links;
- attached as evidence to an existing finding; or
- opened from one-click pivot buttons on event, IOC, finding, and asset rows.

Notebook and finding-evidence actions are disabled for super-timeline results. Select and promote
the individual raw rows first; the promoted forensic copies can then be queried and used normally.
