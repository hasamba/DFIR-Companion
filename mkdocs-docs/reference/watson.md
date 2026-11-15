# Watson — Case Investigation Chat

Watson is an AI assistant that works one case with you. You talk to it in a chat. It tracks the case's key questions, tells you what it is working on, and asks you for one thing at a time. This page describes what Watson does in this version.

Watson follows the case's AI switch. With AI off for the case, Watson does not answer.

Watson writes the chat in ASD-STE100 Simplified Technical English. Its messages, answers, pointers, notes, and the findings, next steps and report text it proposes use short sentences (20 words or fewer for an instruction, 25 for a description), one instruction per sentence, the active voice and no idioms. The fixed text of the panel, its cards and its notes follows the same rules. Technical names stay exactly as they are: host names, user names, paths, hashes, ids, tool and artifact names, quoted evidence and queries.

Watson can read the case, answer questions, and draft changes to it. Watson never changes your findings, next steps, report text or Key Questions without your **Apply**.

Apply is also what Auto mode skips for Watson's own case writes; see [Approve and Auto](#approve-and-auto).

Two things happen without Apply. Text you paste into the chat is stored as evidence in the case at once, and it is parsed into rows when its format is known. Watson also notes what you do in the dashboard. Only the content tagger's promotions of pasted rows wait for your Apply (see [Pasted files in a known format](#pasted-files-in-a-known-format)).

---

## Where Watson lives

Watson is always pinned to the right of the dashboard, on every section and every view. It is not a dashboard section, so no view hides it. It has three states:

- **Rail** — a thin strip with the Watson icon, a dot when Watson has written since you last looked, and the number of proposals waiting for you. Click it, or press Enter or Space on it, to open the panel. The rail is the default.
- **Open** — a 360 px panel with the chat. The dashboard narrows to the space that is left. **Collapse** makes it a rail again.
- **Full screen** — choose **Full screen** in the open panel. Watson covers the whole dashboard below the top toolbar, with the **Key Questions** board on the left and the chat on the right. The page behind does not scroll. Press **Esc** or choose **Exit full screen** to go back to the open panel.

The **Watson** button in the toolbar switches between open and rail. The dashboard remembers the state in this browser.

When the server has no AI provider for Watson, the panel does not appear.

Each case has one chat. The chat is saved with the case. You can close the dashboard, come back later, and continue where you stopped.

Watson keeps the whole chat in the case. Nothing is ever dropped. When you mention something older than the recent chat, Watson searches the full history. The panel shows the latest 400 turns, and **Load earlier messages** scrolls back past them.

On a closed or archived case Watson stays off: you can read the chat, but you cannot send messages.

## The key questions

The six standard incident questions appear after your first message to Watson on a case. Each question has a status. A question Watson cannot answer from the data you can collect gets the status **Not answerable**. The report shows that status, and it does not read as "no".

Watson may want to add a question, change one, or change a status. It does not do this by itself. Each change appears as a **proposal**. You choose **Apply** or **Reject**. After you apply a proposal, you can choose **Undo**.

## What Watson can write

Watson can propose these changes. Each one appears in the chat as a proposal, and nothing is written until you choose **Apply**.

| Proposal | What it does when you apply it |
| --- | --- |
| **Key question** | Adds a question to the board, or changes a question or its status. |
| **Finding** | Adds a finding, or updates a finding that Watson wrote before. The finding cites timeline events, or lines of a paste you gave Watson. |
| **Next step** | Adds a step to the Next Steps list. |
| **Report text** | Writes the **Conclusions** or **Investigation limitations** text of the report. |
| **Held rows** | Raises rows from a pasted file into the forensic timeline. See [Pasted files in a known format](#pasted-files-in-a-known-format). |

A finding that cites a line of a paste adds that line to the forensic timeline when you apply it, so the citation points at a real event. Watson never edits a finding that you or a synthesis run wrote. It updates only its own.

Watson does not change the super-timeline. It searches it only when you ask (see Searching the super-timeline).

## The Watson badge and Undo

Everything you apply from Watson carries a **Watson** badge. The badge shows on the finding, the next step and the report text, with the name of the analyst who approved it. The report says that the item was proposed by Watson and approved by that analyst.

Each applied item has its own **Undo**, in the chat and next to the badge. Undo puts back what was there before. Undo is refused, and nothing changes, in two cases. The card says why:

- the item was changed after you applied it (for example you edited the finding), because Undo would destroy your edit;
- a finding still cites an event that Watson promoted. Undo the finding that cites it first.

Undo of a Watson finding works differently for the events the finding added (one for each pasted line it cited). If another finding now cites such an event, for example a finding from a later synthesis, Undo still removes the Watson finding but keeps that event in the timeline, with its Watson badge. The card then says **Removed the finding; kept N event(s) because other findings cite them**. An added event that no other finding cites is removed with the finding. If such an event was changed after you applied the finding, Undo is refused.

If you mark a Watson finding as a false positive, it stays in the case (Undo removes it), but synthesis no longer treats it as live.

An undo does not wake Watson.

## A round

In the message box, press **Enter** to send. Press **Ctrl+Enter** (or **Shift+Enter**, or **Cmd+Enter** on a Mac) to start a new line.

Each time you send a message, Watson answers with three parts:

1. **Working on** — the question or lead Watson is following.
2. **Learned** — what it found out from the case data and from what you sent.
3. **One request** — the one thing Watson needs next. This is one of two kinds:
    - A **copy-ready query** that you run on your own platform. Watson writes it in the query language of the case's platform.
    - A **file to import**. Import it as usual.

Watson asks for one request at a time so that you always know the next step.

While Watson works on an answer, every analyst who has the case open sees "Watson is working on a message from NAME" in the panel, and the stop icon. The line also shows how many more messages wait. To stop the answer, select the stop icon in the Watson header. The lookups that Watson made stay in the chat, and their cost stays counted. Watson does not propose changes after you stop it. Rows that Watson promoted before the stop stay promoted. If the stop comes after Watson saved its answer, the chat shows "Watson finished this answer before the stop." Then the answer and its proposals stay. If you send the same message again because the network failed, Watson does not answer it two times.

## Asking Watson a question

Watson replaced the **Ask the LLM** panel. Type any question about the case in the chat, for example "Was data exfiltrated?" or "When did the attacker first reach the domain controller?". Watson answers it as part of the round, with:

- a status: answered, partial or unknown;
- the answer, with clickable citations to the forensic events it is based on;
- a pointer: where to look or what to collect next when the case cannot settle it yet.

Choose **Add to open questions** to put the question on the Key Questions board. Your click is the approval: the question is added at once, and you can choose **Undo** like any applied proposal. When your question is already on the board, even in other words, the card names that key question instead of offering the button, and an add of a question already on the board is refused with a message on the card. Choose **New thread** to start a fresh conversation; Watson's memory of the case stays.

On a case with no forensic-timeline events and no findings, the chat says so: an answer would have nothing to read until you import evidence.

Watson reads the case, not only the chat. Besides the forensic timeline, the evidence-chain graph, the attacker path and the findings, it reads your own decisions, so its answer respects them:

| Your work | What Watson is told |
|-----------|---------------------|
| **Hypotheses** | Every hypothesis and its status. A refuted or exhausted theory must not be re-asserted. |
| **Host scope** | The latest signed decision per host. A cleared or out-of-scope host must not be named as compromised. |
| **Dwell windows** | Your attacker-presence windows, for "when did they get in / leave" questions. |
| **Prior hunts** | What was hunted and whether it found anything, so Watson does not ask for an empty hunt again. |
| **Stars, tags, comments** | What you marked or annotated. |
| **Notebook** | Only when **Include notebook in AI synthesis and Watson context** (Notebook panel) is on. |

When the case is too large for the model, Watson reads a prioritised part of it, and its answer says from how many of the in-scope events it was built. The case packet never includes the super-timeline; Watson searches it only when you ask (see Searching the super-timeline).

When an event Watson needs is not in that part (an event a finding cites, a time span, a host or a word), Watson looks it up in the forensic timeline before it answers. It reads at most 200 in-scope events per lookup and one lookup per message, and a lookup counts toward the Watson cost and token limits like any other call. The answer card says so: **Watson looked up 12 forensic-timeline events (on host WS-01)**. A lookup never reads the super-timeline: an event that is only there stays invisible to Watson until you promote it.

To see exactly what Watson would send for a message, use **Preview what the AI will see** and choose **Watson message**. The preview builds the same request a real message sends, masked the same way, and saves nothing.

From Slack, Teams or Telegram, `/dfir ask <question>` sends the question to Watson in the same shared chat. See [War-Room Bot](war-room-bot.md).

## Searching the super-timeline

The forensic timeline holds the events that were graded Low or higher. The super-timeline holds the raw rows, including the Info rows that were cut. When the forensic timeline cannot answer your question, Watson can search the super-timeline.

- When Watson makes several lookups for one question (see [Several lookups for one question](#several-lookups-for-one-question)), it can make up to two searches. Otherwise it makes one search for each question, and none in its own reactions. A search names text (3 characters or more), a hash, a host or a time window of 7 days or less. It can combine these.
- Watson sees at most 100 rows from a search, so at most 200 rows for one question. It does not read the whole super-timeline.
- Watson does not search in its own reactions to imports, notes or stars. Only a question or message you send starts a search.
- If the super-timeline has removed old rows because of its size limit, the answer carries a warning that the search can miss rows. Import the artifact again to get them back.

When Watson cites a raw row, the row is promoted into the forensic timeline before the answer is saved. It shows the **Watson** badge and has an **Undo**. Rows that Watson saw but did not cite stay in the super-timeline. Nothing is promoted from a Watson reaction to an import.

If a round cannot write to the case (writes are off for this message, the case is frozen, or AI is off), nothing is promoted. Watson drops each item that depended on the row and says so in the answer. If a promotion fails, Watson also drops those items. If some rows had already landed, the card offers **Apply** to finish and **Undo**.

Watson's answer in the chat keeps its text. If the answer names a raw row that is not in the forensic timeline, **Add to open questions** is refused. Ask Watson again.

Undo of a promotion is refused while a finding, next step, report text, key question or key question answer that Watson applied still depends on that row. Undo that item first.

Raw rows can show host and account names that the case does not know yet. Watson keeps a list of these names for the case. When anonymization is on, these names are masked in every AI request on the case, synthesis included. The redacted case export and the support bundle mask these names too. The redacted export keeps attacker domains readable, as it always does. A domain is masked in part when a victim host has the same first label, for example ANON_HOST_1.evil.example. Watson never removes a name from the list. When anonymization is on and the list already holds 500 hosts or 500 accounts, a search that would need a new name does not run for that message, and Watson tells you why. When anonymization is off, the search runs as usual and the list still records the names, so they are masked if you turn anonymization on later.

Synthesis and the deep pass never read the super-timeline.

## Several lookups for one question

When Watson runs on an API provider (OpenAI, OpenRouter, Gemini, Anthropic or Ollama) it can make several lookups before it answers one question. It asks for each lookup with a native tool call. There are four lookups:

- the forensic timeline
- the super-timeline
- a pasted file
- the chat history

Set the limit with `DFIR_AI_WATSON_MAX_TOOL_CALLS` (**Settings → AI**, "Watson lookups per question"). The default is 4. The highest value is 10. 0 means one lookup, as before. Watson can search the super-timeline two times for each question.

Each lookup is read-only. Every result is masked like the rest of the request, and Presidio checks it before it goes to the model. When Presidio finds a new value, Watson stops and holds the message until you approve the value.

Before each call to the provider, Watson checks the Watson cost limit and token limit. When a limit is reached, Watson stops at once and says so. The answer card lists every lookup Watson made for the answer.

Some cases stay on one lookup:

- Claude Code, Codex and LiteLLM always make one lookup.
- A model that refuses tools makes one lookup. Watson remembers this until the server restarts.
- Watson's own reactions to imports, notes and stars always make one lookup only.

If no Watson cost or token limit is set, Settings shows a warning, because each question can cost more than one call. Set a limit to control cost. The AI preview shows the first request only. It says how many lookups Watson can make.

## Giving Watson evidence

You can paste text into the chat or attach a text file. Watson stores it as evidence in the case.

- Watson searches the stored text in short, bounded excerpts. It never sends a whole large paste to the model.
- A paste does not start a synthesis, and it does not count as a normal import.
- Watson can cite the exact lines of a paste in a finding.

A paste can be up to 50 MB.

If Watson cannot read a stored paste at once, the paste stays in the case. Watson reads it on your next message. This happens when the anonymizer holds the message for your approval, and when the round fails or reaches the cost limit. The chat tells you that the paste was stored, so do not paste it again.

### Pasted files in a known format

When a paste is in a format that a built-in importer reads (for example SIEM or EDR JSON, or a known event log export), Watson parses it into rows. The rows are graded like a normal import. The chat shows a line such as: "Watson read 2 rows from events.json (siem). The tagger graded 1 rows above Info. These rows wait for your approval."

- The content tagger may raise some rows above Info (for example a `ntdsutil` command line). **Watson holds those promotions.** The rows stay in the super-timeline, and the raised copies wait as a **held rows** proposal. Choose **Apply** to put them in the forensic timeline, or **Reject** to leave them out. Large batches are split, 25 rows per proposal, and the chat says if more than 200 rows were cut.
- Only the tagger's promotions are held. Other grading works as in a normal import. For example, a pasted account-creation row that resembles a case account is raised to High, the same as in a normal import.
- A generic CSV or log stays text, because only the AI could read its columns, and Watson does not call the AI for that. This includes CSV exports such as a Defender CSV. Watson can still search the text and cite its lines.
- If the importer cannot read a paste, the paste stays as searchable text and the chat says why.

See [Importing Data](importing.md#chat-pastes-watson) for the import side.

## Running Velociraptor

When the case's server set includes a Velociraptor server, the panel header shows a **Velociraptor connected** chip, and Watson can ask to run VQL on it. There are two kinds of run:

- **A single-host collection** on one host that belongs to the case's fleet.
- **A fleet-wide hunt** across the fleet.

Each request appears in the chat as a card. The card shows the VQL, the target and Watson's reason, with **Launch** and **Reject**. Nothing runs until you choose Launch (or Auto allows it, see below).

Watson refuses, and does not guess, in these cases:

- The host is unknown or could be more than one machine. Watson never turns an unclear host into a fleet hunt.
- The same VQL already ran on the case as a hunt. For a collection, the same VQL on the same host counts as already run.

**A launch cannot be undone.** Once Velociraptor has started a collection or hunt, Watson cannot stop it.

If Watson cannot tell whether a launch ran (for example after a crash or a network error), the card says so. Check Velociraptor, then choose **Mark as launched** or **Try again**. Watson never retries by itself. A card that stays on *Launching* after the companion stopped mid-launch offers the same two choices.

A launch you marked as launched has no hunt or flow id that Watson knows. Its card says so, and Watson does not read its result: import that result from Velociraptor yourself.

### What VQL Watson may use

Watson prefers a reviewed, read-only list of plugins, functions, artifacts and WMI classes. VQL that stays on that list gets a normal card.

### Risky queries

Sometimes Watson needs something off the list: running a program, writing or uploading, a network call, a network path or URL, a path built at run time, or an artifact nobody reviewed. Watson can still propose that query, with its reason. The card is marked as risky:

- A red warning block names the risks in ASD-STE100 sentences, for example *The query runs a program on the endpoint (execve).*, and says that Watson's safety check usually blocks this query. Read the query before you approve it.
- The card has **Review risk and launch…** instead of **Launch**. Click it, read the question that opens on the card, then click **Yes, launch it**, or **Cancel**. Nothing runs before that second click.
- Just before the launch, Watson checks the query again. If the query now has a risk you did not see on the card, Watson refuses it.
- The launched card says that the analyst *approved this launch after the warning*. The audit log and the hunt entry say *approved by* the analyst *despite warning*, with the risks.
- **Auto mode never launches a risky query**, from any round. The Auto listing says *It waits for your approval, because the query is risky*, and names the risks.

### What is always refused

Some VQL is refused outright and never becomes a card, because Velociraptor could read it differently from what you see, or the launch itself is not valid:

- comments, triple-quoted strings, carriage returns, and hidden, control or text-direction characters (for example a right-to-left override that makes a file name read backwards), even inside a quoted string
- a string that holds a blank line or a line starting with `--`
- VQL that Watson's check cannot read, or that calls something it cannot name
- VQL longer than the size limit

Watson also never changes the text inside a quoted string before it sends the query, so the query that runs matches the card character for character.
- the same query that already ran on the case, an unknown or unclear host, or a fleet hunt with a host

When Watson's request is refused, its turn ends with **Nothing to approve** and the reason. If Watson's own text asked you to approve something, there is no card: nothing runs. The VQL is still shown with **Copy**, so you can run it by hand in Velociraptor if you decide it is safe. Watson also sees the list of collections it already launched on the case, so it should not ask for them again.

Two practical limits help Watson stay inside the list: every argument has a name, and file paths are plain quoted text with forward slashes.

### Approve and Auto

Each case has a run mode, shown in the panel:

- **Approve** (default) — every write and every Velociraptor launch waits for your choice.
- **Auto** — Watson acts on the limits below without asking.

Any analyst with write access to the case can switch the mode. Switching to Auto asks you to confirm first. Each switch is written to the audit log with the analyst's name. While the case is on Auto, the rail shows an **A**.

In Auto, Watson:

- applies its own case writes, from every round (a reaction to an import still changes Key Questions only, as before), but not the writes that rest on raw rows (see below)
- applies the tagger's promotions from the results of its own single-host collections, and from a file you paste in that round
- launches single-host collections from messages you type or files you paste in the dashboard's Watson panel, any number of them

In Auto, Watson never:

- starts a fleet-wide hunt (those always ask)
- launches a risky query (those always wait for an analyst)
- launches from a round it started itself, such as a reaction or a round that reads its own results
- launches from a `/dfir ask` sent through a chat bot, or from any round that did not start from the Watson panel
- acts on a case that was closed or archived while the round ran

In Auto, a case write waits for you when it rests on rows that Watson saw in the super-timeline or in a paste. This applies to findings, next steps, report text and key-question answers or new questions, from every round. The chat lists each one with the note *Waits for you: it rests on rows Watson saw in the super-timeline or in a paste.* A write that cites only forensic-timeline events still applies on its own. Promotions do not wait: the rows Watson promotes from the super-timeline or from a paste are evidence, with the Watson badge and Undo.

Every Auto action is listed in the chat with the exact VQL, and is logged as **Watson (Auto)** with who switched Auto on and when. Switching back to Approve stops the rest of the actions.

### Results coming back

- **A fleet hunt** is collected as for any hunt: the results are imported and a synthesis runs. Watson then reacts, and because an import arrived it proposes Key Question changes only.
- **A single-host collection** is imported like a pasted file in a known format: the rows are graded, the tagger's promotions wait for your Apply, and no synthesis runs. Watson reacts and may propose case writes. In Auto, the tagger's promotions from Watson's own collection results, and from a file you paste in that round, are applied automatically and listed in the chat.

Watson reads a collection's results from the Velociraptor server it was launched on, even if the case moves to another server set meanwhile. If that server is no longer available, the message says the results are in Velociraptor.

If the collection returned nothing, Watson reports that it found nothing. If the row limit cut a result, the message says so. If a result could not be read, or was interrupted, the message names the flow and the host and says the results are in Velociraptor and may not be in the case.

Watson watches a collection for 30 minutes. If the companion restarts during that time, the watch resumes.

## Watson and synthesis

A synthesis run keeps the answers Watson gave, and it keeps Watson's findings and next steps with their badge. If a new synthesis reaches a different conclusion, the board shows **Synthesis does not agree** next to the question. Synthesis does not overwrite Watson's work. You decide which one to keep.

## What happens while you work

Watson notes these actions while you use the rest of the dashboard:

- notebook edits (they wake Watson only when **Include notebook in AI synthesis and Watson context** is on; otherwise they are noted, because Watson cannot read the notebook)
- new stars on events (other tag changes are noted, but do not wake Watson)
- imports
- an import undo or redo (noted, but does not wake Watson)

When nothing new happens for 60 seconds, Watson reacts once to everything it noted. Each reaction is a full Watson round with the case context, so it costs like a message and counts toward the Watson cost and token limits. One reaction covers a whole batch of files. A reaction shows in the chat as **Watson reacted to: …**, followed by Watson's answer. A reaction never starts a synthesis, and a reaction never starts another reaction.

- Watson reacts only on a case where you already sent it a message.
- Watson does not react while AI is off for the case, or on a closed or archived case.
- When an import starts a synthesis, Watson waits for the synthesis to finish and then reacts to its result.
- After an import, Watson can answer and update the key questions, but it does not propose findings, next steps or report text. After notes and stars, it can propose them for your approval.
- When a reaction is held by Presidio, reaches the Watson cost or token limit, or fails two times in a row, Watson stops reacting on the case and says so in the chat. Send a message to start again.

Set the quiet time with `DFIR_AI_WATSON_REACT_DELAY_SEC` (default 60). Set 0 to stop the reactions: Watson then reads what it noted at the start of your next message.

## Privacy

Every Watson call goes through the same anonymizer as the other AI features. With the anonymizer on, Watson also masks every hostname and username in its message to the model, including ones in text you paste.

When Presidio finds a new value in Watson's message, it holds the message until you approve the value under **Anonymization**. Watson does nothing on the case while the message is held. After you approve, send a message to continue. A paste that was held is read then.

Known limits:

- Watson also masks a host name in the text of a raw row or a paste. It finds a name after a label such as Workstation Name or Computer, or a name in capitals with a hyphen and a digit, such as WS-PC01.
- After a label, Watson takes a name only when it has a digit, a hyphen or a dot. A plain word such as fakepc or Windows is not taken.
- For a domain after a label or in a paste, Watson keeps the full domain on its list. It keeps the first label alone only for an internal domain, such as files in files.corp.local. Common words such as www and login are not masked.
- A host name in lowercase or without a hyphen, such as dc01, may still go to the AI when no field of the case names it.
- With the anonymizer on, Watson masks all domains in its message. This includes attacker domains, which the other AI features leave readable.

Recovery from an unreadable chat file:

- If watson-chat.json is damaged and the case has no readable masking list file (watson-mask-roster.json), Watson refuses every change to the chat. The AI calls on the case also stop, because the masked names are not known.
- To recover, an administrator restores watson-chat.json from a backup.
- Alternatively, an administrator removes watson-chat.json. Watson then starts a new chat with an empty list. Names from the old chat are not masked after that.

## Settings and cost

Set these under **Settings → AI**. See the [Settings Reference](settings.md) for details.

| Setting | Meaning |
| --- | --- |
| `DFIR_AI_WATSON_MODEL` | The model Watson uses. Blank means the synthesis model. |
| `DFIR_AI_WATSON_COST_LIMIT_USD` | A dollar limit per case. It applies only when the provider reports a price. |
| `DFIR_AI_WATSON_TOKEN_LIMIT` | A token limit per case. It always applies. |
| `DFIR_AI_WATSON_MAX_TOOL_CALLS` | The most lookups Watson makes for one question. Default 4, highest 10, 0 = one lookup. |
| `DFIR_AI_WATSON_REACT_DELAY_SEC` | Seconds of quiet before Watson reacts to case changes. Default 60. 0 = no reactions. |

The footer of the Watson panel shows how many calls Watson made on the case, and the cost in dollars or the tokens used, depending on what the provider reports.

## Backups and export

Watson's chat history stays out of state backups, so restoring a state backup does not bring back old chat. It travels with a case export, so an exported case keeps the full history.

## Not in this version

Watson does not yet:

- run queries on any platform other than Velociraptor
- start fleet-wide hunts on its own
- parse a generic CSV or log into timeline rows
