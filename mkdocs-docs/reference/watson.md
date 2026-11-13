# Watson — Case Investigation Chat

Watson is an AI assistant that works one case with you. You talk to it in a chat. It tracks the case's key questions, tells you what it is working on, and asks you for one thing at a time. This page describes what Watson does in this version.

Watson follows the case's AI switch. With AI off for the case, Watson does not answer.

Watson can read the case, answer questions, and draft changes to it. **Every change waits for your Apply.** Watson never writes to the case by itself.

---

## Where Watson lives

Watson is always pinned to the right of the dashboard, on every section and every view. It is not a dashboard section, so no view hides it. It has three states:

- **Rail** — a thin strip with the Watson icon, a dot when Watson has written since you last looked, and the number of proposals waiting for you. Click it, or press Enter or Space on it, to open the panel. The rail is the default.
- **Open** — a 360 px panel with the chat. The dashboard narrows to the space that is left. **Collapse** makes it a rail again.
- **Full screen** — choose **Full screen** in the open panel. Watson covers the whole dashboard below the top toolbar, with the **Key Questions** board on the left and the chat on the right. The page behind does not scroll. Press **Esc** or choose **Exit full screen** to go back to the open panel.

The **Watson** button in the toolbar switches between open and rail. The dashboard remembers the state in this browser.

When the server has no AI provider for Watson, the panel does not appear.

Each case has one chat. The chat is saved with the case. You can close the dashboard, come back later, and continue where you stopped.

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

Watson does not change the super-timeline, and it never reads it.

## The Watson badge and Undo

Everything you apply from Watson carries a **Watson** badge. The badge shows on the finding, the next step and the report text, with the name of the analyst who approved it. The report says that the item was proposed by Watson and approved by that analyst.

Each applied item has its own **Undo**, in the chat and next to the badge. Undo puts back what was there before. For a finding, a step or report text, a later edit by you is kept: Watson does not overwrite it.

Undo is refused while a finding still cites the item. This protects the finding from pointing at an event that no longer exists. Undo the finding that cites it first. A new synthesis keeps Watson's findings and their badge: it does not remove them.

An undo does not wake Watson.

## A round

Each time you send a message, Watson answers with three parts:

1. **Working on** — the question or lead Watson is following.
2. **Learned** — what it found out from the case data and from what you sent.
3. **One request** — the one thing Watson needs next. This is one of two kinds:
    - A **copy-ready query** that you run on your own platform. Watson writes it in the query language of the case's platform.
    - A **file to import**. Import it as usual.

Watson asks for one request at a time so that you always know the next step.

## Asking Watson a question

Watson replaced the **Ask the LLM** panel. Type any question about the case in the chat, for example "Was data exfiltrated?" or "When did the attacker first reach the domain controller?". Watson answers it as part of the round, with:

- a status: answered, partial or unknown;
- the answer, with clickable citations to the forensic events it is based on;
- a pointer: where to look or what to collect next when the case cannot settle it yet.

Choose **Add to open questions** to put the question on the Key Questions board. Your click is the approval: the question is added at once, and you can choose **Undo** like any applied proposal. Choose **New thread** to start a fresh conversation; Watson's memory of the case stays.

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

When the case is too large for the model, Watson reads a prioritised part of it, and its answer says from how many of the in-scope events it was built. The super-timeline is never read.

To see exactly what Watson would send for a message, use **Preview what the AI will see** and choose **Watson message**. The preview builds the same request a real message sends, masked the same way, and saves nothing.

From Slack, Teams or Telegram, `/dfir ask <question>` sends the question to Watson in the same shared chat. See [War-Room Bot](war-room-bot.md).

## Giving Watson evidence

You can paste text into the chat or attach a text file. Watson stores it as evidence in the case.

- Watson searches the stored text in short, bounded excerpts. It never sends a whole large paste to the model.
- A paste does not start a synthesis, and it does not count as a normal import.
- Watson can cite the exact lines of a paste in a finding.

A paste can be up to 50 MB.

If Watson cannot read a stored paste at once, the paste stays in the case. Watson reads it on your next message. This happens when the anonymizer holds the message for your approval, and when the round fails or reaches the cost limit. The chat tells you that the paste was stored, so do not paste it again.

### Pasted files in a known format

When a paste is in a format that a built-in importer reads (for example SIEM or EDR JSON, or a known event log export), Watson parses it into rows. The rows are graded like a normal import. The chat shows a line such as: "Parsed 2 rows from events.json (siem). 1 rows the tagger graded above Info wait for your approval."

- The content tagger may raise some rows above Info (for example a `ntdsutil` command line). **Watson holds those promotions.** The rows stay in the super-timeline, and the raised copies wait as a **held rows** proposal. Choose **Apply** to put them in the forensic timeline, or **Reject** to leave them out. Large batches are split, 25 rows per proposal, and the chat says if more than 200 rows were cut.
- Only the tagger's promotions are held. Other grading works as in a normal import. For example, a pasted account-creation row that resembles a case account is raised to High, the same as in a normal import.
- A generic CSV or log stays text, because only the AI could read its columns, and Watson does not call the AI for that. This includes CSV exports such as a Defender CSV. Watson can still search the text and cite its lines.
- If the importer cannot read a paste, the paste stays as searchable text and the chat says why.

See [Importing Data](importing.md#chat-pastes-watson) for the import side.

## Watson and synthesis

A synthesis run keeps the answers Watson gave. If a new synthesis reaches a different conclusion, the board shows **Synthesis disagrees** next to the question. Synthesis does not overwrite Watson's answer. You decide which one to keep.

## What happens while you work

Watson notes these actions while you use the rest of the dashboard:

- notebook edits
- new stars on events (other tag changes are noted, but do not wake Watson)
- imports
- an import undo or redo (noted, but does not wake Watson)

When nothing new happens for 60 seconds, Watson reacts once to everything it noted. One reaction covers a whole batch of files. A reaction shows in the chat as **Watson reacted to: …**, followed by Watson's answer. A reaction never starts a synthesis, and a reaction never starts another reaction.

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

- A short hostname or username that appears alone, without its full name, may not be masked.
- With the anonymizer on, Watson masks all domains in its message. This includes attacker domains, which the other AI features leave readable.

## Settings and cost

Set these under **Settings → AI**. See the [Settings Reference](settings.md) for details.

| Setting | Meaning |
| --- | --- |
| `DFIR_AI_WATSON_MODEL` | The model Watson uses. Blank means the synthesis model. |
| `DFIR_AI_WATSON_COST_LIMIT_USD` | A dollar limit per case. It applies only when the provider reports a price. |
| `DFIR_AI_WATSON_TOKEN_LIMIT` | A token limit per case. It always applies. |
| `DFIR_AI_WATSON_REACT_DELAY_SEC` | Seconds of quiet before Watson reacts to case changes. Default 60. 0 = no reactions. |

The footer of the Watson panel shows how many calls Watson made on the case, and the cost in dollars or the tokens used, depending on what the provider reports.

## Backups and export

Watson's chat history stays out of state backups, so restoring a state backup does not bring back old chat. It travels with a case export, so an exported case keeps the full history.

## Not in this version

Watson does not yet:

- run in an automatic mode that works without your approval
- run Velociraptor actions
- search the super-timeline
- parse a generic CSV or log into timeline rows
