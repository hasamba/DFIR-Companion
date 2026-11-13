# Watson — Case Investigation Chat

Watson is an AI assistant that works one case with you. You talk to it in a chat. It tracks the case's key questions, tells you what it is working on, and asks you for one thing at a time. This page describes what Watson does in this version.

Watson follows the case's AI switch. With AI off for the case, Watson does not answer.

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

Watson may want to add a question, change one, or change a status. It does not do this by itself. Each change appears as a **proposal**. You choose **Apply** or **Reject**. After you apply a proposal, you can choose **Undo**. In this version Watson changes nothing on the board without your approval.

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
- The text is not split into timeline rows in this version.
- A paste does not start a synthesis.

A paste can be up to 50 MB.

If Watson cannot read a stored paste at once, the paste stays in the case. Watson reads it on your next message. This happens when the anonymizer holds the message for your approval, and when the round fails or reaches the cost limit. The chat tells you that the paste was stored, so do not paste it again.

## Watson and synthesis

A synthesis run keeps the answers Watson gave. If a new synthesis reaches a different conclusion, the board shows **Synthesis disagrees** next to the question. Synthesis does not overwrite Watson's answer. You decide which one to keep.

## What happens while you work

While you use the rest of the dashboard, Watson does not react at once. These actions are queued:

- notebook edits
- tags and stars on events
- imports, and an import undo

Watson reads the queue at the start of your next message to it.

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

The footer of the Watson panel shows how many calls Watson made on the case, and the cost in dollars or the tokens used, depending on what the provider reports.

## Not in this version

Watson does not yet:

- run in an automatic mode that works without your approval
- run Velociraptor actions
- write findings or report text
- search the super-timeline
- react to notes, stars or imports as they happen
- split pasted text into timeline rows
