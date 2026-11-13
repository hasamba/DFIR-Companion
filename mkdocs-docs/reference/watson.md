# Watson — Case Investigation Chat

Watson is an AI assistant that works one case with you. You talk to it in a chat. It tracks the case's key questions, tells you what it is working on, and asks you for one thing at a time. This page describes what Watson does in this version.

Watson follows the case's AI switch. With AI off for the case, Watson does not answer.

---

## Where Watson lives

A side panel sits on the right of every dashboard section. It collapses to a thin rail. Click the rail to expand it. The expanded panel opens the **Watson** section, which holds the chat and a **Key Questions** board.

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

## Giving Watson evidence

You can paste text into the chat or attach a text file. Watson stores it as evidence in the case.

- Watson searches the stored text in short, bounded excerpts. It never sends a whole large paste to the model.
- The text is not split into timeline rows in this version.
- A paste does not start a synthesis.

A paste can be up to 50 MB.

## Watson and synthesis

A synthesis run keeps the answers Watson gave. If a new synthesis reaches a different conclusion, the board shows **Synthesis disagrees** next to the question. Synthesis does not overwrite Watson's answer. You decide which one to keep.

## What happens while you work

While you use the rest of the dashboard, Watson does not react at once. These actions are queued:

- notebook edits
- findings and events you star
- normal imports

Watson reads the queue at the start of your next message to it.

## Privacy

Every Watson call goes through the same anonymizer as the other AI features. With the anonymizer on, Watson also masks hostnames it has not seen before in text you paste.

Known limits:

- A short hostname or username that appears alone, without its full name, may not be masked.
- With the anonymizer on, all domains in a paste are masked. This includes attacker domains.

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
