# Step 1 — Open the Dashboard

The browser panel on the right should be showing the DFIR Companion dashboard. If it's blank, the server may still be starting. Run this to check:

```
curl -s http://localhost:4773/health | python3 -m json.tool
```{{exec}}

You should see `"status": "ok"`. If not, wait 30 seconds and try again.

---

## Load the demo case

The dashboard opens to the case list. You'll see a **"Demo case"** button in the toolbar — click it to load the pre-built GlobalTech Industries investigation. Confirm the prompt.

The dashboard will reload showing the **GlobalTech Industries — BEC & Ransomware Precursor** case.

## Orient yourself

The dashboard has several panels:

- **Forensic Timeline** — every event from every imported tool, in chronological order
- **Findings** — AI-synthesised conclusions with severity and MITRE techniques
- **IOCs** — observed indicators (IPs, domains, hashes, files, processes)
- **Attacker Path / Evidence Chain** — causal graph of the attack
- **Adversary Hints** — which known threat groups match the observed techniques

The **severity legend** at the top of the timeline shows the breakdown: Critical, High, Medium, Low, Info.

---

Click **Check** when you can see the GlobalTech case loaded in the dashboard.
