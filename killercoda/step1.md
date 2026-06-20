# Step 1 — Open the Dashboard

The terminal should have printed **"DFIR Companion is ready!"** when setup finished. If it's still counting, wait until you see that message before continuing.

Once it's ready, open the dashboard:

1. Click the **hamburger menu** (≡) in the top-right of the KillerCoda header → **Traffic / Ports**
2. Enter port **4773** and press **Access**
3. The DFIR Companion dashboard opens in a new browser tab

Alternatively, verify the server is running from the terminal:

```
curl -s http://localhost:4773/health | python3 -m json.tool
```{{exec}}

You should see `"status": "ok"`.

---

## Load the demo case

In the dashboard, click the **"Demo case"** button in the toolbar to load the pre-built GlobalTech Industries investigation. Confirm the prompt.

The dashboard will reload showing the **GlobalTech Industries — BEC & Ransomware Precursor** case.

## Orient yourself

The dashboard has several panels:

- **Forensic Timeline** — every event from every imported tool, in chronological order
- **Findings** — AI-synthesised conclusions with severity and MITRE techniques
- **IOCs** — observed indicators (IPs, domains, hashes, files, processes)
- **Attacker Path / Evidence Chain** — causal graph of the attack
- **Adversary Hints** — which known threat groups match the observed techniques

---

Click **Check** when you can see the GlobalTech case loaded in the dashboard.
