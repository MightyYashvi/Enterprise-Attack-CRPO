# CVE to MITRE ATT&CK Mapping with LLMs

Maps three CVEs to MITRE ATT&CK Enterprise techniques using two local open-source LLMs (I chose Llama 3.1 8B and Qwen 2.5 7B, run through Ollama). Every technique ID is validated against the official MITRE ATT&CK dataset, and the result is written as JSON.


## Why did I chose the two models Llama and Qwen?

I chose Llama 3.1 8B and Qwen 2.5 7B because they’re comparable-sized open-source models from different companies (Meta and Alibaba), so the comparison is fair, and both run locally through Ollama with no API keys, so anyone can reproduce the results.

## How to run 

1. Install Python 3 and [Ollama](https://ollama.com).
2. Pull the models:
   ```bash
   ollama pull llama3.1:8b
   ollama pull qwen2.5:7b
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Download `enterprise-attack.json` from [MITRE's attack-stix-data repository](https://github.com/mitre-attack/attack-stix-data) (folder `enterprise-attack`) and place it next to `LLM Test programming main code.py`.
5. Make sure Ollama is running, then:
   ```bash
   python LLM Test programming main code.py
   ```

## Output files

- `final_output.json`: combined result from both models (main deliverable)
- `output_llama3.1_8b.json`, `output_qwen2.5_7b.json`: validated results per model
- `run1_baseline.txt`, `run2_technique_list.txt`, `run3_enriched.txt`: terminal logs from each prompt iteration

## Pipeline

1. **CVE input.** NVD descriptions, enriched with product type, CWE, attack vector, privileges required and user interaction from each CVE's NVD entry. The input never names an ATT&CK technique, so the mapping is still inferred by the LLM.
2. **MITRE loading.** Parses `enterprise-attack.json` and keeps only active techniques (type `attack-pattern`, not revoked or deprecated), building an ID to name lookup of 706 techniques including sub-techniques.
3. **LLM call.** Ollama `/api/chat` with JSON mode and temperature 0.
4. **Validation.** Each returned ID is checked against the MITRE lookup. Invalid or retired IDs are rejected and logged. For valid IDs the official MITRE name replaces the LLM's name, and every mismatch is logged. The technique link is built from the ID.
5. **Comparison and merge.** Both models' validated results are merged per CVE. Each technique records which models chose it, their self-reported confidence and justification, and an `agreement` field (`both` or `one`).

## Prompt design choices
Everytime I ran it there were some changes which gave a better output and the changes are listed below.
The prompt was improved over three runs:

| Run | Change | Effect |
|---|---|---|
| 1 | Role, task, rules, exact JSON example, cap of 3 techniques | Valid JSON, but invented or retired IDs (T1208, T1046.001) and real IDs paired with the wrong names. The models agreed on nothing. |
| 2 | Added the list of ~200 parent techniques (ID: name); the model must choose from it. Context window raised to 8192 | Zero invalid IDs and zero name mismatches. The picks were still poor: follow-up actions such as persistence and phishing, and WMI for a browser bug. |
| 3 | Enriched CVE descriptions, a rule against follow-up actions, and one worked example (CVE-2021-34527, the sample CVE from the brief, so no test answer leaks) | Both models chose T1068 for Zerologon, with plausible picks such as T1204 (User Execution) and T1552 (Unsecured Credentials). |

Other choices:
- JSON mode plus an exact example of the output shape, so every reply can be parsed the same way.
- The script, not the model, adds the `cve` key, the official technique name and the link, so those fields are always correct.
- Temperature 0 so results are reproducible.

## How accuracy was ensured

- **ID validation** against the official MITRE ATT&CK dataset, with revoked and deprecated techniques excluded.
- **Name correction:** small models often pair a real ID with the wrong name, so the official name is always used.
- **Constrained choice:** the model picks from the real technique list instead of recalling IDs from memory.
- **Cross-model agreement:** techniques chosen by both models are ranked first.
- **Manual check** against reference mappings:

| CVE | Reference mapping |
|---|---|
| CVE-2021-21148 (Chrome V8) | T1189 Drive-by Compromise, T1203 Exploitation for Client Execution |
| CVE-2020-1472 (Zerologon) | T1068 Exploitation for Privilege Escalation, T1210 Exploitation of Remote Services |
| CVE-2021-21975 (vROps SSRF) | T1190 Exploit Public-Facing Application, T1212 Exploitation for Credential Access |

## Challenges and limitations

- 8B models remember technique names better than IDs, which is what made validation and the constrained list necessary.
- The `confidence` field is generated text, not a computed probability. In run 1 it was a neat 0.9 / 0.8 / 0.7 countdown, and in run 2 Llama copied the 0.0 placeholder from the format example. Cross-model agreement is a more meaningful signal.
- Agreement does not guarantee correctness: both models chose T1047 (WMI) for the Chrome bug in run 2, and T1210 for it in run 3.
- Few-shot anchoring: after the example was added, Llama chose T1210 (one of the example's techniques) for all three CVEs.
- Qwen often ignored the negative instruction against follow-up actions.
- Only parent techniques are offered, to keep the prompt short, so sub-technique precision is lost.
- Not implemented, as future work: RAG retrieval over technique descriptions, and a retry when the output is incomplete.

## Key learnings for me 
This project taught me that we cannot always rely on a small LLM to give the correct answers, especially when it comes to matching things like CVEs and MITRE techniques. In my first attempt, both models gave me technique IDs that looked real but were actually made up, no longer in use, or matched with the wrong technique names.

I found that the best way to improve the results was to add more checks around the models. For example, I checked every technique ID against the official MITRE dataset, gave the models a list of valid IDs to choose from, and used extra information from NVD to help them make better decisions.

I also learned that just because a model says it is confident, it doesn't mean its answer is correct. Even if two different models give the same answer, it is still important to check it. Overall, this project helped me understand that using LLMs is not just about getting an answer from a model, but also making sure that the answer is actually correct.


## Sample output

```json
{
  "cve": "CVE-2020-1472",
  "techniques": [
    {
      "technique_id": "T1068",
      "technique_name": "Exploitation for Privilege Escalation",
      "link": "https://attack.mitre.org/techniques/T1068/",
      "chosen_by": ["llama3.1:8b", "qwen2.5:7b"],
      "llm_confidence": {"llama3.1:8b": 0.8, "qwen2.5:7b": 0.9},
      "justification": {
        "llama3.1:8b": "The attacker can take over the domain controller, which implies privilege escalation.",
        "qwen2.5:7b": "The vulnerability allows an attacker to establish a connection and take over the domain controller, which is a form of privilege escalation."
      },
      "agreement": "both"
    }


## RAG version (`rag.py`)

### What it does

The main version gives the LLM all ~200 ATT&CK technique names and asks it to choose. `rag.py` adds a retrieval step first:

1. Every parent technique's name and MITRE description is turned into an embedding with `nomic-embed-text` (run through Ollama). This is done once and cached in `technique_embeddings.json`.
2. Each CVE description is embedded the same way.
3. The 15 techniques with the highest cosine similarity to the CVE are kept as candidates.
4. Only those 15, with a short MITRE description of each, go into the prompt, and the model must choose from them.

Retrieval compares meaning rather than exact words. The Chrome CVE says "victim visits a malicious page", while MITRE's T1189 (Drive-by Compromise) describes a user visiting a website while browsing. They share few words, and T1189 still ranked first.

### How to run

```bash
ollama pull nomic-embed-text
python rag.py
```

The first run takes about a minute longer while it embeds the techniques. Delete `technique_embeddings.json` if you switch to a different `enterprise-attack.json`.

Outputs: `output_rag_llama3.1_8b.json`, `output_rag_qwen2.5_7b.json` and `final_output_rag.json`.

### Retrieval check

Every reference technique appeared in its CVE's top 15:

| CVE | Reference technique | Rank in retrieved list |
|---|---|---|
| CVE-2021-21148 | T1189 Drive-by Compromise | 1 |
| | T1203 Exploitation for Client Execution | 12 |
| CVE-2020-1472 | T1068 Exploitation for Privilege Escalation | 3 |
| | T1210 Exploitation of Remote Services | 11 |
| CVE-2021-21975 | T1190 Exploit Public-Facing Application | 1 |
| | T1212 Exploitation for Credential Access | 5 |

Retrieval found the right candidates every time, so any remaining errors come from the LLM's choice.

### Results

| CVE | Llama 3.1 8B | Qwen 2.5 7B | Both agree |
|---|---|---|---|
| CVE-2021-21148 | T1189, T1204 | T1185, T1203, T1606 | none |
| CVE-2020-1472 | T1068, T1210, T1548 | T1210, T1548 | T1210, T1548 |
| CVE-2021-21975 | T1190, T1212, T1539 | T1190, T1675 | T1190 |

Across both models, RAG found all 6 reference techniques, compared with 2 of 6 in the best run without retrieval. Llama alone found 5 of 6.

### My thoughts on the responses

**CVE-2021-21148 (Chrome).** Llama's answer is the one I'd give myself. T1189 describes how the victim is reached (visiting a malicious page), and T1204 reflects that the victim has to take that action. Qwen picked T1203, which is also correct, since the exploit runs code inside the browser. Its other two picks, Browser Session Hijacking and Forge Web Credentials, describe what an attacker might do afterwards, not what the vulnerability provides. The models agreed on nothing here even though both were partly right, so a lack of agreement doesn't always mean the answers are wrong.

**CVE-2020-1472 (Zerologon).** Llama's T1068 and T1210 match the reference. Both models also chose T1548 (Abuse Elevation Control Mechanism), which I think is a weaker fit: T1548 covers bypassing mechanisms like UAC or sudo, while Zerologon exploits a flaw in the Netlogon protocol itself. This is a case where the two models agreed on a technique that isn't the best answer, which shows that agreement raises confidence but doesn't prove correctness.

**CVE-2021-21975 (vRealize SSRF).** Both models chose T1190, which is the clearest mapping: a vulnerability in an internet-facing API. Llama added T1212, which fits because the stated goal is stealing administrative credentials. Its third pick, T1539 (Steal Web Session Cookie), is speculation, and its own justification admits it ("it's possible that..."). Qwen's T1675 (ESXi Administration Command) is a follow-up action: it assumes the stolen credentials are later used on an ESXi host.

**Overall.** Llama was more precise, and Qwen was more speculative and followed the "no follow-up actions" rule less reliably. A pattern I noticed is that the weak picks tend to have hedging justifications, with words like "potentially", "it's possible" or "if the stolen credentials are used". The strong picks are stated directly. That could be the basis for a future filter that flags or drops hedged picks automatically.
  ]
}
```
