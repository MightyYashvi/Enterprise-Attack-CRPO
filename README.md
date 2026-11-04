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
  ]
}
```
