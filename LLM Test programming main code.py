
#storing the three cve in format of dictionary
#enriched form of the cve description with product type, weakness, attack vector, user interaction, privileges required and impact
cve = {
    "CVE-2021-21148": (
        "Heap buffer overflow in V8 in Google Chrome prior to 88.0.4324.150 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. "
        "Product type: web browser. Weakness: CWE-787 (out-of-bounds write). "
        "Attack vector: network. User interaction: required (victim visits a malicious page)."
    ),
    "CVE-2020-1472": (
        "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon "
        "secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC). "
        "Also known as Zerologon. Product type: Windows domain controller. Weakness: CWE-330 (insufficiently random values). "
        "Attack vector: network. Privileges required: none. Impact: attacker can take over the domain controller."
    ),
    "CVE-2021-21975": (
        "Server Side Request Forgery in vRealize Operations Manager API prior to 8.4 may allow a malicious actor "
        "with network access to the API to perform a Server Side Request Forgery attack to steal administrative credentials. "
        "Product type: internet-facing web application/API. Weakness: CWE-918 (SSRF). "
        "Attack vector: network. Privileges required: none."
    ),
}


# loading the mitre file in json format
import json

with open ("enterprise-attack.json",encoding="utf-8") as f:  # read the file and f is nickname , encoding for special char in mitre
    data=json.load(f)
# reading the whole file and converting into python dictionary in data
mitre={}
for obj in data["objects"]: # list of everything in ATTACK
    # 1. skip anything that isn't a technique
    if obj.get("type") != "attack-pattern":
        continue

    # 2. skip anything revoked or deprecated , retired old techniques
    if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
        continue

    # 3. find the ID inside obj["external_references"] , has to be mitre attack
    technique_id = None
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            technique_id = ref.get("external_id")
            break

    # 4. add ID -> name to mitre
    if technique_id:
        mitre[technique_id] = obj["name"]

print(len(mitre))
print(mitre["T1068"])
print("T9999" in mitre)


# list of parent techniques only (no sub-techniques like T1059.001) to keep the prompt short
technique_list = "\n".join(f"{tid}: {name}" for tid, name in mitre.items() if "." not in tid)

import requests  # allows the python to tlak to internet and the ollama


def ask_llm(model,prompt): # function to ask the ollama model to carry it for every cve
     # send data to the above address ,which is ollamas address, handle chat style questions,json is the data we are sending

    response =requests.post("http://localhost:11434/api/chat",
                            json = { "model":model,                 #tells ollama which model should be answered

                                    "messages": [{"role": "user", "content": prompt}],      #the converstaion as a list of messages, and text of q as content
                                                                                            #add a "system" message here to give the model instructions.
                                    "stream": False ,# wait and send the whole answer once
                                    "format": "json",# to get the answer in json format, so we can convert it into python dictionary
                                      "options": {"temperature": 0, "num_ctx": 8192}   # randomness of the answer = 0 and num_ctx = 8192 is the context window size, how much text the model can see at once
                            } )
    return response.json()["message"]["content"] # return the answer from the model
    # ollama returns in json so .json() converts it into python dictionary

def build_prompt(cve_id,description): # function that takes a cve id and its description . # f for replacing with actual valus
    prompt=f"""
    So you are a security analyst who knows MITRE ATT&CK framework a nd you are given a CVE ID and its description. Your task is to identify the most relevant
    MITRE ATT&CK technique(s) an attacker would use when exploiting this CVE.

    Rules:
- Return up to 3 techniques, most relevant first.
- Choose ONLY from the list of valid techniques below. Copy the ID and name exactly. Do not invent IDs.
- - Only pick techniques the attacker achieves directly by exploiting this vulnerability (how they get in, run code, escalate privileges or steal credentials). Do NOT pick follow-up actions like persistence, discovery or phishing.
- If no relevant technique can be identified, return an empty list: {{"techniques": []}}
- Respond in JSON only, with no text before or after it.

Valid MITRE ATT&CK techniques (ID: name):
{technique_list}

Use exactly this JSON format:
{{
  "techniques": [
    {{
      "technique_id": "T0000",
      "technique_name": "Technique name",
      "confidence": 0.0,
      "justification": "One or two sentences linking the CVE to this technique."
    }}
  ]
}}

Example for a different CVE:
CVE: CVE-2021-34527
Description: Windows Print Spooler remote code execution vulnerability (PrintNightmare). An authenticated attacker can exploit the Print Spooler service to run code with SYSTEM privileges. Attack vector: network.
Answer:
{{
  "techniques": [
    {{"technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation", "confidence": 0.9, "justification": "Exploiting the Print Spooler flaw lets the attacker run code as SYSTEM, which is privilege escalation."}},
    {{"technique_id": "T1210", "technique_name": "Exploitation of Remote Services", "confidence": 0.6, "justification": "The flaw is triggered over the network against the Spooler service on a remote host."}}
  ]
}}
confidence is a number from 0 to 1 showing how sure you are of the mapping.

    CVE:{cve_id}
    Description:{description}
    """
    return prompt   # hand the finished text back to whoever called the function




def validate(cve_id, raw):  # turns the model's raw reply into one clean entry for the final JSON
    try:
        parsed = json.loads(raw)  # text -> Python dictionary
    except json.JSONDecodeError:  # model returned broken JSON
        print(f"[{cve_id}] model did not return valid JSON")
        return {"cve": cve_id, "techniques": []}  # return an empty entry so the program keeps running

    kept = []  # techniques that pass validation go here
    for t in parsed.get("techniques", []):  # .get so a missing key gives an empty list, not a crash
        tid = str(t.get("technique_id", "")).strip().upper()  # clean the ID: " t1210 " -> "T1210"

        if tid in mitre:  # real, current ATT&CK technique
            # if the model's name is different from MITRE's official name, print both for safety
            if t.get("technique_name") != mitre[tid]:
                print(f"[{cve_id}] {tid}: model said '{t.get('technique_name')}', MITRE says '{mitre[tid]}'")
            kept.append({
                "technique_id": tid,
                "technique_name": mitre[tid],  # official name from MITRE, not the model's guess
                "link": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",  # T1059.001 -> T1059/001
                "confidence": t.get("confidence"),
                "justification": t.get("justification"),
            })
        else:
            print(f"[{cve_id}] rejected {tid}: not a valid ATT&CK ID")  # log what was thrown out

    return {"cve": cve_id, "techniques": kept}  # final format, with "cve" added by your code

MODELS = ["llama3.1:8b", "qwen2.5:7b"]  # the two LLMs to compare

all_results = {}  # model name -> its list of CVE entries

for model in MODELS:  # outer loop: one pass per model
    results = []  # this model's entries for all 3 CVEs
    for cve_id, description in cve.items():  # inner loop: each CVE ID and its description
        print(f"Running {model} on {cve_id}...")
        raw = ask_llm(model, build_prompt(cve_id, description))  # build the prompt and ask the model
        results.append(validate(cve_id, raw))  # validate, then add the clean entry to the list
    all_results[model] = results  # remember this model's results for the comparison

    filename = f"output_{model.replace(':', '_')}.json"  # "llama3.1:8b" -> "output_llama3.1_8b.json"
    with open(filename, "w", encoding="utf-8") as f:  # "w" = write mode
        json.dump(results, f, indent=2)  # write the list into the file
    print(f"Saved {filename}")


print("\nComparision of the two models' results:")
for i, cve_id in enumerate(cve):  # i = 0, 1, 2 and cve_id = each CVE
    ids = {}  # model name -> set of technique IDs it found for this CVE
    for model in MODELS:
        ids[model] = {t["technique_id"] for t in all_results[model][i]["techniques"]}
    both = ids[MODELS[0]] & ids[MODELS[1]]  # IDs that appear in both sets

    print(cve_id)
    for model in MODELS:
        print(f"  {model}: {sorted(ids[model])}")
    print(f"  both agree on: {sorted(both)}")


#combining both models in a single JSON file, so we can see which techniques both models picked and which only one model picked

final = []  # the final JSON array, one entry per CVE

for i, cve_id in enumerate(cve):  # i = position (0, 1, 2), same order both models ran in
    merged = {}  # technique ID -> combined entry, so a technique both models picked appears once

    for model in MODELS:
        for t in all_results[model][i]["techniques"]:  # each validated technique this model gave
            tid = t["technique_id"]
            if tid not in merged:  # first time we see this ID, create its entry
                merged[tid] = {
                    "technique_id": tid,
                    "technique_name": t["technique_name"],
                    "link": t["link"],
                    "chosen_by": [],       # which models picked it
                    "llm_confidence": {},  # each model's self-reported confidence
                    "justification": {},   # each model's reasoning
                }
            merged[tid]["chosen_by"].append(model)
            merged[tid]["llm_confidence"][model] = t["confidence"]
            merged[tid]["justification"][model] = t["justification"]

    techniques = list(merged.values())  # turn the dictionary into a list
    for entry in techniques:
        entry["agreement"] = "both" if len(entry["chosen_by"]) == len(MODELS) else "one"  # your own confidence signal
    techniques.sort(key=lambda e: len(e["chosen_by"]), reverse=True)  # techniques both models chose go first

    final.append({"cve": cve_id, "techniques": techniques})

with open("final_output.json", "w", encoding="utf-8") as f:
    json.dump(final, f, indent=2)
print("Saved final_output.json")
