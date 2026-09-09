import os
import requests
from stix2 import MemoryStore

OUTPUT_DIR = "/home/betrayedchair/soc-testing/Ai/rag/data/knowledge_base/mitre"
os.makedirs(OUTPUT_DIR, exist_ok=True)

url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

print("Downloading MITRE ATT&CK dataset...")
data = requests.get(url).json()

store = MemoryStore(stix_data=data["objects"])

techniques = store.query([
    {
        "type": "attack-pattern"
    }
])

count = 0

for technique in techniques:

    if technique.get("revoked", False):
        continue

    if technique.get("x_mitre_deprecated", False):
        continue

    attack_id = "UNKNOWN"

    for ref in technique.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            attack_id = ref.get("external_id")
            break

    name = technique.get("name", "Unknown")
    description = technique.get("description", "No description.")

    tactics = technique.get("kill_chain_phases", [])

    tactic_list = []

    for t in tactics:
        tactic_list.append(t.get("phase_name"))

    filename = os.path.join(
        OUTPUT_DIR,
        f"{attack_id}.md"
    )

    with open(filename, "w", encoding="utf-8") as f:

        f.write(f"# {attack_id} - {name}\n\n")

        f.write("## Description\n\n")
        f.write(description + "\n\n")

        f.write("## ATT&CK Tactics\n\n")

        if tactic_list:
            for tactic in tactic_list:
                f.write(f"- {tactic}\n")
        else:
            f.write("No tactics available.\n")

    count += 1

print(f"\nGenerated {count} MITRE knowledge files.")