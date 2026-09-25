import re
from pathlib import Path

content = Path("dashboard/prototype_console.html").read_text(encoding="utf-8")
navs = re.findall(r'data-section="([^"]+)"', content)
sections = [m for m in re.findall(r'<section[^>]+id="([^"]+)"', content)]

print("Prototype Nav items:", navs)
print("Prototype Section IDs:", sections)
