"""Inject data/ai-security.json into the dashboard as seed data so it works from disk or any static host."""
import json, pathlib
root = pathlib.Path(__file__).parent
data = json.loads((root / "data/ai-security.json").read_text())
html = (root / "src/dashboard.html").read_text()
seed = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
(root / "index.html").write_text(html.replace("/*__SEED__*/", seed))
print("built index.html with", len(data["advisories"]), "advisories")
