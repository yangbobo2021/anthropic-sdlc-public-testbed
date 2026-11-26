from pathlib import Path
import json
import sys

mode, case = sys.argv[1:]
paths = {"api":("api/status.txt","API_OK"), "client":("client/status.txt","CLIENT_OK"),
         "integration":("tests/integration/status.txt","INTEGRATION_OK"), "unit":("api/status.txt","API_OK")}
file, expected = paths[case]
assert Path(file).read_text().splitlines()[0] == expected
if mode == "full" and not (case == "integration" and Path("tests/no-integration-coverage").exists()):
    out = Path("artifacts")
    out.mkdir(exist_ok=True)
    (out / f"coverage-{case}.json").write_text(json.dumps({"group":case,"source_file":file,"success":True}) + "\n")
