from pathlib import Path

Path(__file__).with_name("sitecustomize-executed").write_text("executed\n", encoding="utf-8")
