from pathlib import Path

print(Path(__file__).with_name("sitecustomize-executed").exists())
