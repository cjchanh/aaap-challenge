from pathlib import Path
Path(__file__).resolve().parent.parent.parent.joinpath(
    'STATIC_IMPORT_EXECUTED'
).write_text('unsealed module executed before inventory\n', encoding='utf-8')
