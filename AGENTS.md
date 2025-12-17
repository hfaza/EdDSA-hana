# Agent Change Log

## 2023-10-27: Gemini

- **Removed Document Preview Feature:**
    - Deleted the `_generate_docx_preview` and related HTML rendering functions from `signer/utils.py`.
    - Removed the associated preview logic and context variables from the `home` view in `signer/views.py`.
    - Deleted the document preview section from the `signer/templates/signer/home.html` template.
- **Removed .DS_Store from git:**
    - Added `.DS_Store` to `.gitignore` to prevent Mac-specific files from being committed.

# Repository Guidelines

## Project Structure & Module Organization
- The root currently holds `eddsa.ipynb`, the interactive workspace for EdDSA exploration.
- `README.md` tracks the high-level vision; expand it as features mature.
- Add reusable Python modules under `src/` (create the folder when needed) and mirror tests in `tests/`.
- Keep datasets or supporting assets in `data/` or `assets/` so notebooks remain reproducible across machines.

## Build, Test, and Development Commands
- `python3 -m venv .venv && source .venv/bin/activate` creates an isolated environment for notebook work.
- `pip install -r requirements.txt` installs dependencies once the list is curated; align notebook imports with this file.
- `jupyter lab` (or `jupyter notebook`) launches the UI for editing `eddsa.ipynb`.
- `jupyter nbconvert --execute eddsa.ipynb --to notebook --output eddsa-run.ipynb` runs the notebook headlessly and verifies all cells execute cleanly.

## Coding Style & Naming Conventions
- Follow PEP 8: 4-space indentation, `snake_case` functions, `PascalCase` classes, and `UPPERCASE` constants.
- Prefer reusable helpers in `src/` and import them into notebook cells to keep the notebook concise.
- Use Markdown cells to explain derivations; clear bulky outputs before committing (e.g., `jupyter nbstripout eddsa.ipynb`).

## Testing Guidelines
- Add unit tests with `pytest`; name files `tests/test_<module>.py` and align fixtures with curve parameters.
- Mirror notebook computations in tests so algorithm tweaks remain verifiable outside the notebook.
- Run `pytest -q` locally and aim for coverage on key scalar multiplication, signature, and verification helpers before merging.

## Commit & Pull Request Guidelines
- Start commit messages with imperative verbs (`Add key generation helper`) and keep the summary line under 72 characters.
- Keep commits focused: code, tests, and updated notebooks that belong together should land together.
- Pull requests need a short description, explicit verification steps (`pytest -q`, nbconvert run), and links to related issues.
- Attach screenshots or output snippets when visualizations or metrics change to help reviewers validate results quickly.