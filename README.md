# cwe_db

Simple Juliet -> Sqlite Packer

## Install

```
python -m venv .venv
source .venv/bin/activate
pip install git+https://github.com/173duprot/cwe_db.git
```

## Usage

```py
import cwe_db
cwe_db.record("out.db", "manifest.xml", "./testcases", min_lines=6)
```

or

```sh
cwe_db ./out.db ./manifest.xml ./testcases --min-lines 6
```
