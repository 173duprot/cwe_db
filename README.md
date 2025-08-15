# cwe_db

Simple Juliet -> Sqlite Packer

## Install

```
pip install git+https://github.com/173duprot/cwe_db.git
```

## Usage
```py
from tinycwe import cwe_db
cwe_db("out.db", "manifest.xml", "/path/to/repo", min_lines=6)
```
