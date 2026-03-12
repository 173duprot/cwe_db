# CWE Database Builder

A lightweight, efficient tool for extracting and organizing vulnerable code samples from security testing datasets into SQLite databases. Built for AI security research, this library uses tree-sitter for precise AST-based code parsing and supports multiple vulnerability dataset formats.

## Features

- **Multi-dataset support**: Juliet Test Suite, Devign, BugsInPy
- **AST-based parsing**: Accurate function extraction using tree-sitter
- **Multi-language**: C, C++, Java, Python, C#
- **Deduplication**: Built-in simhash-based similarity detection
- **Vulnerability tracking**: Preserves line-level flaw annotations

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install git+https://github.com/173duprot/cwe_db.git
```

## Quick Start

### Command Line

```bash
cwe_db ./output.db ./manifest.xml ./testcases --min-lines 6
```

### Python API

```python
import cwe_db

# Initialize database
db = cwe_db.CWE_DB("vulnerabilities.db")

# Process Juliet Test Suite
db.juliet("./testcases", min_lines=6)

# Commit and close
db.commit().close()
```

## Usage Examples

### Processing Juliet Test Suite

The Juliet Test Suite contains synthetic test cases for various CWE categories. Extract functions with vulnerability annotations:

```python
from cwe_db import CWE_DB

# Create database and process Juliet dataset
db = CWE_DB("juliet.db")
db.juliet(
    src="./testcases",      # Path to Juliet testcases directory
    min_lines=6             # Minimum function length (filters trivial functions)
)
db.commit().close()

# Database schema:
# funcs(grp, id, start, end, vuln, code, len)
# - grp: CWE identifier (e.g., "CWE121")
# - id: Source filename
# - start/end: Line numbers in original file
# - vuln: Comma-separated vulnerable line numbers (relative to function start)
# - code: Complete function source code
# - len: Number of lines in function
```

### Processing Devign Dataset

Devign contains real-world vulnerabilities from open-source projects:

```python
db = CWE_DB("devign.db")
db.devign("devign.json")  # Process Devign JSON dataset
db.commit().close()
```

### Processing BugsInPy

BugsInPy provides Python bug datasets with patch information:

```python
db = CWE_DB("bugsinpy.db")
db.bugsinpy("./projects")  # Path to BugsInPy projects directory
db.commit().close()
```

### Deduplication with Simhash

Remove near-duplicate functions using locality-sensitive hashing. This is crucial for preventing data leakage in train/test splits:

```python
db = CWE_DB("dataset.db")
db.juliet("./testcases", min_lines=6)

# Remove duplicates with Hamming distance ≤ 3
db.simhash(k=3)  # k: maximum bit differences to consider duplicates

db.close()
```

**How simhash works:**

1. **Tokenization**: Each function is split into tokens (words)
2. **Hashing**: Each token is hashed using MD5 to a 64-bit fingerprint
3. **Weighted accumulation**: For each bit position, accumulate +1 if bit is set, -1 if not
4. **Fingerprint generation**: Final hash has bit set if accumulated value > 0
5. **Similarity detection**: Functions with Hamming distance ≤ k are considered duplicates

The algorithm runs in O(n) time and provides approximate similarity detection suitable for large datasets. Lower k values (1-3) catch near-exact duplicates, while higher values (4-8) catch more semantic similarity.

### Chaining Operations

All methods return `self` for convenient chaining:

```python
(CWE_DB("combined.db")
    .juliet("./juliet_testcases", min_lines=6)
    .devign("./devign.json")
    .simhash(k=3)
    .commit()
    .close())
```

### Querying the Database

```python
import sqlite3

conn = sqlite3.connect("vulnerabilities.db")
cursor = conn.cursor()

# Get all vulnerable functions from a specific CWE
cursor.execute("""
    SELECT grp, id, code, vuln 
    FROM funcs 
    WHERE grp = 'CWE121' AND vuln IS NOT NULL
""")

for cwe, filename, code, vuln_lines in cursor.fetchall():
    print(f"{cwe} in {filename}, vulnerable lines: {vuln_lines}")
    print(code[:200])  # First 200 chars
    print("---")

conn.close()
```

## Supported Languages

- C (`.c`, `.h`)
- C++ (`.cpp`, `.hpp`, `.cxx`, `.cc`)
- Java (`.java`)
- Python (`.py`)
- C# (`.cs`)

## Database Schema

```sql
CREATE TABLE funcs (
    grp TEXT,      -- CWE/project identifier
    id TEXT,       -- File or commit identifier
    start INT,     -- Starting line number
    end INT,       -- Ending line number
    vuln TEXT,     -- Vulnerable line numbers (comma-separated, relative to function)
    code TEXT,     -- Complete function source code
    len INT        -- Number of lines in function
);
```

## License

GPL-3.0

## Citation

If you use this tool in your research, please cite the relevant datasets:

- **Juliet Test Suite**: NIST Software Assurance Reference Dataset
- **Devign**: Zhou et al., "Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks"
- **BugsInPy**: Widyasari et al., "BugsInPy: A Database of Existing Bugs in Python Programs"
