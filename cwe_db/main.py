import sqlite3
import json
import unidiff
import xml.etree.ElementTree as ET
from git import Repo
from pathlib import Path
from tree_sitter import Query, QueryCursor
from tree_sitter_language_pack import get_language, get_parser


class CWE_DB:
    def __init__(self, db):
        self.db = sqlite3.connect(db)
        self.cur = self.db.cursor()
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS funcs (
                grp TEXT,
                id TEXT,
                start INT,
                end INT,
                vuln TEXT,
                code TEXT,
                len INT
            )
        """)

    def commit(self):
        self.db.commit()
        return self

    def close(self):
        self.db.close()

    def devign(self, src):
        """Load Devign dataset from JSON file."""
        data = json.load(open(src))
        
        for entry in data:
            required_keys = ("project", "commit_id", "target", "func")
            if not all(key in entry for key in required_keys):
                continue
            
            func = entry["func"]
            self.cur.execute(
                "INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?,?)",
                (
                    entry["project"],
                    entry["commit_id"],
                    None,
                    None,
                    str(entry["target"]),
                    func,
                    len(func.splitlines())
                )
            )
        
        return self

    def juliet(self, src, min_lines=6):
        """Load Juliet test suite, extracting functions with FLAW comments."""
        for file_path in Path(src).rglob("*"):
            if not (file_path.is_file() and file_path.suffix in CWE_DB.CODE.LANGS):
                continue

            cve = file_path.stem.split("_", 1)[0] if "_" in file_path.stem else file_path.stem
            code = CWE_DB.CODE(file_path.suffix, file_path.read_bytes())

            # Find lines marked with FLAW comments
            flaw_lines = set()
            for node in code.query(code.cmt):
                comment = node.text.decode("utf-8", "ignore")
                
                if "FLAW" in comment:
                    # Find the next non-comment sibling
                    sibling = node.next_named_sibling
                    while sibling and sibling.type == "comment":
                        sibling = sibling.next_named_sibling
                    
                    if sibling:
                        start_line = sibling.start_point[0] + 1
                        end_line = sibling.end_point[0] + 1
                        flaw_lines.update(range(start_line, end_line + 1))
                
                code.strip(node)

            # Extract functions and record them
            for node in code.query(code.fn):
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                
                if end_line - start_line + 1 < min_lines:
                    continue
                
                # Find which flaw lines are within this function
                vulns = [
                    str(line - (start_line - 1))
                    for line in flaw_lines
                    if start_line <= line <= end_line
                ]
                
                func = node.text.decode("utf-8", "ignore")
                self.cur.execute(
                    "INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?,?)",
                    (
                        cve,
                        file_path.name,
                        start_line,
                        end_line,
                        ",".join(vulns) if vulns else None,
                        func,
                        len(func.splitlines())
                    )
                )
        
        return self

    def bugsinpy(self, src):
        """Load BugsInPy dataset by cloning repos and analyzing patches."""
        for bug_info_path in Path(src).rglob("bug.info"):
            # Parse bug.info file
            info = {
                key: value.strip().strip('"')
                for key, value in (
                    line.split("=", 1)
                    for line in bug_info_path.read_text().splitlines()
                )
            }
            
            # Parse project.info file
            project_info_path = bug_info_path.parents[2] / "project.info"
            proj_info = {
                key: value.strip().strip('"')
                for key, value in (
                    line.split("=", 1)
                    for line in project_info_path.read_text().splitlines()
                )
            }
            
            project_name = Path(proj_info["github_url"]).stem
            repo_path = Path(f"/tmp/{project_name}")

            # Clone or reuse repository
            try:
                repo = Repo.clone_from(proj_info["github_url"], repo_path)
            except:
                if repo_path.exists():
                    repo = Repo(repo_path)
                else:
                    print(project_name, "clone fail")
                    continue
            
            # Checkout buggy commit
            try:
                repo.git.checkout(info["buggy_commit_id"])
                print(project_name, info["buggy_commit_id"], "ok")
            except:
                print(project_name, info["buggy_commit_id"], "fail")
                continue

            # Process patch file
            patch_path = bug_info_path.parent / "bug_patch.txt"
            patch_set = unidiff.PatchSet.from_filename(patch_path, encoding="utf-8")
            
            for patched_file in patch_set:
                if Path(patched_file.path).suffix not in CWE_DB.CODE.LANGS:
                    continue
                
                file_path = repo_path / patched_file.path
                code = CWE_DB.CODE(Path(patched_file.path).suffix, file_path.read_bytes())

                # Remove comments
                for node in code.query(code.cmt):
                    code.strip(node)

                # Extract functions and check if they overlap with patch hunks
                for node in code.query(code.fn):
                    start_line = node.start_point[0] + 1
                    end_line = node.end_point[0] + 1
                    
                    # Check if function overlaps with any hunk in the patch
                    vuln = any(
                        hunk.target_start <= start_line <= hunk.target_start + hunk.target_length
                        or start_line <= hunk.target_start <= end_line
                        for hunk in patched_file
                    )
                    
                    func = node.text.decode("utf-8", "ignore")
                    self.cur.execute(
                        "INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?,?)",
                        (
                            project_name,
                            f"{info['buggy_commit_id']}/{patched_file.path}",
                            start_line,
                            end_line,
                            "1" if vuln else "0",
                            func,
                            len(func.splitlines())
                        )
                    )
        
        return self

    def simhash(self, k=3):
        """Remove near-duplicate functions using simhash with Hamming distance."""
        import hashlib
        
        def compute_hash(code):
            """Compute 64-bit simhash for code."""
            vector = [0] * 64
            
            for word in code.split():
                digest = int(hashlib.md5(word.encode()).hexdigest(), 16)
                for i in range(64):
                    vector[i] += 1 if (digest >> i) & 1 else -1
            
            return sum(1 << i for i in range(64) if vector[i] > 0)
        
        seen = []
        to_remove = []
        
        for rowid, code in self.cur.execute("SELECT rowid, code FROM funcs").fetchall():
            hash_value = compute_hash(code)
            
            # Check if similar to any seen hash (Hamming distance <= k)
            if any((hash_value ^ seen_hash).bit_count() <= k for seen_hash in seen):
                to_remove.append(rowid)
            else:
                seen.append(hash_value)
        
        if to_remove:
            placeholders = ",".join(map(str, to_remove))
            self.cur.execute(f"DELETE FROM funcs WHERE rowid IN ({placeholders})")
        
        return self.commit()

    class CODE:
        """Helper class for parsing code files with tree-sitter."""
        
        def __init__(self, ext, code):
            self.lang, self.parser, self.fn, self.cmt = CWE_DB.CODE.LANGS[ext]
            self.code = code

        def query(self, query_string):
            """Execute a tree-sitter query and yield matching nodes."""
            query = Query(self.lang, query_string)
            cursor = QueryCursor(query)
            tree = self.parser.parse(self.code)
            captures = cursor.captures(tree.root_node)
            
            for nodes in captures.values():
                for node in nodes:
                    yield node

        def strip(self, node):
            """Replace a node's text with whitespace, preserving newlines."""
            self.code = (
                self.code[:node.start_byte]
                + bytes((ch if ch == 10 else 32) for ch in self.code[node.start_byte:node.end_byte])
                + self.code[node.end_byte:]
            )
            return self

        LANGS = {
            ext: (get_language(lang), get_parser(lang), fn_query, cmt_query)
            for lang, exts, fn_query, cmt_query in [
                ('c', ['.c', '.h'], '(function_definition) @f', '(comment) @c'),
                ('cpp', ['.cpp', '.hpp', '.cxx', '.cc'], '(function_definition) @f', '(comment) @c'),
                ('java', ['.java'], '(method_declaration) @f', '[(line_comment)(block_comment)] @c'),
                ('python', ['.py'], '(function_definition) @f', '(comment) @c'),
                ('csharp', ['.cs'], '(method_declaration) @f', '(comment) @c')
            ]
            for ext in exts
        }

