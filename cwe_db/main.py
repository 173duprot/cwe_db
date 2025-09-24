import sqlite3, json, unidiff, xml.etree.ElementTree as ET
from git import Repo
from pathlib import Path
from tree_sitter import Query, QueryCursor
from tree_sitter_language_pack import get_language, get_parser

class CVE_DB:
    def __init__(s,db):
        s.db=sqlite3.connect(db); s.cur=s.db.cursor()
        s.cur.execute("CREATE TABLE IF NOT EXISTS funcs (grp TEXT,id TEXT,start INT,end INT,vuln TEXT,code TEXT,PRIMARY KEY(grp,id,vuln))")
    def commit(s): s.db.commit(); return s
    def close(s): s.db.close()

    def devign(s,src):
        # Extract
        for x in json.load(open(src)):
            if all(k in x for k in ("project","commit_id","target","func")):
                s.cur.execute("INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?)",
                    (x["project"],x["commit_id"],None,None,str(x["target"]),x["func"])) # Record
        return s

    def juliet(s,src,min_lines=6):
        # Files
        for f in Path(src).rglob("*"):
            if not(f.is_file() and f.suffix in CVE_DB.CODE.LANGS): continue

            # Extract
            cve=f.stem.split("_",1)[0] if "_" in f.stem else f.stem
            code=CVE_DB.CODE(f.suffix,f.read_bytes())

            # Find
            flaw_lines=set()
            for n in code.query(code.cmt):
                comment=n.text.decode("utf-8","ignore")
                if "POTENTIAL FLAW" in comment:
                    sib = n.next_named_sibling
                    while sib and sib.type == "comment":
                        sib = sib.next_named_sibling
                    if sib:
                        s0, e0 = sib.start_point[0] + 1, sib.end_point[0] + 1
                        flaw_lines.update(range(s0, e0 + 1))
                code.strip(n) # clean

            # Record
            for n in code.query(code.fn):
                s0,e0=n.start_point[0]+1,n.end_point[0]+1
                if e0-s0+1<min_lines: continue
                vulns=[str(l-(s0-1))for l in flaw_lines if s0<=l<=e0]
                s.cur.execute("INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?)",
                    (cve,f.name,s0,e0,",".join(vulns) if vulns else None,
                     n.text.decode("utf-8","ignore")))
        return s

    def bugsinpy(s,src):
        # Extract
        for p in Path(src).rglob("bug.info"):
            info={k:v.strip().strip('"') for k,v in (l.split("=",1) for l in p.read_text().splitlines())}
            proj_info={k:v.strip().strip('"') for k,v in (l.split("=",1) for l in (p.parents[2]/"project.info").read_text().splitlines())}
            project_name=Path(proj_info["github_url"]).stem

            # Clone
            repo_path=Path(f"/tmp/{project_name}")
            try: repo=Repo.clone_from(proj_info["github_url"],repo_path)
            except: repo=Repo(repo_path) if repo_path.exists() else (print(project_name,"clone fail") or None)
            try: repo.git.checkout(info["buggy_commit_id"]); print(project_name,info["buggy_commit_id"],"ok")
            except: print(project_name,info["buggy_commit_id"],"fail"); continue

            # Files
            for f in unidiff.PatchSet.from_filename(p.parent/"bug_patch.txt",encoding="utf-8"):
                if Path(f.path).suffix not in CVE_DB.CODE.LANGS: continue
                code=CVE_DB.CODE(Path(f.path).suffix,(repo_path/f.path).read_bytes())

                # Clean
                for n in code.query(code.cmt): code.strip(n)

                # Record
                for n in code.query(code.fn):
                    s0,e0=n.start_point[0]+1,n.end_point[0]+1
                    vuln=any(h.target_start<=s0<=h.target_start+h.target_length or s0<=h.target_start<=e0 for h in f)
                    s.cur.execute("INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?)",
                        (project_name,f"{info['buggy_commit_id']}/{f.path}",s0,e0,"1" if vuln else "0",n.text.decode("utf-8","ignore")))
        return s

    class CODE:
        def __init__(s,ext,code):
            s.lang,s.parser,s.fn,s.cmt=CVE_DB.CODE.LANGS[ext]; s.code=code

        def query(s,q):
            for nodes in QueryCursor(Query(s.lang,q)).captures(s.parser.parse(s.code).root_node).values():
                for n in nodes: yield n

        def strip(s,n):
            s.code=(
                s.code[:n.start_byte]
                +bytes((ch if ch==10 else 32)for ch in s.code[n.start_byte:n.end_byte])
                +s.code[n.end_byte:]
            )
            return s

        LANGS={ext:(get_language(l),get_parser(l),fn,cmt)for l,exts,fn,cmt in[
            ('c',['.c','.h'],'(function_definition) @f','(comment) @c'),
            ('cpp',['.cpp','.hpp','.cxx','.cc'],'(function_definition) @f','(comment) @c'),
            ('java',['.java'],'(method_declaration) @f','[(line_comment)(block_comment)] @c'),
            ('python',['.py'],'(function_definition) @f','(comment) @c'),
            ('csharp',['.cs'],'(method_declaration) @f','(comment) @c')
        ]for ext in exts}
