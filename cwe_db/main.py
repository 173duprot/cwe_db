import sqlite3, json, unidiff, xml.etree.ElementTree as ET
from git import Repo
from pathlib import Path
from tree_sitter import Query, QueryCursor
from tree_sitter_language_pack import get_language, get_parser

class CVE_DB:
    def __init__(s,db):
        s.db=sqlite3.connect(db); s.cur=s.db.cursor()
        s.cur.execute("CREATE TABLE IF NOT EXISTS funcs (cve TEXT,file TEXT,start INT,end INT,vuln TEXT,code TEXT,PRIMARY KEY(cve,file))")
    def commit(s): s.db.commit(); return s
    def close(s): s.db.close()

    def devign(s,src):
        # Extract
        for x in json.load(open(src)):
            if all(k in x for k in ("project","commit_id","target","func")):
                s.cur.execute("INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?)",
                    (x["project"],x["commit_id"],None,None,str(x["target"]),x["func"])) # Record
        return s

    def juliet(s,src,root,min_lines=6):
        # Extract
        manifest={f.get("path"):(flaws[0].get("name"),[int(n.get("line"))for n in flaws if n.get("line")])
                  for f in ET.parse(src).iter("file") if (flaws:=f.findall("flaw"))}
        # Files
        for f in Path(root).rglob("*"):
            if not(f.is_file() and f.suffix in CVE_DB.CODE.LANGS and f.name in manifest): continue # is valid?

            # Fetch
            cve,lines=manifest[f.name]
            code=CVE_DB.CODE(f.suffix,f.read_bytes()).strip() # Clean

            # Record
            for n in code.captures("fn"): # Record
                s0,e0=n.start_point[0]+1,n.end_point[0]+1
                if e0-s0+1<min_lines: continue
                vulns=[str(l-(s0-1))for l in lines if s0<=l<=e0]
                s.cur.execute("INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?)",
                    (cve,f.name,s0,e0,",".join(vulns)if vulns else None,n.text.decode("utf-8","ignore")))
        return s

    def bugsinpy(s,src):
        # Extract
        for p in Path(src).rglob("bug.info"):
            info = dict(l.split("=", 1) for l in p.read_text().splitlines())
            info = {k: v.strip('"') for k, v in info.items()}
            proj_info = dict(l.split("=", 1) for l in (p.parents[2] / "project.info").read_text().splitlines())
            proj_info = {k: v.strip('"') for k, v in proj_info.items()}

            # Fetch
            repo_path = Path(f"/tmp/{info['project_name']}")
            repo = Repo.clone_from(proj_info["github_url"], repo_path) if not repo_path.exists() else Repo(repo_path)
            repo.git.checkout(info["buggy_commit_id"])

            # Record
            for f in unidiff.PatchSet.from_filename(p.parent / "bug.patch", encoding='utf-8'):
                if not Path(f.path).suffix in CVE_DB.CODE.LANGS: continue
                code = CVE_DB.CODE(Path(f.path).suffix, (repo_path / f.path).read_bytes()).strip()
                for n in code.captures("fn"):
                    s_line, e_line = n.start_point[0] + 1, n.end_point[0] + 1
                    if any(h.target_start <= s_line <= h.target_start + h.target_length or s_line <= h.target_start <= e_line for h in f):
                        vuln_lines = ",".join({str(line.target_line_no) for h in f for line in h if (line.is_added or line.is_removed) and s_line <= line.target_line_no <= e_line})
                        s.cur.execute("INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?)",
                            (info["project_name"],f"{info['buggy_commit_id']}/{f.path}",s_line,e_line,vuln_lines if vuln_lines else None,n.text.decode("utf-8","ignore")))
        return s

    class CODE:
        def __init__(s,ext,code):
            s.lang,s.parser,s.fn,s.cmt=CVE_DB.CODE.LANGS[ext]; s.code=code

        def strip(s):
            for nodes in QueryCursor(Query(s.lang,s.cmt)).captures(s.parser.parse(s.code).root_node).values():
                for n in nodes:
                    s0,e0=n.start_byte,n.end_byte
                    s.code=s.code[:s0]+bytes((ch if ch==10 else 32)for ch in s.code[s0:e0])+s.code[e0:]
            return s

        def captures(s,which):
            q={"fn":s.fn,"cmt":s.cmt}[which]
            for nodes in QueryCursor(Query(s.lang,q)).captures(s.parser.parse(s.code).root_node).values():
                for n in nodes: yield n

        LANGS={ext:(get_language(l),get_parser(l),fn,cmt)for l,exts,fn,cmt in[
            ('c',['.c','.h'],'(function_definition) @f','(comment) @c'),
            ('cpp',['.cpp','.hpp','.cxx','.cc'],'(function_definition) @f','(comment) @c'),
            ('java',['.java'],'(method_declaration) @f','[(line_comment)(block_comment)] @c'),
            ('python',['.py'],'(function_definition) @f','(comment) @c'),
            ('csharp',['.cs'],'(method_declaration) @f','(comment) @c')
        ]for ext in exts}
