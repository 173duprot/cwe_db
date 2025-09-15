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

    def juliet(s,src,root,min_lines=6):
        # Extract
        manifest={f.get("path"):(flaws[0].get("name"),[int(n.get("line"))for n in flaws if n.get("line")])
                  for f in ET.parse(src).iter("file") if (flaws:=f.findall("flaw"))}
        # Files
        for f in Path(root).rglob("*"):
            if not(f.is_file() and f.suffix in CVE_DB.CODE.LANGS and f.name in manifest): continue # is valid?

            # Fetch
            cve,lines=manifest[f.name]
            code=CVE_DB.CODE(f).strip(CVE_DB.CODE.LANGS[f.suffix][3]) # strip comments

            # Record
            for n in code.query(code.fn): # functions
                s0,e0=n.start_point[0]+1,n.end_point[0]+1
                if e0-s0+1<min_lines: continue
                vulns=[str(l-(s0-1))for l in lines if s0<=l<=e0]
                s.cur.execute("INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?)",
                    (cve,f.name,s0,e0,",".join(vulns)if vulns else None,n.text.decode("utf-8","ignore")))
        return s

    def bugsinpy(s,src):
        # Extract
        for p in Path(src).rglob("bug.info"):
            info={k:v.strip().strip('"') for k,v in (l.split("=",1) for l in p.read_text().splitlines())}
            proj_info={k:v.strip().strip('"') for k,v in (l.split("=",1) for l in (p.parents[2]/"project.info").read_text().splitlines())}
            project_name=Path(proj_info["github_url"]).stem

            # Fetch
            repo_path=Path(f"/tmp/{project_name}")
            try: repo=Repo.clone_from(proj_info["github_url"],repo_path)
            except: repo=Repo(repo_path) if repo_path.exists() else (print(project_name,"clone fail") or None)
            try: repo.git.checkout(info["buggy_commit_id"]); print(project_name,info["buggy_commit_id"],"ok")
            except: print(project_name,info["buggy_commit_id"],"fail"); continue

            # Record
            for f in unidiff.PatchSet.from_filename(p.parent/"bug_patch.txt",encoding="utf-8"):
                if Path(f.path).suffix not in CVE_DB.CODE.LANGS: continue
                code=CVE_DB.CODE(repo_path/f.path).strip(CVE_DB.CODE.LANGS[Path(f.path).suffix][3])
                for n in code.query(code.fn):
                    s0,e0=n.start_point[0]+1,n.end_point[0]+1
                    vuln=any(h.target_start<=s0<=h.target_start+h.target_length or s0<=h.target_start<=e0 for h in f)
                    s.cur.execute("INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?)",
                        (project_name,f"{info['buggy_commit_id']}/{f.path}",s0,e0,"1" if vuln else "0",n.text.decode("utf-8","ignore")))
        return s

    class CODE:
        def __init__(s,path):
            ext=Path(path).suffix; s.lang,s.parser,s.fn,s.cmt=CVE_DB.CODE.LANGS[ext]; s.code=Path(path).read_bytes()
        def query(s,q):
            return (n for v in QueryCursor(Query(s.lang,q)).captures(s.parser.parse(s.code).root_node).values() for n in v)
        def strip(s,q):
            for n in s.query(q):
                a,b=n.start_byte,n.end_byte
                s.code=s.code[:a]+bytes((c if c==10 else 32)for c in s.code[a:b])+s.code[b:]
            return s
        LANGS={ext:(get_language(l),get_parser(l),fn,cmt)for l,exts,fn,cmt in[
            ('c',['.c','.h'],'(function_definition) @f','(comment) @c'),
            ('cpp',['.cpp','.hpp','.cxx','.cc'],'(function_definition) @f','(comment) @c'),
            ('java',['.java'],'(method_declaration) @f','[(line_comment)(block_comment)] @c'),
            ('python',['.py'],'(function_definition) @f','(comment) @c'),
            ('csharp',['.cs'],'(method_declaration) @f','(comment) @c')
        ]for ext in exts}
