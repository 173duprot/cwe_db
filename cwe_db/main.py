import sqlite3, json, xml.etree.ElementTree as ET
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
            # Record
            if all(k in x for k in ("project","commit_id","target","func")):
                s.cur.execute("INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?)",(x["project"],x["commit_id"],None,None,str(x["target"]),x["func"]))
        return s

    def juliet(s,src,root,min_lines=6):
        # Extract
        manifest={f.get("path"):(flaws[0].get("name"),[int(n.get("line"))for n in flaws if n.get("line")])
                  for f in ET.parse(src).iter("file") if (flaws:=f.findall("flaw"))}
        # Files
        for f in Path(root).rglob("*"):
            if not(f.is_file() and f.suffix in CVE_DB.CODE.LANGS and f.name in manifest): continue # Valid

            # Code
            lang,parser,fn,cmt,code=(*CVE_DB.CODE.LANGS[f.suffix],f.read_bytes())
            cve,lines=manifest[f.name]

            # Clean
            c=CVE_DB.CODE(lang,code).strip(cmt) # Strip

            # Record
            for n in c.captures(fn): # Record
                s0,e0=n.start_point[0]+1,n.end_point[0]+1
                if e0-s0+1<min_lines: continue
                vulns=[str(l-(s0-1))for l in lines if s0<=l<=e0]
                s.cur.execute("INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?)",(cve,f.name,s0,e0,",".join(vulns)if vulns else None,n.text.decode("utf-8","ignore")))
        return s

    class CODE:
        def __init__(s,lang,code): s.lang,s.code=lang,code
        def captures(s,q):
            q=Query(s.lang,q); c=QueryCursor()
            for _,n in c.captures(get_parser(s.lang).parse(s.code).root_node,q): yield n
        def strip(s,q):
            for n in s.captures(q):
                s0,e0=n.start_byte,n.end_byte
                s.code=s.code[:s0]+b''.join((b'\n' if ch==10 else b' ')for ch in s.code[s0:e0])+s.code[e0:]
            return s
        LANGS={ext:(get_language(l),get_parser(l),fn,cmt)for l,exts,fn,cmt in[
         ('c',['.c','.h'],'(function_definition) @f','(comment) @c'),
         ('cpp',['.cpp','.hpp','.cxx','.cc'],'(function_definition) @f','(comment) @c'),
         ('java',['.java'],'(method_declaration) @f','[(line_comment)(block_comment)] @c'),
         ('python',['.py'],'(function_definition) @f','(comment) @c'),
         ('csharp',['.cs'],'(method_declaration) @f','(comment) @c')
        ]for ext in exts}
