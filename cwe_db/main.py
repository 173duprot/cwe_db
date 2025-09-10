import sqlite3, json, xml.etree.ElementTree as ET
from pathlib import Path
from tree_sitter import Query, QueryCursor
from tree_sitter_language_pack import get_language, get_parser

def record(db, dataset, source, root=None, min_lines=6):
    sql = sqlite3.connect(db)
    sql.cursor().execute("CREATE TABLE IF NOT EXISTS funcs (cve TEXT,file TEXT,start INT,end INT,vuln TEXT,code TEXT,PRIMARY KEY(cve,file))")

    match dataset:
        case "bugsinpy":
            for x in json.load(open(source)):
                if all(k in x for k in ("project","commit_id","target","func")):
                    sql.cursor().execute("INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?)",
                        (x["project"], x["commit_id"], None, None, str(x["target"]), x["func"]))

        case "juliet":
            manifest={f.get("path"):(flaws[0].get("name"),[int(n.get("line"))for n in flaws if n.get("line")])
                      for f in ET.parse(source).iter("file") if (flaws:=f.findall("flaw"))}
            LANGS={ext:(get_language(l),get_parser(l),fn,cmt)for l,exts,fn,cmt in[
                ('c',['.c','.h'],'(function_definition) @f','(comment) @c'),
                ('cpp',['.cpp','.hpp','.cxx','.cc'],'(function_definition) @f','(comment) @c'),
                ('java',['.java'],'(method_declaration) @f','[(line_comment)(block_comment)] @c'),
                ('python',['.py'],'(function_definition) @f','(comment) @c'),
                ('csharp',['.cs'],'(method_declaration) @f','(comment) @c')
            ]for ext in exts}

            ### Files ###
            for f in Path(root).rglob("*"):
                if f.suffix not in LANGS or f.name not in manifest or not f.is_file(): continue

                ### Clean ###
                lang,parser,fn,cmt,code=(*LANGS[f.suffix],f.read_bytes())
                for nodes in QueryCursor(Query(lang,cmt)).captures(parser.parse(code).root_node).values():
                    for n in nodes: s,e=n.start_byte,n.end_byte; code=code[:s]+bytes((ch if ch==10 else 32)for ch in code[s:e])+code[e:]

                ### Capture ###
                cve,lines=manifest[f.name]
                for nodes in QueryCursor(Query(lang,fn)).captures(parser.parse(code).root_node).values():
                    for n in nodes:
                        s,e=n.start_point[0]+1,n.end_point[0]+1
                        if e-s+1<min_lines: continue
                        vulns=[str(line-(s-1))for line in lines if s<=line<=e]
                        sql.cursor().execute("INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?)",
                            (cve,f.name,s,e,",".join(vulns)if vulns else None,n.text.decode("utf-8","ignore")))

    sql.commit(); sql.close()
