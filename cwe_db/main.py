import sqlite3, xml.etree.ElementTree as ET
from pathlib import Path
from tree_sitter import Query, QueryCursor
from tree_sitter_language_pack import get_language, get_parser

LANGS = {ext:(get_language(lang), get_parser(lang), fn, cmt)
         for lang, exts, fn, cmt in [
             ('c',      ['.c','.h'],                  '(function_definition) @f', '(comment) @c'),
             ('cpp',    ['.cpp','.hpp','.cxx','.cc'], '(function_definition) @f', '(comment) @c'),
             ('java',   ['.java'],                    '(method_declaration) @f',  '[(line_comment)(block_comment)] @c'),
             ('python', ['.py'],                      '(function_definition) @f', '(comment) @c'),
             ('csharp', ['.cs'],                      '(method_declaration) @f',  '(comment) @c')
         ] for ext in exts }

def record(db_path, manifest_path, root_path, min_lines=6):
    sql = sqlite3.connect(db_path);
    sql.cursor().execute("CREATE TABLE IF NOT EXISTS funcs (cve TEXT,file TEXT,start INT,end INT,vuln TEXT,code TEXT,PRIMARY KEY(cve, file))")

    manifest = {f.get('path'): [(n.get('name'), int(n.get('line')))
                    for n in f.findall('flaw') if n.get('line')]
                for f in ET.parse(manifest_path).iter('file')
                if f.findall('flaw')}

    # Files
    for f in Path(root_path).rglob("*"):
        if f.suffix not in LANGS or f.name not in manifest or not f.is_file(): continue # in manifest

        # Get
        lang, parser, fn, cmt, code = (*LANGS[f.suffix], f.read_bytes())

        # Clean
        for nodes in QueryCursor(Query(lang, cmt)).captures(parser.parse(code).root_node).values():
            for n in nodes:
                s, e = n.start_byte, n.end_byte # Bytes
                code = code[:s] + bytes((ch if ch==10 else 32) for ch in code[s:e]) + code[e:] # (10=\n)(32= )

        # Capture
        flaws = manifest[f.name]; cve = flaws[0][0];
        for nodes in QueryCursor(Query(lang, fn)).captures(parser.parse(code).root_node).values():
            for n in nodes:
                s, e = n.start_point[0]+1, n.end_point[0]+1 # Lines
                if e - s + 1 < min_lines: continue # Filter
                vulns = [str(line-s)for _,line in flaws if s<=line<=e] # Extract

                # Record
                sql.cursor().execute("INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?,?)",
                    (cve, f.name, s, e, ",".join(vulns)if(vulns)else(None), n.text.decode('utf-8', 'ignore')))

    # Save
    sql.commit();
    sql.close()


record("ex.db","./C/manifest.xml","./C/testcases/CWE114_Process_Control/")
