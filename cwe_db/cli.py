import argparse
from .main import cwe_db

def main():
    p = argparse.ArgumentParser()
    p.add_argument("db_path")
    p.add_argument("manifest_path")
    p.add_argument("root_path")
    p.add_argument("--min-lines", type=int, default=6)
    args = p.parse_args()
    cwe_db(args.db_path, args.manifest_path, args.root_path, args.min_lines)
