import argparse
from .main import record

def main():
    p = argparse.ArgumentParser()
    p.add_argument("db_path")
    p.add_argument("manifest_path")
    p.add_argument("root_path")
    p.add_argument("--min-lines", type=int, default=6)
    args = p.parse_args()
    record(args.db_path, args.manifest_path, args.root_path, args.min_lines)
