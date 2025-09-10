import argparse
from .main import record

def main():
    p = argparse.ArgumentParser()
    p.add_argument("db")
    p.add_argument("dataset")
    p.add_argument("source")
    p.add_argument("--root", default=None)
    p.add_argument("--min-lines", type=int, default=6)
    args = p.parse_args()
    record(args.db, args.dataset, args.source, args.root, args.min_lines)
