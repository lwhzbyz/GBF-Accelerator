"""Explicit public-network probe; never uses a hardcoded CA or cache path."""
import sys
from app_main import main

if __name__ == "__main__":
    main(["--probe", *sys.argv[1:]])
