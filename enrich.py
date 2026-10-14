"""Zachowuje stare wywołanie `python enrich.py -i 1.2.3.4`. Właściwy kod: pakiet ioc_enricher."""
from ioc_enricher.cli import run

if __name__ == "__main__":
    run()
