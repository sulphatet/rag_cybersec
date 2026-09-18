"""Download NIST SP 800-61r3 (Incident Response Recommendations, April 2025)."""
from .common import NIST_PDF_URL, RAW, download


def main():
    p = download(NIST_PDF_URL, RAW / "sp800-61r3.pdf")
    print(f"NIST SP 800-61r3: {p} ({p.stat().st_size/1e6:.2f} MB)")


if __name__ == "__main__":
    main()
