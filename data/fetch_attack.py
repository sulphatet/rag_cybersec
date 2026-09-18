"""Download the MITRE ATT&CK Enterprise STIX bundles used by this project.

  python -m data.fetch_attack            # v19.2 (KB) + v15.1 (AttackQA's version, near-miss source)
"""
from .common import ATTACK_BUNDLE, ATTACK_BUNDLE_OLD, ATTACK_URL, ATTACK_VERSION, download


def main():
    for ver, dest in ((ATTACK_VERSION, ATTACK_BUNDLE), ("15.1", ATTACK_BUNDLE_OLD)):
        p = download(ATTACK_URL.format(ver=ver), dest)
        print(f"ATT&CK v{ver}: {p} ({p.stat().st_size/1e6:.1f} MB)")


if __name__ == "__main__":
    main()
