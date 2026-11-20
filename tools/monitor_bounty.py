#!/usr/bin/env python3
"""Monitor the live bounty server for defacement, certificate/DNS mismatch, rogue SSH,
and Bitcoin wallet spend (confirmed or unconfirmed mempool).

    tools/monitor_bounty.py [--notify] [--expect-funded]
    tools/monitor_bounty.py --watch 60 [--notify] [--expect-funded]
    tools/monitor_bounty.py --host NAME --ip ADDRESS ...   a rehearsal (tools/bounty_ceremony.sh):
                                 its proof is cert-NAME/bounty.proof, and its page is site/ with
                                 the address and the certificate's last day put in
    tools/monitor_bounty.py --test

The page it expects and the proof are the ones in the branch `bounty` of this repository
(site/ and bounty.proof as committed there), whatever is checked out; `--site DIR` and
`--proof FILE` take others.
"""
import datetime
import gzip
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bounty  # noqa: E402


def alert(msg, notify=False):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] ALERT: {msg}"
    print(line, file=sys.stderr, flush=True)
    if notify:
        subprocess.run(["notify-send", "-u", "critical", "k15 bounty alert", msg], check=False)


def http_get_raw(tls_or_sock, host, path, headers=()):
    hdrs = "".join(f"{k}: {v}\r\n" for k, v in headers)
    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{hdrs}\r\n".encode()
    tls_or_sock.sendall(req)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = tls_or_sock.recv(4096)
        if not chunk:
            raise RuntimeError(f"EOF reading headers for {path}")
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    lines = head.decode("latin1").split("\r\n")
    status = int(lines[0].split()[1])
    hmap = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hmap[k.strip().lower()] = v.strip()
    clen = int(hmap.get("content-length", "0"))
    while len(rest) < clen:
        chunk = tls_or_sock.recv(max(4096, clen - len(rest)))
        if not chunk:
            raise RuntimeError(f"EOF reading body for {path}")
        rest += chunk
    return status, hmap, rest[:clen]


def read_site(source):
    """index.html, style.css and 404.html of a folder, or of site/ in a branch (`git show`)."""
    files = {}
    for name in ("index.html", "style.css", "404.html"):
        if os.path.isdir(source):
            files[name] = open(os.path.join(source, name), "rb").read()
        else:
            got = subprocess.run(["git", "-C", ROOT, "show", f"{source}:site/{name}"], capture_output=True)
            if got.returncode:
                sys.exit(f"monitor_bounty.py: no site/{name} in '{source}' (a branch, or --site DIR): "
                         + got.stderr.decode().strip())
            files[name] = got.stdout
    return files


def check_site_and_cert(host, sans, ip, port, http_port, site, expected_q1, cafile=None, addr=None):
    problems = []
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    site_index, want_css, want_404 = site["index.html"], site["style.css"], site["404.html"]

    for sni in [host] + list(sans):
        try:
            with socket.create_connection((ip, port), timeout=8) as raw:
                with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                    der = tls.getpeercert(binary_form=True)
                    q1 = bounty.extract_p256_from_der_cert(der)
                    if bounty.R1.encode(q1) != expected_q1:
                        problems.append(f"{sni}: TLS leaf public key mismatch (possible MITM/replacement)")
                    info = tls.getpeercert()
                    want_index = site_index
                    if info and "notAfter" in info:
                        exp = datetime.datetime.strptime(info["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=datetime.timezone.utc
                        )
                        days_left = (exp - datetime.datetime.now(datetime.timezone.utc)).total_seconds() / 86400
                        if days_left < 7:
                            problems.append(f"{sni}: certificate expires in {days_left:.1f} days — sweep bounty before expiry")
                        if addr:  # (a rehearsal's page: changed in a copy, as the ceremony did)
                            want_index = re.sub(rb"bc1q[a-z0-9]{38}", addr.encode(), want_index)
                            want_index = re.sub(rb"until 20[0-9]{2}-[0-9]{2}-[0-9]{2}",
                                                b"until " + exp.strftime("%Y-%m-%d").encode(), want_index)
                    if sni == host:
                        st, _, body = http_get_raw(tls, host, "/")
                        if st != 200 or body != want_index:
                            problems.append(f"/: defacement or mismatch (status={st}, len={len(body)})")
                        st, hm, body = http_get_raw(tls, host, "/", [("Accept-Encoding", "gzip")])
                        if hm.get("content-encoding") == "gzip":
                            body = gzip.decompress(body)
                        if st != 200 or body != want_index:
                            problems.append("/: compressed response mismatch")
                        st, _, body = http_get_raw(tls, host, "/style.css")
                        if st != 200 or body != want_css:
                            problems.append(f"/style.css: mismatch (status={st})")
                        st, _, body = http_get_raw(tls, host, "/.monitor-404-probe")
                        if st != 404 or body != want_404:
                            problems.append(f"404 probe: mismatch (status={st})")
        except Exception as exc:
            problems.append(f"HTTPS {sni} ({ip}:{port}) failed: {exc}")

    try:
        with socket.create_connection((ip, http_port), timeout=6) as raw80:
            st, hm, _ = http_get_raw(raw80, host, "/")
            if st != 301 or hm.get("location") != f"https://{host}/":
                problems.append(f"port {http_port}: expected 301 to https://{host}/, got {st} {hm.get('location')}")
    except Exception as exc:
        problems.append(f"HTTP {ip}:{http_port} failed: {exc}")

    return problems


def check_dns(names, expected_ip):
    problems = []
    for name in names:
        try:
            addrs = {res[4][0] for res in socket.getaddrinfo(name, 443, socket.AF_INET)}
            if addrs != {expected_ip}:
                problems.append(f"DNS {name} resolved to {sorted(addrs)}, expected [{expected_ip}]")
        except Exception as exc:
            problems.append(f"DNS lookup failed for {name}: {exc}")
    return problems


def check_port_closed(ip, port=22):
    try:
        with socket.create_connection((ip, port), timeout=2.5):
            return [f"port {port} on {ip} is OPEN (server may have booted Linux/Rescue!)"]
    except (TimeoutError, socket.timeout, ConnectionRefusedError, OSError):
        return []


def check_btc(addr, expect_funded=False):
    urls = (
        f"https://mempool.space/api/address/{addr}",
        f"https://blockstream.info/api/address/{addr}",
    )
    last_err = None
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "k15-monitor/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            cs, ms = data["chain_stats"], data["mempool_stats"]
            funded = cs["funded_txo_sum"] + ms["funded_txo_sum"]
            spent_chain = cs["spent_txo_sum"]
            spent_mem = ms["spent_txo_sum"]
            bal = funded - spent_chain - spent_mem
            problems = []
            if spent_chain > 0 or spent_mem > 0:
                problems.append(
                    f"BITCOIN SPENT on {addr}! chain_spent={spent_chain} sats, mempool_spent={spent_mem} sats — REVOKE TLS CERT!"
                )
            elif expect_funded and bal <= 0:
                problems.append(f"Bitcoin wallet {addr} has 0 sats balance")
            return problems, bal
        except Exception as exc:
            last_err = exc
    return [f"BTC API check failed for {addr}: {last_err}"], None


def run_self_test():
    import tempfile

    with tempfile.TemporaryDirectory(dir="/dev/shm") as tmp:
        cert_d = os.path.join(tmp, "cert")
        out_d = os.path.join(tmp, "build")
        subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools/bounty.py"), "--gen", cert_d, "-n", "15kb.org"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        os.remove(os.path.join(cert_d, "csr.pem"))
        # Let k15 pack generate ca.pem + leaf for server.key? gen.py makes a fresh key only if both missing;
        # build a self-signed test cert for our generated server.key instead:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-key", os.path.join(cert_d, "server.key"),
                "-out", os.path.join(cert_d, "server.pem"), "-days", "90",
                "-subj", "/CN=15kb.org", "-addext", "subjectAltName=DNS:15kb.org,DNS:www.15kb.org",
            ],
            check=True,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [os.path.join(ROOT, "k15"), "pack", os.path.join(ROOT, "site"), "-n", "15kb.org",
             "--san", "www.15kb.org", "-c", cert_d, "-o", out_d, "--hsts", "31536000"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        q1_b, _, addr = bounty.verify_xcurve(
            bounty.parse_proof(open(os.path.join(cert_d, "bounty.proof"), encoding="utf-8").read())
        )
        port = 18543
        proc = subprocess.Popen(
            [os.path.join(ROOT, "k15"), "run", out_d, "-p", str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            for _ in range(40):
                time.sleep(0.25)
                errs = check_site_and_cert(
                    "15kb.org", ("www.15kb.org",), "127.0.0.1", port, port + 1000,
                    read_site(os.path.join(ROOT, "site")), q1_b, cafile=os.path.join(cert_d, "server.pem"),
                )
                if not errs:
                    break
            assert not errs, f"expected clean check, got: {errs}"
            # Verify defacement detection triggers when local site differs
            fake_site = os.path.join(tmp, "fake_site")
            os.makedirs(fake_site)
            for fn in ("index.html", "style.css", "404.html"):
                with open(os.path.join(fake_site, fn), "wb") as f:
                    f.write(open(os.path.join(ROOT, "site", fn), "rb").read() + (b"X" if fn == "index.html" else b""))
            errs2 = check_site_and_cert(
                "15kb.org", ("www.15kb.org",), "127.0.0.1", port, port + 1000,
                read_site(fake_site), q1_b, cafile=os.path.join(cert_d, "server.pem"),
            )
            assert any("defacement" in e for e in errs2), f"failed to detect defacement: {errs2}"
        finally:
            proc.terminate()
            proc.wait(timeout=5)
    print("monitor_bounty.py: ok")


def main():
    args = sys.argv[1:]
    if "--test" in args:
        run_self_test()
        return

    notify = "--notify" in args
    expect_funded = "--expect-funded" in args
    watch = 0
    host = "15kb.org"
    sans = ("www.15kb.org",)
    ip = "2.28.113.14"
    proof_path = None       # (the proof in the branch `bounty`, like the page)
    site_from = "bounty"
    rehearsal = False

    i = 0
    while i < len(args):
        if args[i] in ("--notify", "--expect-funded"):
            i += 1
        elif args[i] == "--watch" and i + 1 < len(args):
            watch = int(args[i + 1])
            i += 2
        elif args[i] == "--ip" and i + 1 < len(args):
            ip = args[i + 1]
            i += 2
        elif args[i] == "--site" and i + 1 < len(args):
            site_from = args[i + 1]
            i += 2
        elif args[i] == "--host" and i + 1 < len(args):
            host, sans, rehearsal = args[i + 1], (), True
            proof_path = os.path.join(ROOT, f"cert-{host}", "bounty.proof")
            i += 2
        elif args[i] == "--proof" and i + 1 < len(args):
            proof_path = args[i + 1]
            i += 2
        else:
            sys.exit(__doc__)

    if rehearsal and ip == "2.28.113.14":
        sys.exit("monitor_bounty.py: --host needs --ip too")
    if proof_path is None:
        got = subprocess.run(["git", "-C", ROOT, "show", "bounty:bounty.proof"], capture_output=True)
        if got.returncode:
            sys.exit("monitor_bounty.py: no bounty.proof in the branch 'bounty' (tools/bounty_ceremony.sh, then its commit)")
        proof_text = got.stdout.decode()
    elif not os.path.exists(proof_path):
        sys.exit(f"monitor_bounty.py: {proof_path} not found (run tools/bounty_ceremony.sh first)")
    else:
        proof_text = open(proof_path, encoding="utf-8").read()

    q1_b, _, addr = bounty.verify_xcurve(bounty.parse_proof(proof_text))

    step = 0
    last_bal = None
    while True:
        problems = []
        problems += check_dns((host,) + sans, ip)
        problems += check_site_and_cert(host, sans, ip, 443, 80, read_site(site_from), q1_b,
                                        addr=addr if rehearsal else None)
        problems += check_port_closed(ip, 22)
        if step % max(1, (120 // watch) if watch and watch < 120 else 1) == 0:
            btc_probs, last_bal = check_btc(addr, expect_funded=expect_funded)
            problems += btc_probs

        if problems:
            for p in problems:
                alert(p, notify=notify)
            if not watch:
                sys.exit(1)
        else:
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            bal_s = f"{last_bal} sats" if last_bal is not None else "n/a"
            print(f"[{ts}] ok  https://{host}/ ({ip})  {addr} ({bal_s})", flush=True)
            if not watch:
                return
        step += 1
        time.sleep(watch)


if __name__ == "__main__":
    main()
