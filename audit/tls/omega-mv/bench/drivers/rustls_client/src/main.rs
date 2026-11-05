//! THROWAWAY HOST TOOLING (benchmark peer arm, not product code).
//! rustls 0.23 TLS 1.3 client, same CLI/output as om/tls/test/bench/bench.om:
//!   rustls_client MODE PORT N PATH ROOTPEM   (MODE h|g|b|d); BENCH_PROVIDER=aws-lc-rs|ring
//! Offer set matched to the Omega client: TLS 1.3 only, CHACHA20_POLY1305 then AES_128_GCM
//! (BENCH_SUITES=aes|chacha narrows it), X25519 only, resumption disabled, SNI bench.test,
//! chain verified against ROOTPEM only. TCP_NODELAY left at the OS default (as the C arm).
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Instant;

fn provider() -> CryptoProvider {
    let which = std::env::var("BENCH_PROVIDER").unwrap_or_else(|_| "aws-lc-rs".into());
    let suites_env = std::env::var("BENCH_SUITES").unwrap_or_default();
    let (mut p, chacha, aes, x) = match which.as_str() {
        "ring" => (
            rustls::crypto::ring::default_provider(),
            rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
            rustls::crypto::ring::kx_group::X25519,
        ),
        _ => (
            rustls::crypto::aws_lc_rs::default_provider(),
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            rustls::crypto::aws_lc_rs::kx_group::X25519,
        ),
    };
    p.cipher_suites = match suites_env.as_str() {
        "aes" => vec![aes],
        "chacha" => vec![chacha],
        _ => vec![chacha, aes],
    };
    p.kx_groups = vec![x];
    p
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 6 || a[1].len() != 1 {
        eprintln!("usage: rustls_client h|g|b|d PORT N PATH ROOTPEM");
        std::process::exit(2);
    }
    let md = a[1].as_bytes()[0];
    let port: u16 = a[2].parse().unwrap();
    let n: u64 = a[3].parse().unwrap();
    let req = format!("GET /{} HTTP/1.0\r\n\r\n", a[4]);
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&a[5]).unwrap();
    for c in rustls_pemfile::certs(&mut &pem[..]) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.resumption = rustls::client::Resumption::disabled();
    cfg.enable_sni = true;
    let cfg = Arc::new(cfg);
    let name = ServerName::try_from("bench.test").unwrap();
    let mut buf = vec![0u8; 16384];
    let out = std::io::stdout();
    let mut out = out.lock();
    for _ in 0..n {
        let t0 = Instant::now();
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap_or_else(|_| std::process::exit(3));
        let mut conn = rustls::ClientConnection::new(cfg.clone(), name.clone()).unwrap();
        while conn.is_handshaking() {
            if let Err(e) = conn.complete_io(&mut sock) {
                eprintln!("TLSERR {e}");
                std::process::exit(11);
            }
        }
        let t1 = Instant::now();
        let mut smp = (t1 - t0).as_nanos();
        let mut by: u64 = 0;
        if md != b'h' {
            let t2 = Instant::now();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);
            tls.write_all(req.as_bytes()).unwrap();
            loop {
                match tls.read(&mut buf) {
                    Ok(0) => break,
                    Ok(r) => {
                        by += r as u64;
                        if md == b'd' {
                            out.write_all(&buf[..r]).unwrap();
                        }
                    }
                    Err(e) => {
                        eprintln!("TLSERR {e}");
                        std::process::exit(11);
                    }
                }
            }
            let t3 = Instant::now();
            smp = if md == b'b' { (t3 - t2).as_nanos() } else { (t3 - t0).as_nanos() };
        }
        conn.send_close_notify();
        let _ = conn.complete_io(&mut sock);
        drop(sock);
        if md != b'd' {
            writeln!(out, "S {} {}", smp, by).unwrap();
        }
    }
}
