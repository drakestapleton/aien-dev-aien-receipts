/* THROWAWAY HOST TOOLING (benchmark peer arm, not product code).
 * OpenSSL TLS 1.3 client with the same CLI and output as om/tls/test/bench/bench.om:
 *   ossl_client MODE PORT N PATH ROOTPEM     (MODE h|g|b|d)
 * Offer set matched to the Omega client: TLS 1.3 only, CHACHA20_POLY1305 then AES_128_GCM,
 * group X25519 only, no resumption (fresh SSL each time, no session cache), SNI bench.test,
 * hostname verification against bench.test, chain verified against ROOTPEM only. */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static unsigned long long now(void) {
  struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
  return (unsigned long long)t.tv_sec * 1000000000ull + (unsigned long long)t.tv_nsec;
}

static int dial(int port) {
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET; sa.sin_port = htons((unsigned short)port);
  sa.sin_addr.s_addr = htonl(0x7f000001);
  if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) return -1;
  return fd;
}

int main(int argc, char **argv) {
  if (argc != 6 || strlen(argv[1]) != 1) { fprintf(stderr, "usage: ossl_client h|g|b|d PORT N PATH ROOTPEM\n"); return 2; }
  char md = argv[1][0]; int port = atoi(argv[2]); long n = atol(argv[3]);
  char req[1200]; int rl = snprintf(req, sizeof req, "GET /%s HTTP/1.0\r\n\r\n", argv[4]);
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_ciphersuites(ctx, getenv("BENCH_SUITES") ? getenv("BENCH_SUITES")
                                 : "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");
  SSL_CTX_set1_groups_list(ctx, "X25519");
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  if (SSL_CTX_load_verify_locations(ctx, argv[5], NULL) != 1) { fprintf(stderr, "TLSERR store\n"); return 12; }
  static unsigned char buf[16384];
  for (long i = 0; i < n; i++) {
    unsigned long long t0 = now();
    int fd = dial(port);
    if (fd < 0) return 3;
    SSL *s = SSL_new(ctx);
    SSL_set_tlsext_host_name(s, "bench.test");
    SSL_set1_host(s, "bench.test");
    SSL_set_fd(s, fd);
    if (SSL_connect(s) != 1) { ERR_print_errors_fp(stderr); fprintf(stderr, "TLSERR connect\n"); return 11; }
    unsigned long long t1 = now(), t2 = 0, by = 0, smp = t1 - t0;
    if (md != 'h') {
      t2 = now();
      if (SSL_write(s, req, rl) != rl) return 11;
      for (;;) {
        int r = SSL_read(s, buf, sizeof buf);
        if (r <= 0) {
          if (SSL_get_error(s, r) == SSL_ERROR_ZERO_RETURN) break;
          fprintf(stderr, "TLSERR read\n"); return 11;
        }
        by += (unsigned long long)r;
        if (md == 'd') fwrite(buf, 1, (size_t)r, stdout);
      }
      unsigned long long t3 = now();
      smp = md == 'b' ? t3 - t2 : t3 - t0;
    }
    SSL_shutdown(s);
    SSL_free(s);
    close(fd);
    if (md != 'd') printf("S %llu %llu\n", smp, by);
  }
  SSL_CTX_free(ctx);
  return 0;
}
