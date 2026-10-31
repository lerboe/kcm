#include "beeper/http1.h"

BEEPER_HTTP1_PARSE_BUF(parse_http1)

extern int bpf_dynptr_from_skb(struct __sk_buff *skb, u64 flags, struct bpf_dynptr *ptr) __ksym;
extern int bpf_dynptr_adjust(const struct bpf_dynptr *p, u32 start, u32 end) __ksym;
extern void *bpf_cast_to_kern_ctx(void *obj) __ksym;

// must match the order of `capture_hdr` calls in lib.rs
#define CONTENT_LENGTH_MID 0

// keeps the body length below 1e9, so that adding the header length cannot overflow
#define MAX_DIGITS 9

enum http_version {
    HTTP_VERSION_UNKNOWN,
    HTTP_VERSION_1_1,
    HTTP_VERSION_2,
};

// The number of bytes `http_version` needs to tell the versions apart.
#define HTTP_VERSION_PEEK_LEN 4

// Tells from the first bytes of `ptr` whether it holds an HTTP/1.1 or an
// HTTP/2 message. HTTP/1.1 messages start with an uppercase method or with
// `HTTP/`. HTTP/2 messages are either the connection preface, whose method
// `PRI` HTTP/1.1 never uses, or a frame.
static __always_inline enum http_version http_version(const struct bpf_dynptr *ptr) {
    u8 b[HTTP_VERSION_PEEK_LEN];
    if (bpf_dynptr_read(b, sizeof(b), ptr, 0, 0) < 0) return HTTP_VERSION_UNKNOWN;

    if (b[0] == 'P' && b[1] == 'R' && b[2] == 'I' && b[3] == ' ') return HTTP_VERSION_2;
    if (b[0] >= 'A' && b[0] <= 'Z') return HTTP_VERSION_1_1;

    // ponytail: a frame starts with the high byte of its 24 bit length, which is
    // only 0 while SETTINGS_MAX_FRAME_SIZE stays below 65536. Track the
    // connection preface per socket to also cover larger frames.
    if (b[0] == 0) return HTTP_VERSION_2;

    return HTTP_VERSION_UNKNOWN;
}

// The length of a frame header, see section 4.1 of RFC 9113.
#define HTTP2_FRAME_HDR_LEN 9

#define HTTP2_PREFACE_LEN 24
static const char http2_preface[HTTP2_PREFACE_LEN] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Returns the length of the HTTP/2 frame, or of the connection preface, at the
// start of the `len` bytes of `ptr`, 0 if more bytes are needed, or a negative
// value if the preface is malformed.
static __always_inline int http2_msg_len(const struct bpf_dynptr *ptr, u32 len) {
    u8 hdr[HTTP2_PREFACE_LEN];
    if (len < HTTP2_FRAME_HDR_LEN) return 0;
    if (bpf_dynptr_read(hdr, HTTP2_FRAME_HDR_LEN, ptr, 0, 0) < 0) return -EFAULT;

    if (hdr[0] == http2_preface[0]) {
        if (len < HTTP2_PREFACE_LEN) return 0;
        if (bpf_dynptr_read(hdr, HTTP2_PREFACE_LEN, ptr, 0, 0) < 0) return -EFAULT;

        for (int i = 0; i < HTTP2_PREFACE_LEN; i++) {
            if (hdr[i] != http2_preface[i]) return -EPROTO;
        }

        return HTTP2_PREFACE_LEN;
    }

    return HTTP2_FRAME_HDR_LEN + ((u32)hdr[0] << 16 | (u32)hdr[1] << 8 | (u32)hdr[2]);
}

// Returns the length of the HTTP/1.1 message or HTTP/2 frame at the start of
// `skb`, 0 if more bytes are needed, or a negative value if the message is
// malformed.
SEC("socket")
int msg_len(struct __sk_buff *skb) {
    struct bpf_dynptr ptr;
    if (bpf_dynptr_from_skb(skb, 0, &ptr) < 0) return -EFAULT;

    // strparser hands over the whole sk_buff, which may start with the tail of
    // the previous message, and records where this one starts in the control block
    struct sk_buff *kskb = bpf_cast_to_kern_ctx(skb);
    u32 off = ((struct sk_skb_cb *)kskb->cb)->strp.strp.offset;
    if (off > skb->len) return -EFAULT;
    if (bpf_dynptr_adjust(&ptr, off, skb->len) < 0) return -EFAULT;

    if (skb->len - off < HTTP_VERSION_PEEK_LEN) return 0;
    switch (http_version(&ptr)) {
    case HTTP_VERSION_1_1:
        break;
    case HTTP_VERSION_2:
        return http2_msg_len(&ptr, skb->len - off);
    case HTTP_VERSION_UNKNOWN:
        return -EPROTO;
    }

    struct http_parse_res pres = { 0 };
    int hdr_len = parse_http1(&ptr, skb->len - off, &pres);
    if (hdr_len == -EAGAIN) return 0;
    if (hdr_len < 0) return hdr_len;

    // ponytail: without Content-Length the message ends with its headers, so
    // chunked bodies are not supported. Parse Transfer-Encoding to add them.
    struct http_match m = pres.ms[CONTENT_LENGTH_MID];
    if (m.len == 0) return hdr_len;
    if (m.len > MAX_DIGITS) return -EMSGSIZE;

    u8 digits[MAX_DIGITS];
    u32 len = m.len;
    bpf_clamp_uminmax(len, 1, MAX_DIGITS);
    if (bpf_dynptr_read(digits, len, &ptr, m.idx, 0) < 0) return -EFAULT;

    int body_len = 0;
    for (int i = 0; i < MAX_DIGITS && i < len; i++) {
        u8 c = digits[i];
        if (c < '0' || c > '9') return -EINVAL;
        body_len = body_len * 10 + (c - '0');
    }

    return hdr_len + body_len;
}
