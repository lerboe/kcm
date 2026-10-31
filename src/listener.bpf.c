#include "beeper/http1.h"

BEEPER_HTTP1_PARSE_BUF(parse_http1)

extern int bpf_dynptr_from_skb(struct __sk_buff *skb, u64 flags, struct bpf_dynptr *ptr) __ksym;
extern int bpf_dynptr_adjust(const struct bpf_dynptr *p, u32 start, u32 end) __ksym;
extern void *bpf_cast_to_kern_ctx(void *obj) __ksym;

// must match the order of `capture_hdr` calls in lib.rs
#define CONTENT_LENGTH_MID 0

// keeps the body length below 1e9, so that adding the header length cannot overflow
#define MAX_DIGITS 9

// Returns the length of the HTTP/1.1 message at the start of `skb`, 0 if more
// bytes are needed, or a negative value if the message is malformed.
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
