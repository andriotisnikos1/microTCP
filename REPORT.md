# microTCP Code Review Report

**Date:** January 25, 2026  
**Reviewed Files:** `lib/microtcp.c`, `lib/microtcp.h`

---

## Summary

This report documents bugs and issues found during a second review of the microTCP implementation after recent changes. Issues are categorized by severity.

| Severity | Count |
|----------|-------|
| Critical | 8 |
| Medium   | 6 |
| Minor    | 4 |

---

## Critical Bugs

### 1. Wrong byte order function for checksum storage (still present)

**Locations:** `microtcp.c` lines 138, 239, 307, 356, 475, 562, 600, 796

**Problem:** Using `ntohl()` instead of `htonl()` when storing the checksum before sending.

```c
// WRONG - ntohl converts FROM network to host (for reading)
outgoing_mtcp_header.checksum = ntohl(calculated_checksum);
```

**Fix:**
```c
// CORRECT - htonl converts TO network byte order (for sending)
outgoing_mtcp_header.checksum = htonl(calculated_checksum);
```

**Impact:** Checksum will be incorrect on big-endian systems, causing all packets to fail validation on the receiving end.

---

### 2. Wrong byte order check for control flags (still present)

**Locations:** `microtcp.c` lines 86, 170, 270, 388, 438

**Problem:** Using `htons()` on incoming data instead of `ntohs()`.

```c
// WRONG
if (htons(incoming_mtcp_header->control) != SYN) {
```

**Fix:**
```c
// CORRECT
if (ntohs(incoming_mtcp_header->control) != SYN) {
```

**Impact:** Control flag checks will fail on big-endian systems.

---

### 3. Sequence number comparison uses mismatched byte orders (still present)

**Location:** `microtcp.c` lines 190, 195

**Problem:** Comparing host-order value with network-order value.

```c
// WRONG - outgoing_mtcp_header.ack_number is in network byte order
if (ntohl(incoming_mtcp_header->seq_number) != outgoing_mtcp_header.ack_number) {
```

**Fix:**
```c
// CORRECT - convert both to host order for comparison
if (ntohl(incoming_mtcp_header->seq_number) != ntohl(outgoing_mtcp_header.ack_number)) {
```

**Impact:** Sequence number validation will incorrectly fail, breaking the 3-way handshake.

---

### 4. Memory leak in `microtcp_accept`

**Location:** `microtcp.c` line 88

**Problem:** `incoming_mtcp_header` is not freed when SYN flag check fails.

```c
if (htons(incoming_mtcp_header->control) != SYN) {
    perror("[microtcp_accept] expected SYN control flag\n");
    return -1;  // LEAK: incoming_mtcp_header not freed
}
```

**Fix:**
```c
if (ntohs(incoming_mtcp_header->control) != SYN) {
    perror("[microtcp_accept] expected SYN control flag");
    free(incoming_mtcp_header);
    return -1;
}
```

---

### 5. `microtcp_send` missing return value (new)

**Location:** `microtcp.c` line 694

**Problem:** Function ends without returning a `ssize_t` value.

**Fix:**
```c
free(incoming_mtcp_header);
free(packet);
return data_sent;
```

---

### 6. `microtcp_send` memory leaks (new)

**Location:** `microtcp.c` lines 500, 502

**Problem:** `incoming_mtcp_header` and `packet` are allocated but never freed.

```c
microtcp_header_t *incoming_mtcp_header = (microtcp_header_t *)malloc(sizeof(microtcp_header_t));
uint8_t *packet = (uint8_t *)malloc(MICROTCP_MSS);
```

---

### 7. Header still declares old `remove` function

**Location:** `microtcp.h` line 153

**Problem:** `remove()` conflicts with the C standard library and no longer matches the implementation.

```c
int remove(size_t ack_number);  // WRONG
```

**Fix:**
```c
void removeAck(size_t ack_number);
```

---

### 8. Global variable declaration in header file

**Location:** `microtcp.h` line 125

**Problem:** Declaring a global variable in a header causes multiple definition errors when the header is included in multiple source files.

```c
// WRONG - in header file
struct acks *ack_list_head;
```

**Fix:**

In `microtcp.h`:
```c
extern struct acks *ack_list_head;
```

In `microtcp.c`:
```c
struct acks *ack_list_head = NULL;
```

---

## Medium Issues

### 9. Control field uses wrong conversion function

**Locations:** `microtcp.c` lines 547, 585

**Problem:** `control` is `uint16_t` but `htonl()` (32-bit) is used instead of `htons()` (16-bit).

```c
// WRONG
outgoing_mtcp_header.control = htonl(0);

// CORRECT
outgoing_mtcp_header.control = htons(0);
```

---

### 10. `min()` function has type and logic errors

**Location:** `microtcp.c` lines 816-823

**Problems:**
- Compares `size_t` to `NULL` (pointer), which is semantically wrong
- `ssize_t` return type does not match `size_t` parameters
- Function is unused (an inline ternary is used instead)

**Recommendation:** Remove the function or replace it with a correct `min3()` implementation.

---

### 11. `recvfrom` uses `const struct sockaddr *`

**Location:** `microtcp.c` line 716

`socket->peer_address` is `const struct sockaddr *` but `recvfrom()` expects a mutable `struct sockaddr *`. This is a type mismatch and can cause compiler warnings or undefined behavior.

---

### 12. Possible user buffer overflow in `microtcp_recv`

**Location:** `microtcp.c` line 766

```c
memcpy(buffer + bytes_copied, incoming_data_accumulator, bytes_accumulated);
```

There is no check that `bytes_copied + bytes_accumulated <= length`. This can overflow the caller’s buffer.

---

### 13. `microtcp_recv` drops buffered data on exit

**Location:** `microtcp.c` line 806

If the loop exits with `bytes_accumulated > 0`, the data is never copied into the user buffer before returning.

---

### 14. Storing pointer to potentially stack-allocated address

**Locations:** `microtcp.c` lines 205-206, 322-323

```c
socket->peer_address = address;
socket->peer_address_len = address_len;
```

If the caller passes a pointer to a stack-allocated `struct sockaddr`, this becomes a dangling pointer after the caller returns.

---

## Minor Issues

### 15. Inconsistent indentation

**Locations:** `microtcp.c` lines 205-206, 322-323

Some lines use different indentation (tabs vs spaces). Recommend consistent formatting throughout.

---

### 16. `perror()` called with trailing newline

**Multiple locations**

`perror()` automatically appends a newline. Including `\n` in the message creates double newlines.

```c
// Current
perror("[microtcp_accept] malloc failed\n");

// Better
perror("[microtcp_accept] malloc failed");
```

---

### 17. Unused `flags` parameter

**Location:** `microtcp_send` function

The `flags` parameter is never used. Either implement flag handling or document that flags are ignored.

---

### 18. Random number generator not seeded

**Locations:** `microtcp.c` lines 122, 223

```c
outgoing_mtcp_header.seq_number = htonl(rand() % 100 + 1);
```

`rand()` is not seeded with `srand()`, so sequence numbers will be predictable across runs.

---

## Action Items

| Priority | Task | Assignee |
|----------|------|----------|
| P0 | Fix all `ntohl`/`htonl` and `ntohs`/`htons` misuses | |
| P0 | Fix sequence number comparison byte order mismatch | |
| P0 | Fix memory leak in `microtcp_accept` | |
| P0 | Add return statement to `microtcp_send` and free allocated buffers | |
| P0 | Fix `remove` declaration in `microtcp.h` | |
| P0 | Fix global variable declaration in header | |
| P1 | Fix `control` field conversions | |
| P1 | Fix `min()` function or remove it | |
| P1 | Address `recvfrom()` const mismatch | |
| P1 | Prevent buffer overflow in `microtcp_recv` | |
| P1 | Flush remaining buffer data before returning | |
| P2 | Address peer_address pointer lifetime issue | |
| P3 | Code cleanup (formatting, perror newlines, etc.) | |
