// Compatibility shims for linking glibc-built static libs (libpbc.a/libgmp.a) into an SGX enclave.
//
// SGX tlibc intentionally omits FILE/stdio. The pairing code path we use inside the enclave
// (BF-IBE decryption) never performs file I/O, but libpbc/libgmp still reference some stdio/ctype
// symbols from auxiliary code. We provide minimal stubs so the enclave can link.
//
// IMPORTANT: These stubs are NOT meant for general-purpose stdio; they should never be on a
// security-critical path. If a code path accidentally triggers them, it will behave as "no-op".

#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "sgx_trts.h" // sgx_read_rand

// SGX tlibc does not define FILE, but glibc-built libgmp/libpbc expect it.
// We only need a type for signatures; the implementation below never dereferences it.
struct SGX_FILE;
typedef struct SGX_FILE FILE;

// Some glibc objects reference these directly.
FILE* stdout = (FILE*)0;
FILE* stderr = (FILE*)0;

// SGX tlibc doesn't provide `strcpy` (only fortified variants). Some glibc-built
// static libraries (e.g., libpbc) still reference it.
char* strcpy(char* dst, const char* src) {
    char* out = dst;
    while ((*dst++ = *src++) != '\0') {
        // copy
    }
    return out;
}

// --- Minimal ctype table for __ctype_b_loc() ---
//
// glibc's <ctype.h> implements macros via a locale-dependent table returned by __ctype_b_loc().
// libgmp (built against glibc) calls __ctype_b_loc() from parsing code (mpz_set_str).
// We provide a simplified "C locale" classification table sufficient for digits/hex/space.
//
// The exact bit values are not critical as long as they are consistent with the expectations
// in the object code that uses them. We mimic glibc's common bit layout for safety.
#define SGX_CTYPE_ISUPPER 0x0100
#define SGX_CTYPE_ISLOWER 0x0200
#define SGX_CTYPE_ISALPHA 0x0400
#define SGX_CTYPE_ISDIGIT 0x0800
#define SGX_CTYPE_ISXDIGIT 0x1000
#define SGX_CTYPE_ISSPACE 0x2000

static const unsigned short sgx_ctype_b[256] = {
    // Control chars
    ['\t'] = SGX_CTYPE_ISSPACE,
    ['\n'] = SGX_CTYPE_ISSPACE,
    ['\v'] = SGX_CTYPE_ISSPACE,
    ['\f'] = SGX_CTYPE_ISSPACE,
    ['\r'] = SGX_CTYPE_ISSPACE,
    [' '] = SGX_CTYPE_ISSPACE,

    // Digits
    ['0'] = SGX_CTYPE_ISDIGIT | SGX_CTYPE_ISXDIGIT,
    ['1'] = SGX_CTYPE_ISDIGIT | SGX_CTYPE_ISXDIGIT,
    ['2'] = SGX_CTYPE_ISDIGIT | SGX_CTYPE_ISXDIGIT,
    ['3'] = SGX_CTYPE_ISDIGIT | SGX_CTYPE_ISXDIGIT,
    ['4'] = SGX_CTYPE_ISDIGIT | SGX_CTYPE_ISXDIGIT,
    ['5'] = SGX_CTYPE_ISDIGIT | SGX_CTYPE_ISXDIGIT,
    ['6'] = SGX_CTYPE_ISDIGIT | SGX_CTYPE_ISXDIGIT,
    ['7'] = SGX_CTYPE_ISDIGIT | SGX_CTYPE_ISXDIGIT,
    ['8'] = SGX_CTYPE_ISDIGIT | SGX_CTYPE_ISXDIGIT,
    ['9'] = SGX_CTYPE_ISDIGIT | SGX_CTYPE_ISXDIGIT,

    // Upper hex
    ['A'] = SGX_CTYPE_ISUPPER | SGX_CTYPE_ISALPHA | SGX_CTYPE_ISXDIGIT,
    ['B'] = SGX_CTYPE_ISUPPER | SGX_CTYPE_ISALPHA | SGX_CTYPE_ISXDIGIT,
    ['C'] = SGX_CTYPE_ISUPPER | SGX_CTYPE_ISALPHA | SGX_CTYPE_ISXDIGIT,
    ['D'] = SGX_CTYPE_ISUPPER | SGX_CTYPE_ISALPHA | SGX_CTYPE_ISXDIGIT,
    ['E'] = SGX_CTYPE_ISUPPER | SGX_CTYPE_ISALPHA | SGX_CTYPE_ISXDIGIT,
    ['F'] = SGX_CTYPE_ISUPPER | SGX_CTYPE_ISALPHA | SGX_CTYPE_ISXDIGIT,

    // Lower hex
    ['a'] = SGX_CTYPE_ISLOWER | SGX_CTYPE_ISALPHA | SGX_CTYPE_ISXDIGIT,
    ['b'] = SGX_CTYPE_ISLOWER | SGX_CTYPE_ISALPHA | SGX_CTYPE_ISXDIGIT,
    ['c'] = SGX_CTYPE_ISLOWER | SGX_CTYPE_ISALPHA | SGX_CTYPE_ISXDIGIT,
    ['d'] = SGX_CTYPE_ISLOWER | SGX_CTYPE_ISALPHA | SGX_CTYPE_ISXDIGIT,
    ['e'] = SGX_CTYPE_ISLOWER | SGX_CTYPE_ISALPHA | SGX_CTYPE_ISXDIGIT,
    ['f'] = SGX_CTYPE_ISLOWER | SGX_CTYPE_ISALPHA | SGX_CTYPE_ISXDIGIT,
};

const unsigned short int** __ctype_b_loc(void) {
    // glibc returns a pointer to a pointer.
    static const unsigned short int* table = sgx_ctype_b;
    return &table;
}

// --- Fortify wrappers (glibc) ---
// We don't support FILE output; we just format into the destination if applicable.

int __sprintf_chk(char* s, int flag, size_t slen, const char* fmt, ...) {
    (void)flag;
    va_list ap;
    va_start(ap, fmt);
    // vsnprintf is provided by SGX tlibc.
    extern int vsnprintf(char*, size_t, const char*, va_list);
    int ret = vsnprintf(s, slen, fmt, ap);
    va_end(ap);
    return ret;
}

int __snprintf_chk(char* s, size_t maxlen, int flag, size_t slen, const char* fmt, ...) {
    (void)flag;
    (void)slen;
    va_list ap;
    va_start(ap, fmt);
    extern int vsnprintf(char*, size_t, const char*, va_list);
    int ret = vsnprintf(s, maxlen, fmt, ap);
    va_end(ap);
    return ret;
}

int __vsnprintf_chk(char* s, size_t maxlen, int flag, size_t slen, const char* fmt, va_list ap) {
    (void)flag;
    (void)slen;
    extern int vsnprintf(char*, size_t, const char*, va_list);
    return vsnprintf(s, maxlen, fmt, ap);
}

int __fprintf_chk(FILE* stream, int flag, const char* fmt, ...) {
    (void)stream;
    (void)flag;
    // Best-effort: drop output (we cannot print to FILE in enclaves).
    (void)fmt;
    return 0;
}

int __vfprintf_chk(FILE* stream, int flag, const char* fmt, va_list ap) {
    (void)stream;
    (void)flag;
    (void)fmt;
    (void)ap;
    return 0;
}

// --- stdio stubs ---

int puts(const char* s) {
    (void)s;
    return 0;
}

int putc(int c, FILE* stream) {
    (void)c;
    (void)stream;
    return c;
}

int fputc(int c, FILE* stream) {
    (void)c;
    (void)stream;
    return c;
}

int fputs(const char* s, FILE* stream) {
    (void)s;
    (void)stream;
    return 0;
}

size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream) {
    (void)ptr;
    (void)stream;
    return nmemb;
}

int ferror(FILE* stream) {
    (void)stream;
    return 0;
}

// --- minimal "file" API used by libpbc random seeding ---
// libpbc tries to read randomness from /dev/urandom. We emulate that source using sgx_read_rand().
struct SGX_FILE {
    int kind; // 1 = urandom
};

FILE* fopen(const char* path, const char* mode) {
    (void)mode;
    if (path != NULL && strcmp(path, "/dev/urandom") == 0) {
        static struct SGX_FILE f = {1};
        return (FILE*)&f;
    }
    return (FILE*)0;
}

size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream) {
    if (ptr == NULL || stream == NULL) {
        return 0;
    }
    struct SGX_FILE* f = (struct SGX_FILE*)stream;
    if (f->kind != 1) {
        return 0;
    }
    size_t total = size * nmemb;
    if (total == 0) {
        return 0;
    }
    if (sgx_read_rand((unsigned char*)ptr, total) != SGX_SUCCESS) {
        return 0;
    }
    return nmemb;
}

int fclose(FILE* stream) {
    (void)stream;
    return 0;
}

// --- misc stubs ---

int rand(void) {
    // Deterministic fallback. (We do not rely on rand() inside the enclave.)
    static uint32_t x = 0x12345678u;
    x = x * 1103515245u + 12345u;
    return (int)((x >> 16) & 0x7fff);
}

void srand(unsigned int seed) {
    (void)seed;
}

int raise(int sig) {
    (void)sig;
    return 0;
}

char* nl_langinfo(int item) {
    (void)item;
    // A minimal decimal point representation is sufficient for the few formatting paths that may query it.
    static char dot[] = ".";
    return dot;
}

int vfprintf(FILE* stream, const char* fmt, va_list ap) {
    (void)stream;
    (void)fmt;
    (void)ap;
    return 0;
}

void exit(int status) {
    (void)status;
    // If a fatal code path triggers exit inside an enclave, abort execution.
    abort();
}
