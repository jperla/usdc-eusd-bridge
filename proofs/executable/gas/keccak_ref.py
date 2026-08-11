#!/usr/bin/env python3
"""Reference Keccak-f[1600], to verify the Solidity version against."""
RHO = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
       41, 45, 15, 21, 8, 18, 2, 61, 56, 14]
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
      0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
      0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
      0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
      0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
      0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
      0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
M = (1 << 64) - 1
def rol(x, n): return ((x << n) | (x >> (64 - n))) & M if n else x

def keccak_f1600(a):
    a = list(a)
    for rnd in range(24):
        c = [a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20] for x in range(5)]
        d = [c[(x+4) % 5] ^ rol(c[(x+1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(0, 25, 5):
                a[y+x] ^= d[x]
        b = [0]*25
        for x in range(5):
            for y in range(5):
                b[y*5 + ((2*x + 3*y) % 5)] = rol(a[y*5 + x], RHO[y*5 + x])
        # NOTE: pi maps (x,y) -> (y, 2x+3y); index below is [newy*5+newx]
        b2 = [0]*25
        for x in range(5):
            for y in range(5):
                b2[((2*x + 3*y) % 5)*5 + y] = rol(a[y*5 + x], RHO[y*5 + x])
        b = b2
        for y in range(0, 25, 5):
            t = b[y:y+5]
            for x in range(5):
                a[y+x] = t[x] ^ ((~t[(x+1) % 5] & M) & t[(x+2) % 5])
        a[0] ^= RC[rnd]
    return a

if __name__ == "__main__":
    import sys
    st = [0]*25
    out = keccak_f1600(st)
    print("keccak_f1600(all-zero) first 4 lanes:")
    for v in out[:4]:
        print(f"  0x{v:016x}")
