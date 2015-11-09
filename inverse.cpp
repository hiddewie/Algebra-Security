#include <iostream>
#include <stdio.h>
/*
using namespace std;

uint8_t numbits (uint16_t z) {
    uint8_t ret = 0;

    while (z > 0) {
        if (z & 1) {
            ret ++;
        }
        z >>= 1;
    }

    return ret;
}

uint8_t ginv(uint8_t x)
    {
        uint16_t u1, u3, v1, v3;

        u1 = 0; u3 = 0x11b;
        v1 = 1; v3 = x;

        for (;;) {
            uint16_t t1, t3, x, y;

            if (v3 == 0) break;

            x = u3; x |= x>>1; x |= x>>2; x |= x>>4;
            y = v3; y |= y>>1; y |= y>>2; y |= y>>4;
            if (x >= y) {
                uint16_t z = x & ~y;
                uint8_t q = numbits(z);
                t1 = u1 ^ (v1<<q);
                t3 = u3 ^ (v3<<q);
            } else {
                t1 = u1;
                t3 = u3;
            }
            u1 = v1; u3 = v3;
            v1 = t1; v3 = t3;
        }

        if (u1 >= 0x100) u1 ^= 0x11b;

        return u1;
    }

void printInverses () {
    cout << "{ ";
    for (int i = 0; i < 256; i+=16) {
        cout << " ";
        for (int j = i; j < i+16; j++) {
            cout << (int) leftShift(ginv(j)) << ", ";
        }
        cout << endl;
    }
    cout << "};" << endl;

    cout << "{ ";
    for (int i = 0; i < 256; i+=16) {
        cout << " ";
        for (int j = i; j < i+16; j++) {
            cout << (int) (ginv(rightShift(j))) << ", ";
        }
        cout << endl;
    }
    cout << "};" << endl;
}
*/
