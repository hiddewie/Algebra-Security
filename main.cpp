#include <iostream>
#include <stdio.h>
#include <vector>
#include <time.h>
#include <limits>
#include <map>
#include <set>
#include <thread>
#include <fstream>

using namespace std;

#define P8 (1<<8)

typedef uint8_t byte;

/** Inverse of x, seen as a polynomial in GF(2^8) **/
byte GF2p8Inv[] = {
     0, 1, 141, 246, 203, 82, 123, 209, 232, 79, 41, 192, 176, 225, 229, 199,
     116, 180, 170, 75, 153, 43, 96, 95, 88, 63, 253, 204, 255, 64, 238, 178,
     58, 110, 90, 241, 85, 77, 168, 201, 193, 10, 152, 21, 48, 68, 162, 194,
     44, 69, 146, 108, 243, 57, 102, 66, 242, 53, 32, 111, 119, 187, 89, 25,
     29, 254, 55, 103, 45, 49, 245, 105, 167, 100, 171, 19, 84, 37, 233, 9,
     237, 92, 5, 202, 76, 36, 135, 191, 24, 62, 34, 240, 81, 236, 97, 23,
     22, 94, 175, 211, 73, 166, 54, 67, 244, 71, 145, 223, 51, 147, 33, 59,
     121, 183, 151, 133, 16, 181, 186, 60, 182, 112, 208, 6, 161, 250, 129, 130,
     131, 126, 127, 128, 150, 115, 190, 86, 155, 158, 149, 217, 247, 2, 185, 164,
     222, 106, 50, 109, 216, 138, 132, 114, 42, 20, 159, 136, 249, 220, 137, 154,
     251, 124, 46, 195, 143, 184, 101, 72, 38, 200, 18, 74, 206, 231, 210, 98,
     12, 224, 31, 239, 17, 117, 120, 113, 165, 142, 118, 61, 189, 188, 134, 87,
     11, 40, 47, 163, 218, 212, 228, 15, 169, 39, 83, 4, 27, 252, 172, 230,
     122, 7, 174, 99, 197, 219, 226, 234, 148, 139, 196, 213, 157, 248, 144, 107,
     177, 13, 214, 235, 198, 14, 207, 173, 8, 78, 215, 227, 93, 80, 30, 179,
     91, 35, 56, 52, 104, 70, 3, 140, 221, 156, 125, 160, 205, 26, 65, 28,

},
/** Encrypts one round of WES **/
WESRoundEncrypt[] = {
     0, 2, 27, 237, 151, 164, 246, 163, 209, 158, 82, 129, 97, 195, 203, 143,
     232, 105, 85, 150, 51, 86, 192, 190, 176, 126, 251, 153, 255, 128, 221, 101,
     116, 220, 180, 227, 170, 154, 81, 147, 131, 20, 49, 42, 96, 136, 69, 133,
     88, 138, 37, 216, 231, 114, 204, 132, 229, 106, 64, 222, 238, 119, 178, 50,
     58, 253, 110, 206, 90, 98, 235, 210, 79, 200, 87, 38, 168, 74, 211, 18,
     219, 184, 10, 149, 152, 72, 15, 127, 48, 124, 68, 225, 162, 217, 194, 46,
     44, 188, 95, 167, 146, 77, 108, 134, 233, 142, 35, 191, 102, 39, 66, 118,
     242, 111, 47, 11, 32, 107, 117, 120, 109, 224, 161, 12, 67, 245, 3, 5,
     7, 252, 254, 1, 45, 230, 125, 172, 55, 61, 43, 179, 239, 4, 115, 73,
     189, 212, 100, 218, 177, 21, 9, 228, 84, 40, 63, 17, 243, 185, 19, 53,
     247, 248, 92, 135, 31, 113, 202, 144, 76, 145, 36, 148, 157, 207, 165, 196,
     24, 193, 62, 223, 34, 234, 240, 226, 75, 29, 236, 122, 123, 121, 13, 174,
     22, 80, 94, 71, 181, 169, 201, 30, 83, 78, 166, 8, 54, 249, 89, 205,
     244, 14, 93, 198, 139, 183, 197, 213, 41, 23, 137, 171, 59, 241, 33, 214,
     99, 26, 173, 215, 141, 28, 159, 91, 16, 156, 175, 199, 186, 160, 60, 103,
     182, 70, 112, 104, 208, 140, 6, 25, 187, 57, 250, 65, 155, 52, 130, 56,
},
/** Decrypts one round of WES **/
WESRoundDecrypt[] = {
     0, 131, 1, 126, 141, 127, 246, 128, 203, 150, 82, 115, 123, 190, 209, 86,
     232, 155, 79, 158, 41, 149, 192, 217, 176, 247, 225, 2, 229, 185, 199, 164,
     116, 222, 180, 106, 170, 50, 75, 109, 153, 216, 43, 138, 96, 132, 95, 114,
     88, 42, 63, 20, 253, 159, 204, 136, 255, 249, 64, 220, 238, 137, 178, 154,
     58, 251, 110, 124, 90, 46, 241, 195, 85, 143, 77, 184, 168, 101, 201, 72,
     193, 38, 10, 200, 152, 18, 21, 74, 48, 206, 68, 231, 162, 210, 194, 98,
     44, 12, 69, 224, 146, 31, 108, 239, 243, 17, 57, 117, 102, 120, 66, 113,
     242, 165, 53, 142, 32, 118, 111, 61, 119, 189, 187, 188, 89, 134, 25, 87,
     29, 11, 254, 40, 55, 47, 103, 163, 45, 218, 49, 212, 245, 228, 105, 15,
     167, 169, 100, 39, 171, 83, 19, 4, 84, 27, 37, 252, 233, 172, 9, 230,
     237, 122, 92, 7, 5, 174, 202, 99, 76, 197, 36, 219, 135, 226, 191, 234,
     24, 148, 62, 139, 34, 196, 240, 213, 81, 157, 236, 248, 97, 144, 23, 107,
     22, 177, 94, 13, 175, 214, 211, 235, 73, 198, 166, 14, 54, 207, 67, 173,
     244, 8, 71, 78, 145, 215, 223, 227, 51, 93, 147, 80, 33, 30, 59, 179,
     121, 91, 183, 35, 151, 56, 133, 52, 16, 104, 181, 70, 186, 3, 60, 140,
     182, 221, 112, 156, 208, 125, 6, 160, 161, 205, 250, 26, 129, 65, 130, 28,
};

/** Stores a WES key **/
struct WESKey {
    byte k1, k2, k3;
    bool operator== (const WESKey &comp) {
       return (k1 == comp.k1 && k2 == comp.k2 && k3 == comp.k3);
    }
};
/** Stores a TripleWES key **/
struct TripleWESKey {
    byte white;
    WESKey k1, k2, k3;
    bool operator== (const TripleWESKey &comp) {
       return (white == comp.white && k1 == comp.k1 && k2 == comp.k2 && k3 == comp.k3);
    }
};

/** Finds the hex string of a byte **/
string getHex (byte b) {
    char s[8];
    sprintf(s, "%#x", b);
    return s;
}
/** Finds the hex string of an integer **/
string getHex (int b) {
    char s[32];
    sprintf(s, "%#x", b);
    return s;
}
/** Finds the hex string of an unsigned integer **/
string getHex (unsigned int b) {
    char s[32];
    sprintf(s, "%#x", b);
    return s;
}
/** Finds the hex string of a WES key **/
string getHex (WESKey k) {
    return "{" + getHex(k.k1) + ", " + getHex(k.k2) + ", " + getHex(k.k3) + "}";
}
/** Finds the hex string of a TripleWES key **/
string getHex (TripleWESKey k) {
    return "{" + getHex(k.white) + ", " + getHex(k.k1) + ", " + getHex(k.k2) + ", " + getHex(k.k3) + "}";
}
/** Encrypts a byte, using the given key **/
byte WESEncrypt (byte b, WESKey k) {
    return WESRoundEncrypt[WESRoundEncrypt[WESRoundEncrypt[b] ^ k.k1] ^ k.k2] ^ k.k3;
}
/** Decrypts a byte, using the given key **/
byte WESDecrypt(byte b, WESKey k) {
    return WESRoundDecrypt[WESRoundDecrypt[WESRoundDecrypt[b ^ k.k3] ^ k.k2] ^ k.k1];
}
/** TripleWES encrypts a byte, using the given key **/
byte TripleWESEncrypt (byte b, TripleWESKey k) {
    return WESEncrypt(WESEncrypt(WESEncrypt(b ^ k.white, k.k1), k.k2), k.k3);
}
/** TripleWES decrypts a byte, using the given key **/
byte TripleWESDecrypt(byte b, TripleWESKey k) {
    return k.white ^ WESDecrypt(WESDecrypt(WESDecrypt(b, k.k3), k.k2), k.k1);
}

/** Tests the WES encryption and decryption **/
void testWES () {
    byte input = 190;
    WESKey key = {0xFF, 0xFF, 0xFF};
    cout << "Testing input " << getHex(input) << " with key " << getHex(key)<< endl;
    cout << "Encryption: " << getHex(WESEncrypt(input, key)) << endl;
    cout << "Decryption: " << getHex(WESDecrypt(WESEncrypt(input, key), key)) << endl;
}

/** Tests the TripleWES encryption and decryption **/
void testTripleWES () {
    byte input = 0x41;
    TripleWESKey key = {0x01, {0x03, 0x07, 0x0f}, {0x1f, 0x3f, 0x7f}, {0xfe, 0xfc, 0xf8}};
    cout << "Testing input " << getHex(input) << " with key " << getHex(key)<< endl;
    cout << "Encryption: " << getHex(TripleWESEncrypt(input, key)) << endl;
    cout << "Decryption: " << getHex(TripleWESDecrypt(TripleWESEncrypt(input, key), key)) << endl;
}

/** Prints a message **/
void message (string m) {
    cout << "--- " << m << " ---" << endl;
}
/** Prints a progress bar **/
void printProcessBar () {
    cout << '[';
    cout << 0;
    for (int i = 0; i < 30; i++) cout << '-';
    cout << 50;
    for (int i = 0; i < 28; i++) cout << '-';
    cout << 100;
    cout << ']' << endl;
}
/** Prints a progress character **/
void process(char c) {
    cout << c;
}
/** Prints a '.' as a process character **/
void process () {
    process('.');
}
/** Starts a progress bar with a message **/
void startProcess (string desc) {
    message(desc);
    cout << '[';
}
/** Starts a progress bar **/
void startProcess () {
    cout << '[';
}
/** Finishes a progress bar **/
void finishProccess () {
    cout << ']' << endl;
}

/** Variables for timing the execution **/
clock_t startTime = clock();
vector<float> foundKeyTimes;

/** Gets the time as a float **/
float getFloatTime (time_t t) {
    return ((float) t) / CLOCKS_PER_SEC;
}

/** prints the time **/
void printTime () {
    cout << "    @ " << getFloatTime(clock() - startTime) << " seconds" << endl;
}

/** Found keys, and output **/
/*
Bronze:
{0, {0x5a, 0xee, 0x1b}, {0xca, 0xb2, 0x87}, {0x87, 0x87, 0x87}}
algebra and security 191511410
*/
/*
Silver:
136 s
{0x6, {0x98, 0xbc, 0xaf}, {0x9e, 0x5b, 0x7b}, {0x9c, 0x9c, 0x9c}}
Evariste Galois 1811 1832 20yo
*/
/*
Gold:
{0xb7, {0x70, 0x15, 0x40}, {0x3, 0xf1, 0x7f}, {0x2b, 0xd2, 0xd2}}
EF36 EF37 EF37A 6J5 6V6 6K8 807 GT1C

[0------------------------------50----------------------------100]
--- Generating reverse save table ---
[................................................................]
--- Sorting reverse save table ---
[................................................................]
    @ 2.281 seconds
--- Finding keys from back ---
[...............!................................................]
--- Done generating keys from back ---
1 possible keys found
    @ 36986 seconds

Key {0xb7, {0x70, 0x15, 0x40}, {0x3, 0xf1, 0x7f}, {0x2b, 0xd2, 0xd2}} (found at
9085.69 seconds):
EF36 EF37 EF37A 6J5 6V6 6K8 807 GT1C

--- Releasing memory ---
    @ 36986 seconds
--- Done ---
    @ 36986 seconds

*/

/** Supplied cyphertext, which has to be decrypted **/
byte bronzeCypher[] = {0x0f, 0xf6, 0xa3, 0x62, 0xa5, 0xb5, 0x0f, 0xca, 0x0f, 0x92, 0x27, 0xca, 0x13, 0x62, 0x14, 0xbb, 0xb5, 0xc0, 0xbf, 0x81, 0xca, 0x89, 0x20, 0x89, 0xa4, 0x89, 0x89, 0xc7, 0x89, 0x4b};
int bronzeCypherSize = 30;
byte silverCypher[] = {0xd0, 0xae, 0x4f, 0x7c, 0xcf, 0xea, 0xa6, 0x2d, 0xd8, 0xe8, 0x4f, 0x50, 0x7d, 0xcf, 0xea, 0xd8, 0x42, 0x8d, 0x42, 0x42, 0xd8, 0x42, 0x8d, 0x24, 0xf3, 0xd8, 0xf3, 0x5c, 0xcc, 0x7d};
int silverCypherSize = 30;
byte goldCypher[] = {0xd6, 0x6c, 0x19, 0x3a, 0x5d, 0xd6, 0x6c, 0x19, 0xf3, 0x5d, 0xd6, 0x6c, 0x19, 0xf3, 0x43, 0x5d, 0x3a, 0x37, 0x7b, 0x5d, 0x3a, 0x1d, 0x3a, 0x5d, 0x3a, 0xe7, 0x77, 0x5d, 0x77, 0xf0, 0xf3, 0x5d, 0x0c, 0x9d, 0x4d, 0xf7};
int goldCypherSize = 36;

/** Supplied plain-cyphertext pairs **/
byte bronze[] = {
    0xfd, // 0x41
    0x2f,
    0x1a,
    0xcd,
    0x06,
    0x8b,
    0x1b,
    0xbc,
    0x1e,
    0x53,
    0x50,
    0xd4, // 0x4c
}, silver[] = {
    0x51, // 0x41
    0xc4,
    0x8e,
    0xcb,
    0xd0,
    0xa0,
    0xe8,
    0x88,
    0xe4,
    0x9e,
    0xf5,
    0x3b, // 0x4c
}, gold[] = {
    0x43, // 0x41
    0x10,
    0xf7,
    0x76,
    0xd6,
    0x6c,
    0x0c,
    0x29,
    0x97,
    0x37,
    0xe7,
    0x98, // 0x4c
};

/**
    Explanation on the lookup table:
    Stored as a linked list. Each node consists of two things: a value and a pointer to the next node in its sequence.
    In total there are 0x1000000 elements, divided over 0x1000000 sequences (not evenly!).
    The table is sorted to make sure less memory is swapped into the CPU.
**/

/** Size of the lookup table **/
const long long sSize = 0x1000000 * 2 * 1;
const long long fSize = 0x1000000;

/** Lookup table **/
long long* save = new long long[sSize];
/** Pointers to the last occurence of the lookup **/
long long* f[fSize];
/** Pointers to the first place of the lookup **/
long long* fStart[fSize];
/** The current place in the linked list **/
long long* current;

/** Same as above, for the sorted table **/
long long* sortedSave = new long long[sSize];
long long* sortedF[fSize];
long long* sortedFStart[fSize];
long long* sortedCurrent;

/** All the found keys, independent of the threading **/
vector<TripleWESKey> foundKeys;

/** Prints all the found keys, and decrypts the cyphertext **/
void printKeys (byte cypherText[], int cypherTextSize) {
    for (int i = 0; i < (int) foundKeys.size(); i++) {
        cout << "Key " << getHex(foundKeys[i]) << " (found at " << foundKeyTimes[i] << " seconds): " << endl;
        for (int j = 0; j < cypherTextSize; j++) {
            cout << TripleWESDecrypt(cypherText[j], foundKeys[i]);
        }
        cout << endl << endl;
    }
}

/** Initializes the tables, builds the tables and sorts the tables **/
void init () {
    int i, j, k[3];
    byte enc[4];
    long long *start;

    for (i = 0; i < fSize; i++) {
        f[i] = 0;
        fStart[i] = 0;
        sortedFStart[i] = 0;
    }
    for (i = 0; i < sSize; i++) {
        save[i] = 0;
        sortedSave[i] = 0;
    }
    current = save;
    sortedCurrent = sortedSave;

    startProcess("Generating reverse save table");
    for (k[0] = 0x00; k[0] <= 0xFF; k[0]++) {
        for (k[1] = 0x00; k[1] <= 0xFF; k[1]++) {
            for (k[2] = 0x00; k[2] <= 0xFF; k[2]++) {
                /** Encrypt 4 plaintexts **/
                for (j = 0; j < 4; j++) {
                    enc[j] = WESRoundEncrypt[WESRoundEncrypt[WESRoundEncrypt[(0x41 + j) ^ k[0]] ^ k[1]] ^ k[2]];
                }

                /** Save the differences (XORed) in an integer **/
                i = (enc[0] ^ enc[1]) | ((enc[1] ^ enc[2]) << 8) | ((enc[2] ^ enc[3]) << 16);
                /** Put the value into the lookup table **/
                *current = ((enc[0] << 24) | (k[0] << 16) | (k[1] << 8) | k[2]) ;
                if (f[i]) {
                    *(f[i] + 1) = (long long) current;
                } else {
                    fStart[i] = current;
                }
                f[i] = current;
                current += 2;
            }
        }
        if (k[0] % 4 == 0) {
            process();
        }
    }
    finishProccess();

    /** Sort the lookup table for more efficient lookups **/
    startProcess("Sorting reverse save table");
    for (int key = 0x000000; key <= 0xFFFFFF; key++) {
        start = fStart[key];
        while (start) {
            *sortedCurrent = *start;
            if (sortedF[key]) {
                *(sortedF[key] + 1) = (long long) sortedCurrent;
            } else {
                sortedFStart[key] = sortedCurrent;
            }
            sortedF[key] = sortedCurrent;
            sortedCurrent += 2;

            start = (long long*) *(start + 1);
        }
        if (key % 0x40000 == 0x40000 - 1) {
            process();
        }
    }
    finishProccess();

    FILE *pFile = fopen ("foundKeys.txt", "w");
    fclose(pFile);
}

/** Number of threads to run **/
const int numThreads = 16;
/** Whether any keys have been found (only for indication in the progress bar) **/
bool found = false;
/** Number of loops done (only for indication in the progress bar) **/
int progress = 0;

/** Tests all keys using the lookup table, in the specified keyspace **/
void testKeys (int k5Lower, int k5Upper, int k6Lower, int k6Upper, int k7Lower, int k7Upper, int k8Lower, int k8Upper, int k9Lower, int k9Upper, bool equal78, bool equal89, byte cypher[]) {
    int k[10], d, j;
    byte between[12], dec[4];
    long long *start;
    bool error;
    int progressLimit = ((k9Upper - k9Lower) * (equal89 ? 1 : (k8Upper - k8Lower))) / 4;

    /** Search for keys 4 to 8 for gold **/
    for (k[8] = k9Lower; k[8] < k9Upper; k[8]++) {
        for (k[7] = (equal89 ? k[8] : k8Lower); k[7] < (equal89 ? k[8] + 1 : k8Upper); k[7]++) {
            for (k[6] = (equal78 ? k[7] : k7Lower); k[6] < (equal78 ? k[7] + 1 : k7Upper); k[6]++) {
                for (j = 0; j < 12; j++) {
                    between[j] = WESRoundDecrypt[
                                WESRoundDecrypt[
                                WESRoundDecrypt[
                                WESRoundDecrypt[
                                    cypher[j] ^ k[8]
                                ] ^ k[8]
                                ] ^ k[7]
                                ] ^ k[6]
                                ];
                }
                for (k[5] = k6Lower; k[5] < k6Upper; k[5]++) {
                    for (k[4] = k5Lower; k[4] < k5Upper; k[4]++) {
                        /** Decrypt 4 cyphertexts **/
                        for (j = 0; j < 4; j++) {
                            dec[j] = WESRoundDecrypt[
                                    WESRoundDecrypt[
                                        between[j] ^ k[5]
                                    ] ^ k[4]
                                    ];
                        }
                        /** Lookup the 3 differences in the table **/
                        d = (dec[0] ^ dec[1]) | ((dec[1] ^ dec[2]) << 8) | ((dec[2] ^ dec[3]) << 16);
                        start = sortedFStart[d];
                        while (start) {
                            /** Extract k0, k1 and k2 from the table **/
                            k[0] = (byte) ((0xFF0000 & (*start)) >> 16);
                            k[1] = (byte) ((0xFF00 & (*start)) >> 8);
                            k[2] = (byte) ((0xFF & (*start)) >> 0);
                            /** Generate k3 from the two sides **/
                            k[3] = ((byte) ((0xFF000000 & (*start)) >> 24)) ^ dec[0];

                            error = false;
                            /** Test each possible key, whether the plain-cyphertext pairs match **/
                            for (j = 3; j < 12; j++) {
                                if (
                                    (
                                       WESRoundEncrypt[
                                       WESRoundEncrypt[
                                       WESRoundEncrypt[

                                       (0x41 + j) ^ k[0]

                                       ] ^ k[1]
                                       ] ^ k[2]
                                       ] ^
                                    (WESRoundDecrypt[
                                        WESRoundDecrypt[
                                            between[j] ^ k[5]
                                        ] ^ k[4]
                                        ]))
                                    != k[3]) {
                                    error = true;
                                    break;
                                }
                            }
                            if (!error) {
                                /** Save the found key **/
                                TripleWESKey foundKey = {(byte) k[0], {(byte) k[1], (byte) k[2], (byte) k[3]}, {(byte) k[4], (byte) k[5], (byte) k[6]}, {(byte) k[7], (byte) k[8], (byte) k[8]}};
                                foundKeys.push_back(foundKey);
                                foundKeyTimes.push_back(getFloatTime(clock() - startTime));

                                /** Print the found key to a file **/
                                ofstream file;
                                file.open ("foundKeys.txt", ios::out | ios::app);
                                file << getHex(foundKey);
                                file.close();

                                found = true;
                            }
                            /** Get the pointer to the next key in the list **/
                            start = (long long*) *(start + 1);
                        }
                    }
                }
            }
            progress ++;
            if (progress % progressLimit == (progressLimit - 1)) {
                if (found) {
                    process('!');
                    found = false;
                } else {
                    process();
                }
            }
        }
    }
}

int main() {
    printProcessBar();

    init();

    printTime ();
    startProcess("Finding keys from back");

    /** Spawn threads which search the entire key-space together **/
    thread t[numThreads];
    for (int j = 0; j < numThreads; j++) {
        t[j] = thread(testKeys, 16 * j, 16 * (j+1), 0x00, 0x100, 0x00, 0x100, 0x00, 0x100, 0x00, 0x100, true, true, bronze  );
    }
    for (int j = 0; j < numThreads; j++) {
        t[j].join();
    }

    finishProccess();

    message("Done generating keys from back");
    cout << foundKeys.size() << " possible keys found" << endl;

    printTime();

    cout << endl;

    printKeys (bronzeCypher, bronzeCypherSize);

    message("Releasing memory");
    printTime();
    message("Done");
    printTime();

    return 0;
}
