#include <cstdio>
#include <chrono>
#include <iostream>
#include "../Yux/Yux-dagger-F_p.h"
#include <cmath>

using namespace std;
using namespace std::chrono;

void test_encryption(int Nr) {
    const int NUM_ITERATIONS = 1000;
    int i, Nk = 16;
    long roundKeySize = (Nr + 1) * Nk;
    uint64_t in[Nk], enced[Nk], Key[Nk], RoundKey[roundKeySize];

    // Initialize plaintext and key
    uint64_t plain1[16] = {0x09999, 0x09999, 0x09999, 0x09999, 
                          0x09999, 0x09999, 0x09999, 0x09999,
                          0x09999, 0x09999, 0x09999, 0x09999,
                          0x09999, 0x09999, 0x09999, 0x09999};
    uint64_t temp3[16] = {0x00};

    for(i = 0; i < Nk; i++) {
        Key[i] = temp3[i];
        in[i] = plain1[i];
    }

    Yux_dagger_F_p cipher = Yux_dagger_F_p(Nk, Nr, 65537);
    
    // Key expansion
    cipher.KeyExpansion(RoundKey, Key);
    
    // Warm-up
    cipher.encryption(enced, in, RoundKey);

    // Timing
    auto total_duration = 0ns;
    high_resolution_clock::time_point start, end;

    for(int iter = 0; iter < NUM_ITERATIONS; iter++) {
        start = high_resolution_clock::now();
        cipher.encryption(enced, in, RoundKey);
        end = high_resolution_clock::now();
        auto duration = duration_cast<nanoseconds>(end - start);
        total_duration += duration;
    }

    auto avg_duration = total_duration / NUM_ITERATIONS;

    // output
    printf("\nNr = %d Test results:\n", Nr);
    printf("Average time for 1000 encryptions: %lld Nanosecond\n", avg_duration.count());
    // printf("Total time: %lld Nanosecond\n", total_duration.count());

    // Thoughput (KB/min)
    double avg_seconds = avg_duration.count() / 1e9;  
    double throughput = (256.0 * 60.0 * pow(2, -13)) / avg_seconds;  
    printf("Average throughput for 1000 encryptions: %.2f KB/min\n", throughput);

    // Verification of decryption
    uint64_t RoundKey_invert[roundKeySize];
    cipher.decRoundKey(RoundKey_invert, RoundKey);
    uint64_t deced[Nk];
    cipher.decryption(deced, enced, RoundKey_invert);
    
    bool success = true;
    for(i = 0; i < Nk; i++) {
        if(deced[i] != in[i]) {
            success = false;
            break;
        }
    }
    printf("Decryption verification: %s\n\n", success ? "Success" : "Failure");
}

int main() {
    // Testing 3 kinds of rounds
    int test_rounds[] = {9, 12, 14};
    
    for(int nr : test_rounds) {
        test_encryption(nr);
    }

    return 0;
}