#include <cstdio>
#include <chrono>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include "../symmetric/Yux-F_p.h"
#include <cmath>

using namespace std;
using namespace std::chrono;
namespace fs = std::filesystem;

void test_encryption(int Nr, int test_round, const vector<vector<uint64_t>>& test_data) {
    // const int NUM_ITERATIONS = test_data.size();
    int i, Nk = 16;
    long plain_mod = 65537;
    long roundKeySize = (Nr + 1) * Nk;
    uint64_t in[Nk], enced[Nk], Key[Nk], RoundKey[roundKeySize];
    uint64_t temp3[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint64_t plain1[16] = {0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999,
                           0x09999, 0x09999, 0x09999, 0x09999,0x09999, 0x09999, 0x09999, 0x09999};

    // Initialize key
    for(i = 0; i < Nk; i++) {
        Key[i] = temp3[i];
    }

    Yux_F_p cipher = Yux_F_p(Nk, Nr, plain_mod);
    
    // Key expansion
    cipher.KeyExpansion(RoundKey, Key);
    
    // Warm-up 
    for(i = 0; i < Nk; i++) {
        in[i] = plain1[i];
    }
    cipher.encryption(enced, in, RoundKey);

    // Timing
    long total_time = 0;
    // high_resolution_clock::time_point start, end;

    for(int iter = 0; iter < test_round; iter++) {
        // Load test data
        for(i = 0; i < Nk; i++) {
            in[i] = test_data[iter][i];
        }

        auto start = high_resolution_clock::now();
        cipher.encryption(enced, in, RoundKey);
        auto end = high_resolution_clock::now();
        auto diff = duration_cast<nanoseconds>(end - start);
        total_time += diff.count();
    }

    // running time (s)
    double avg_time = total_time / 1e9 / test_round;

    cout << "Nr = " << Nr << " Test results: " << endl;    

    // cout << "Average symmetric encryption time over " << test_round << " runs: " 
    //     << fixed << setprecision(2) << avg_time 
    //     << " seconds" << endl;
    
    printf("Average symmetric encryption time over %d runs: %.2e seconds\n", 
       test_round, avg_time);

    // Throughput (KB/min)
    double throughput = (256.0 * 60.0 * pow(2, -13)) / avg_time; 

    cout << "Average throughput over " << test_round << " runs: " 
         << fixed << setprecision(2) << throughput 
         << " KB/min" << endl;

}

vector<vector<uint64_t>> read_test_data(const string& filename, int test_data_num) {
    vector<vector<uint64_t>> test_data;
    ifstream file(filename);
    
    if (!file.is_open()) {
        cerr << "Error: Could not open file " << filename << endl;
        return test_data;
    }
    
    for (int i = 0; i < test_data_num; i++) {
        vector<uint64_t> data;
        uint64_t value;
        
        // Read 16 hex values per line
        for (int j = 0; j < 16; j++) {
            if (!(file >> hex >> value)) {
                cerr << "Error: Failed to read value" << endl;
                return test_data;  // If there's an error, exit early
            }
            data.push_back(value);
        }
        
        test_data.push_back(data);
    }
    
    file.close();
    return test_data;
}

int main() {

    const int TEST_ROUND = 1000;
    vector<vector<uint64_t>> test_data = read_test_data("../tests/random-plain.txt", TEST_ROUND);
    
    if (test_data.size() != TEST_ROUND) {
        cerr << "Error: Failed to read test data" << endl;
        return 1;
    }
    
    // Testing 3 kinds of rounds
    int param_rounds[] = {9, 12, 14};
    
    for(int nr : param_rounds) {
        test_encryption(nr, TEST_ROUND, test_data);
    }

    return 0;
}