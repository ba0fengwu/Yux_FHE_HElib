#include <cstring>
#include <stdint.h>
#include <chrono>
#include <helib/helib.h>
#include <fstream>
#include <vector>
#include <iomanip>
#include "../transciphering/transciphering-dagger-F_p-16.h"

using namespace helib;
using namespace std;
using namespace NTL;

// #define homDec

static long mValues[][4] = { 
  { 65537,  65536,  853, 17},
  { 65537,  131072,  1320, 6},
  { 65537,  131072,  1400, 10},
};


void test_homo_decryption(int test_round, const vector<vector<uint64_t>>& test_data) {
    int i, Nr = pROUND;// Nr is round number
    int Nk = 16;// a block has Nk Words
    int nBlocks = 1;
    long plain_mod = 65537;
    long roundKeySize = (Nr + 1) * Nk;

    int idx = -1;
    if (Nr == 9) {
        idx = 0;
    } else if (Nr == 12) {
        idx = 1;
    } else if (Nr == 14) {
        idx = 2;
    }

    uint64_t Key[Nk], RoundKey[roundKeySize];
    Vec<uint64_t> ptxt(INIT_SIZE, nBlocks*Nk);
    Vec<uint64_t> symEnced(INIT_SIZE, nBlocks*Nk);
    uint64_t temp3[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint64_t plain1[16] = {0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 
                           0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999, 0x09999};

    for (i = 0; i < Nk; i++) {
        Key[i] = temp3[i];
    }

    Yux_dagger_F_p cipher = Yux_dagger_F_p(Nk, Nr, plain_mod);

    //             ********************************************************
    // The KeyExpansion routine must be called before encryption.
    // Key expansion
    cipher.KeyExpansion(RoundKey, Key);

    // Decrypt roundkey
    uint64_t RoundKey_invert[roundKeySize];
    cipher.decRoundKey(RoundKey_invert, RoundKey);

    // creat context
    auto context = Transcipher16_dagger_F_p::create_context(mValues[idx][1], mValues[idx][0], /*r=*/1, /*bits*/ mValues[idx][2], 
                                                      /*c=*/ mValues[idx][3], /*d=*/1, /*k=*/128, /*s=*/1);
    Transcipher16_dagger_F_p FHE_cipher(context);
    FHE_cipher.print_parameters();
    FHE_cipher.create_pk();

    // Time of the HE of symmetric key
    cout << "HE encrypting key..." << flush;
    auto time_start = chrono::high_resolution_clock::now();
    vector<Ctxt> heKey; 
    vector<uint64_t> keySchedule_dec(roundKeySize);  
    for (int i = 0; i < roundKeySize; i++) {
        keySchedule_dec[i] = RoundKey_invert[i];
    }
    FHE_cipher.encryptSymKey(heKey, keySchedule_dec);
    auto time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::milliseconds>(time_end - time_start);
    cout << "...done in " << time_diff.count() << " ms" << endl;

    vector<Ctxt> heKey_initial = heKey;

    cout << "initial noise:" << endl;
    FHE_cipher.print_noise(heKey);

    // Warm-up
    for(i=0;i<Nk;i++) {
        ptxt[i]=plain1[i];
    }
    
    Vec<uint64_t> symEnced_warm(INIT_SIZE, Nk);

     // Symmetric encryption: symCtxt = Enc(symKey, ptxt) 
    for (long i=0; i<nBlocks; i++) {
        Vec<uint64_t> tmp(INIT_SIZE, Nk);
        cipher.encryption(&symEnced_warm[Nk*i], &ptxt[Nk*i], RoundKey);
    }
    // cipher.encryption(symEnced_warm.data(), warm_up_data, keySchedule);

    /************************************FHE dec Yupx-p-sym Begin ******************************************************/
    vector<Ctxt> homEncrypted_warm;
    FHE_cipher.FHE_YuxDecrypt(homEncrypted_warm, heKey, symEnced_warm);

    // test
    long total_time = 0;
    vector<Ctxt> homEncrypted_temp;
    
    cout << "Running FHE_YuxDecrypt " << test_round << " times..." << endl;
    
    for(int iter = 0; iter < test_round; iter++) {
        heKey = heKey_initial;
        for(i = 0; i < Nk; i++) {
            ptxt[i] = test_data[iter][i];
        }

        for (long i=0; i<nBlocks; i++) {
            Vec<uint64_t> tmp(INIT_SIZE, Nk);
            cipher.encryption(&symEnced[Nk*i], &ptxt[Nk*i], RoundKey);
        }
        

        auto start = chrono::high_resolution_clock::now();
        FHE_cipher.FHE_YuxDecrypt(homEncrypted_temp, heKey, symEnced);
        auto end = chrono::high_resolution_clock::now();
        auto diff = chrono::duration_cast<chrono::milliseconds>(end - start);
        total_time += diff.count();

        cout << "the FHE_YuxDecrypt time in " << iter << " runs: " 
         << fixed << setprecision(2) << diff.count() 
         << " milliseconds" << endl;

    }
    
    // running time
    double avg_time = total_time / 1e3 / test_round; 

    cout << "Average FHE_YuxDecrypt time over " << test_round << " runs: " 
         << fixed << setprecision(2) << avg_time 
         << " seconds" << endl;

    // thoughtput (KB/min)
    double throughput = (256.0 * 60.0 * pow(2, -13) * 32768.0) / avg_time;
    
    cout << "Average throughput over " << test_round << " runs: " 
         << fixed << setprecision(2) << throughput 
         << " KB/min" << endl;

    // // Perform the final homomorphic decryption for subsequent operations
    // vector<Ctxt> homEncrypted;
    // time_start = chrono::high_resolution_clock::now();
    // FHE_cipher.FHE_YuxDecrypt(homEncrypted, heKey, symEnced);
    // time_end = chrono::high_resolution_clock::now();
    // time_diff = chrono::duration_cast<chrono::milliseconds>(time_end - time_start);
    // cout << "Last FHE_YuxDecrypt Time: " << time_diff.count() << " milliseconds" << endl;

    // cout << "final noise:" << endl;
    // FHE_cipher.print_noise(homEncrypted);

    // cout << "Final decrypt..." << flush;
    // time_start = chrono::high_resolution_clock::now();

    // Vec<uint64_t> poly(INIT_SIZE, homEncrypted.size());
    // cout<<endl;
    // for (long i=0; i<poly.length(); i++) {
    //     FHE_cipher.decrypt(homEncrypted[i], poly[i]);
    //     cout<<i;
    //     printf(". %05lx ",poly[i]);
    // }
    // cout<<endl;

    // Vec<uint64_t> symDeced(INIT_SIZE, nBlocks*Nk);
    // for (long i=0; i<nBlocks; i++) {
    //     cipher.decryption(&symDeced[Nk*i], &symEnced[Nk*i], RoundKey_invert);
    // }
    
    // printf("\nText after Yux decryption:\n");
    // for(i=0;i<Nk;i++) {
    //     cout<<i;
    //     printf(". %05lx ",symDeced[i]);
    // }
    // printf("\n\n");
    // printState_p(symDeced);  cout << endl;
      
    // if (ptxt != symDeced) {
    //     cout << "@ decryption error\n";
    //     if (ptxt.length()!=symDeced.length())
    //         cout << "  size mismatch, should be "<<ptxt.length()
    //         << " but is "<<symDeced.length()<<endl;
    //     else {
    //         cout << "  input symCtxt = "; printState_p(symEnced); cout << endl;
    //         cout << "  output    got = "; printState_p(symDeced); cout << endl;
    //         cout << " should be ptxt = "; printState_p(ptxt); cout << endl;
    //     }
    // }
    // return true;
}

vector<vector<uint64_t>> read_test_data(const string& filename, int test_data_num) {
    vector<vector<uint64_t>> test_data ;
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

int main(int argc, char **argv) {
    int TEST_ROUND = 100;
    vector<vector<uint64_t>> test_data = read_test_data("../tests/random-plain.txt", TEST_ROUND);
    test_homo_decryption(TEST_ROUND, test_data);
    return 0;
}