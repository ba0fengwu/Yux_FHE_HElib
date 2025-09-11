#include <cstring>
#include <stdint.h>
#include <chrono>
#include <helib/helib.h>
#include "../transciphering/transciphering-dagger-F_p-16.h"

using namespace helib;
using namespace std;
using namespace NTL;

#define homDec

// static long mValues[][4] = { 
// //{   p,       m,   bits}
//   { 65537,  131072,  1320, 6}, // m=(3)*{257} 1250
//   { 65537,  65536,  853, 17},
// };

static long mValues[][4] = { 
//{   p,       m,   bits}
  { 65537,  65536,  853, 17},
  { 65537,  131072,  1250, 6},
  { 65537,  131072,  1500, 10},
};

bool dec_test() {
    int i, Nr=pROUND;

    int idx = -1;
    if (Nr == 2) {
      idx = 0;
    }
    else if (Nr == 12) {
      idx = 1;
    }
    else if (Nr == 14) {
      idx = 2;
    }

    int Nk= 16;
    long plain_mod = 65537;
    long roundKeySize = (Nr+1)*Nk;
    int nBlocks = 1;
    uint64_t in[Nk],  Key[Nk];
   
    uint64_t plain[16] = {0x09990, 0x049e1, 0x0dac4, 0x053b5, 0x0ff86, 0x06f91, 0x07a8f, 0x0e700,
        0x0152e, 0x034b6, 0x0a16f, 0x01219, 0x00b83, 0x09ab7, 0x06b12, 0x0e2b1};
    uint64_t plain1[16] = {0x09999, 0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999,0x09999};
    uint64_t temp3[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    Vec<uint64_t> ptxt(INIT_SIZE, nBlocks*Nk);
    Vec<uint64_t> symEnced(INIT_SIZE, nBlocks*Nk);

    for(i=0;i<Nk;i++) {
        Key[i]=temp3[i];
        // Key[i]=plain1[i];
        ptxt[i]=plain1[i];
    }

    Yux_dagger_F_p cipher = Yux_dagger_F_p(Nk, Nr, plain_mod);
    
    uint64_t keySchedule[roundKeySize];
    cipher.KeyExpansion(keySchedule, Key);

    for (long i=0; i<nBlocks; i++) {
        Vec<uint64_t> tmp(INIT_SIZE, Nk);
        cipher.encryption(&symEnced[Nk*i], &ptxt[Nk*i], keySchedule);
    }

    printf("\nText after Yux encryption:\n");
    for(i=0;i<Nk;i++) {
        printf("%05lx ",symEnced[i]);
    }
    printf("\n\n");

    printf("\nText about Roundkey:\n");
    for(i=0;i<Nk;i++) {
        printf("%05lx ",keySchedule[i]);
    }
    printf("\n\n");

    uint64_t RoundKey_invert[roundKeySize];
    cipher.decRoundKey(RoundKey_invert, keySchedule);

    auto context = Transcipher16_dagger_F_p::create_context(mValues[idx][1], mValues[idx][0], /*r=*/1, /*bits*/ mValues[idx][2], 
                                                      /*c=*/ mValues[idx][3], /*d=*/1, /*k=*/128, /*s=*/1);
    Transcipher16_dagger_F_p FHE_cipher(context);
    FHE_cipher.print_parameters();
    FHE_cipher.create_pk();

    cout << "HE encrypting key..." << flush;
    auto time_start = chrono::high_resolution_clock::now();
    vector<Ctxt> heKey; 
    vector<uint64_t> keySchedule_dec(roundKeySize);  
    for(int i=0; i<roundKeySize; i++) keySchedule_dec[i] = RoundKey_invert[i];
    FHE_cipher.encryptSymKey(heKey, keySchedule_dec);
    auto time_end = chrono::high_resolution_clock::now();
    auto time_diff = chrono::duration_cast<chrono::milliseconds>(time_end - time_start);
    cout << "...done in " << time_diff.count() << " ms" << endl;

    cout << "initial noise:" << endl;
    FHE_cipher.print_noise(heKey);

    // warm-up
    vector<Ctxt> homEncrypted_warm;
    FHE_cipher.FHE_YuxDecrypt(homEncrypted_warm, heKey, symEnced);

    // Timing
    long total_time = 0;
    vector<Ctxt> homEncrypted_temp;
    cout << "Running FHE_YuxDecrypt 10 times..." << endl;
    
    for (int i = 0; i < 10; i++) {
        auto start = chrono::high_resolution_clock::now();
        FHE_cipher.FHE_YuxDecrypt(homEncrypted_temp, heKey, symEnced);
        auto end = chrono::high_resolution_clock::now();
        auto diff = chrono::duration_cast<chrono::milliseconds>(end - start);
        total_time += diff.count();
    }
    
    double avg_time = total_time / 10.0;
    cout << "Average FHE_YuxDecrypt time over 10 runs: " << avg_time << " milliseconds" << endl;

    // thoughput(KB/min)
    double avg_time_seconds = avg_time / 1000.0;  
    double throughput = (256.0 * 60.0 * pow(2, -13) * 32768.0) / avg_time_seconds;
    cout << "Average throughput over 10 runs: " 
        << fixed << setprecision(2) << throughput 
        << " KB/min" << endl;

    // Perform the final homomorphic decryption for subsequent operations
    vector<Ctxt> homEncrypted;
    time_start = chrono::high_resolution_clock::now();
    FHE_cipher.FHE_YuxDecrypt(homEncrypted, heKey, symEnced);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::milliseconds>(time_end - time_start);
    cout << "Last FHE_YuxDecrypt Time: " << time_diff.count() << " milliseconds" << endl;

    cout << "final noise:" << endl;
    FHE_cipher.print_noise(homEncrypted);

    cout << "Final decrypt..." << flush;
    time_start = chrono::high_resolution_clock::now();

    Vec<uint64_t> poly(INIT_SIZE, homEncrypted.size());
    cout<<endl;
    for (long i=0; i<poly.length(); i++) {
        FHE_cipher.decrypt(homEncrypted[i], poly[i]);
        cout<<i;
        printf(". %05lx ",poly[i]);
    }
    cout<<endl;

    Vec<uint64_t> symDeced(INIT_SIZE, nBlocks*Nk);
    for (long i=0; i<nBlocks; i++) {
        cipher.decryption(&symDeced[Nk*i], &symEnced[Nk*i], RoundKey_invert);
    }
    
    printf("\nText after Yux decryption:\n");
    for(i=0;i<Nk;i++) {
        cout<<i;
        printf(". %05lx ",symDeced[i]);
    }
    printf("\n\n");
    printState_p(symDeced);  cout << endl;
      
    if (ptxt != symDeced) {
        cout << "@ decryption error\n";
        if (ptxt.length()!=symDeced.length())
            cout << "  size mismatch, should be "<<ptxt.length()
            << " but is "<<symDeced.length()<<endl;
        else {
            cout << "  input symCtxt = "; printState_p(symEnced); cout << endl;
            cout << "  output    got = "; printState_p(symDeced); cout << endl;
            cout << " should be ptxt = "; printState_p(ptxt); cout << endl;
        }
    }
    return true;
}

int main(int argc, char **argv){
   dec_test();
}