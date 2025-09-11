#include <cstdlib>
#include <cstdio>
#include <stdint.h>
#include <iostream>
#include <vector>
using namespace std;


class Yux_dagger_F_p{

  private:
    int ROUND=4;
    int BlockWords = 16;
    uint64_t Yux_p = 65537;
    uint64_t modulus = 65537;
    uint64_t roundConstant = 0xCD;

    uint64_t Model_p(uint64_t state);
    void addRoundKey(uint64_t state[], uint64_t RoundKey[], int round);
    void encSboxFi(uint64_t state[], int begin);
    void encLinearLayer(uint64_t in[16]);
    
    void subtractRoundKey(uint64_t state[], uint64_t RoundKey[], int round);
    void decSboxFi(uint64_t state[], int begin);
    void decLinearLayer(uint64_t in[16]);

    void rotation(uint64_t *a, int l,int r);
    void constantForKey(uint64_t RC[56][4]);


  public:
    Yux_dagger_F_p(const int b, const int r, const uint64_t p): BlockWords(b), ROUND(r), modulus(p){}
    // YUX_F_P() = default;

    void decryption(uint64_t out[], uint64_t in[], uint64_t RoundKey[]);
    void encryption(uint64_t out[], uint64_t in[], uint64_t RoundKey[]);
    long KeyExpansion(uint64_t RoundKey[], uint64_t Key[]);
    void decRoundKey(uint64_t RoundKey_invert[], uint64_t RoundKey[]);

    vector<vector<uint64_t>> matrix_dagger = {
      { 8738, 0, 4369, 0, 56799, 0, 61168, 0, 30584, 0, 26215, 0, 34953, 0, 61168, 0 },
      { 0, 8738, 0, 4369, 0, 56799, 0, 61168, 0, 30584, 0, 26215, 0, 34953, 0, 61168 },
      { 61168, 0, 8738, 0, 4369, 0, 56799, 0, 61168, 0, 30584, 0, 26215, 0, 34953, 0 },
      { 0, 61168, 0, 8738, 0, 4369, 0, 56799, 0, 61168, 0, 30584, 0, 26215, 0, 34953 },
      { 34953, 0, 61168, 0, 8738, 0, 4369, 0, 56799, 0, 61168, 0, 30584, 0, 26215, 0 },
      { 0, 34953, 0, 61168, 0, 8738, 0, 4369, 0, 56799, 0, 61168, 0, 30584, 0, 26215 },
      { 26215, 0, 34953, 0, 61168, 0, 8738, 0, 4369, 0, 56799, 0, 61168, 0, 30584, 0 },
      { 0, 26215, 0, 34953, 0, 61168, 0, 8738, 0, 4369, 0, 56799, 0, 61168, 0, 30584 },
      { 30584, 0, 26215, 0, 34953, 0, 61168, 0, 8738, 0, 4369, 0, 56799, 0, 61168, 0 },
      { 0, 30584, 0, 26215, 0, 34953, 0, 61168, 0, 8738, 0, 4369, 0, 56799, 0, 61168 },
      { 61168, 0, 30584, 0, 26215, 0, 34953, 0, 61168, 0, 8738, 0, 4369, 0, 56799, 0 },
      { 0, 61168, 0, 30584, 0, 26215, 0, 34953, 0, 61168, 0, 8738, 0, 4369, 0, 56799 },
      { 56799, 0, 61168, 0, 30584, 0, 26215, 0, 34953, 0, 61168, 0, 8738, 0, 4369, 0 },
      { 0, 56799, 0, 61168, 0, 30584, 0, 26215, 0, 34953, 0, 61168, 0, 8738, 0, 4369 },
      { 4369, 0, 56799, 0, 61168, 0, 30584, 0, 26215, 0, 34953, 0, 61168, 0, 8738, 0 },
      { 0, 4369, 0, 56799, 0, 61168, 0, 30584, 0, 26215, 0, 34953, 0, 61168, 0, 8738 }
    };

};