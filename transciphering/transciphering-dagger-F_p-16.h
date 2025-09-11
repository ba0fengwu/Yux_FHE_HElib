#include <cstring>
#include <stdint.h>
#include <chrono>
#include <NTL/ZZX.h>
#include <NTL/ZZ.h>
#include <vector>

#include <helib/helib.h>
#include <helib/ArgMap.h>
#include <helib/DoubleCRT.h>

#include "../Yux/Yux-dagger-F_p.h"
#include "params.h"
#include "utils.h"

using namespace helib;
using namespace std;
using namespace NTL;

class Transcipher16_dagger_F_p
{
  protected:
  // std::vector<uint64_t> secret_key;
  uint64_t plain_mod;

  std::shared_ptr<helib::Context> context;
  uint64_t nslots;

  // std::vector<helib::Ctxt> secret_key_encrypted;

  helib::SecKey he_sk;
  std::unique_ptr<helib::PubKey> he_pk;
  const helib::EncryptedArray& ea;

public:
  static std::shared_ptr<helib::Context> create_context(
      uint64_t m, uint64_t p, uint64_t r, uint64_t L, uint64_t c,
      uint64_t d = 1, uint64_t k = 128, uint64_t s = 1);
 
  Transcipher16_dagger_F_p(std::shared_ptr<helib::Context> con);
  int print_noise();
  int print_noise(vector<Ctxt>& ciphs);
  void print_parameters();
  void create_pk();

  helib::EncryptedArray getEa();
  // run the Yux key-expansion and then encrypt the expanded key.
  void encryptSymKey(vector<Ctxt>& eKey, vector<uint64_t>& roundKeySchedule);

  
  void FHE_YuxDecrypt(vector<Ctxt>& eData, const vector<Ctxt>& symKey);
  void buildRoundConstant(Ctxt& encA);
  // Perform sym encryption on plaintext bytes (ECB mode). The input are
  // raw plaintext bytes, and the sym key encrypted under HE. The output
  // is a doubly-encrypted ciphertext, out=Enc_HE(Enc_Sym(X)). The symKey
  // array contains an encryption of the expanded sym key, the number of
  // sym rounds is YuxKey.size() -1.
  // NOTE: This is a rather useless method, other than for benchmarking
  void FHE_YuxDecrypt(vector<Ctxt>& eData, const vector<Ctxt>& symKey,
      const Vec<uint64_t> inBytes);

  // Encode plaintext/ciphertext bytes as native HE plaintext
  // packing
  void encodeTo16Ctxt(Vec<ZZX>& encData, const Vec<uint64_t>& data, long s);

  void decrypt(helib::Ctxt& in, uint64_t& out);
  static void decSboxFunc(vector<Ctxt>& eData, long begin, Ctxt& encA);

};
