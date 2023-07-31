#include "transciphering-F_p-1.h"

using namespace helib;
using namespace std;
using namespace NTL;

Transcipher1_F_p::Transcipher1_F_p(std::shared_ptr<helib::Context> con)
    : context(con),
      he_sk(*context),
      ea(context->getEA()) {
  
  cout << "Transcipher1_F_p init ..." <<endl;
        
  plain_mod = con->getP();

  if (plain_mod > (uint64_t)std::numeric_limits<long>::max())
    throw std::runtime_error("plain size to big for long");

  nslots = ea.size();

  he_sk.GenSecKey();
    // Add key-switching matrices for the automorphisms that we need
  
  long ord = con->getZMStar().OrderOf(0) ;
  for (long i = 1; i < 16; i++) { // rotation along 1st dim by size i*ord/16
    long exp = i*ord/16;
    long val = PowerMod(con->getZMStar().ZmStarGen(0), exp, con->getM()); // val = g^exp

    // From s(X^val) to s(X)
    he_sk.GenKeySWmatrix(1, val);
    if (!con->getZMStar().SameOrd(0))
      // also from s(X^{1/val}) to s(X)
      he_sk.GenKeySWmatrix(1, InvMod(val,con->getM()));
  }

  // power_of_2_ring = isPowerOfTwo(context->getM());
}

/************************************************************************
  long m;          // m-th cyclotomic polynomial
  long p;          // plaintext primeplain_mod;
  long r;          // Lifting [defualt = 1]
  long L;          // bits in the ciphertext modulus chain
  long c;          // columns in the key-switching matrix [default=2]
  long d;          // Degree of the field extension [default=1]
  long k;          // Security parameter [default=80]
  long s;          // Minimum number of slots [default=0]
************************************************************************/

shared_ptr<Context> Transcipher1_F_p::create_context(
    uint64_t m, uint64_t p, uint64_t r, uint64_t L, uint64_t c, uint64_t d,
    uint64_t k, uint64_t s) {
    cout << "create_context... ";
  if (!m) m = FindM(k, L, c, p, d, s, 0);
    cout << " m =  " << m<<endl;
    bool TTT= m && (!(m & (m - 1)));
    cout << "!!!!!!!!!!!!!!!!!!!!!!!!TTT = " << TTT <<endl;
  return shared_ptr<Context>(ContextBuilder<BGV>()
                                             .m(m)
                                             .p(p)
                                             .r(r)
                                             .bits(L)
                                             .c(c)
                                             .buildPtr());

}

//----------------------------------------------------------------

// int Transcipher1_F_p::print_noise() { return print_noise(secret_key_encrypted); }

//----------------------------------------------------------------

int Transcipher1_F_p::print_noise(vector<Ctxt>& ciphs) {
  int min = ciphs[0].bitCapacity();
  int max = min;
  for (uint64_t i = 1; i < ciphs.size(); i++) {
    int budget = ciphs[i].bitCapacity();
    if (budget > max) max = budget;
    if (budget < min) min = budget;
  }
  cout << "min noise budget: " << min << endl;
  cout << "max noise budget: " << max << endl;
  return min;
}


void Transcipher1_F_p::print_parameters() {
  if (!context) {
    throw std::invalid_argument("context is not set");
  }

  std::cout << "/" << std::endl;
  std::cout << "| Encryption parameters:" << std::endl;
  std::cout << "|   scheme: BGV " << std::endl;
  std::cout << "|   slots: " << context->getNSlots() << std::endl;
  std::cout << "|   bootstrappable: " << context->isBootstrappable()
            << std::endl;
  std::cout << "|   m: " << context->getM() << std::endl;
  std::cout << "|   phi(m): " << context->getPhiM() << std::endl;
  std::cout << "|   plain_modulus: " << context->getP() << std::endl;
  std::cout << "|   cipher mod size (bits): " << context->bitSizeOfQ()
            << std::endl;
  std::cout << "|   r: " << context->getR() << std::endl;
  std::cout << "|   sec level: " << context->securityLevel() << std::endl;
  std::cout << "\\" << std::endl;
}

//----------------------------------------------------------------

void Transcipher1_F_p::create_pk() {
  addSome1DMatrices(he_sk);
  he_pk = std::make_unique<helib::PubKey>(he_sk);
  return;
}


helib::EncryptedArray Transcipher1_F_p::getEa() {
  return ea;
}



//----------------------------------------------------------------
// encrypt the expanded key roundKeySchedule.
void Transcipher1_F_p::encryptSymKey(vector<Ctxt>& eKey, vector<uint64_t>& roundKeySchedule)
{   
    eKey.resize(pROUND+1, Ctxt(*he_pk));
    cout<< "ekey.size() = " <<eKey.size() <<endl;

    long blocksPerCtxt = ea.size() / BlockWords;

    for (long i=0; i<eKey.size(); i++){ // encrypt the encoded key
      vector<long> slotsData(0);
      for(long j=0; j<blocksPerCtxt; j++) {
        slotsData.insert(slotsData.begin()+j*BlockWords, roundKeySchedule.begin()+i*BlockWords, roundKeySchedule.begin()+(i+1)*BlockWords);
      }
      slotsData.resize(nslots);
      // if(i<=10) {
      //   printState_p(slotsData);
      // }
      ea.encrypt(eKey[i], *he_pk, slotsData);
    }
      // he_pk.Encrypt(eKey[i], encoded[i]);
}


void Transcipher1_F_p::FHE_YuxDecrypt(vector<Ctxt>& eData, const vector<Ctxt>& symKey) 
{
  if (1>(long)eData.size() || 1>(long)symKey.size()) return; // no data/key
  //  long lvlBits = eData[0].getContext().bitsPerLevel;
  
  Ctxt encA(ZeroCtxtLike,symKey[0]);
  buildRoundConstant(encA);

  // apply the symmetric rounds
  // cout << "homSymDec Begin\n";
  /*
  for (long j=0; j<(long)eData.size(); j++) eData[j] -= symKey[0];  // initial key addition
  
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (long i=1; i<pROUND; i++){ 
    for (long j=0; j<(long)eData.size(); j++){
      // // S Layer 
      // for (long step=0; step<2; step++)
      //   decSboxFunc2(eData[j], encLinTran, encA, ea);
      // Linear Layer
      Linear_function(eData[j]);
      // Add round key
      eData[j] -= symKey[i];
    }
    cout<< "round "<< i << " ";
    print_noise(eData);
  }
  // The last round is given below.
  // Linear layer is not here in the last round
  {
    for (long j=0; j<(long)eData.size(); j++){
      
      // S Layer 
      // for (long step=0; step<2; step++)
      //   decSboxFunc2(eData[j], encLinTran, encA, ea);
      // Add round key
      eData[j] -= symKey[pROUND];
    }
  }
  // cout << "homSymDec Finish! \n";
  // return to natural PrimeSet to save memery
  for (int i = 0; i < eData.size(); i++)
    eData[i].bringToSet(eData[i].naturalPrimeSet());
    */
}

void Transcipher1_F_p::Linear_function(Ctxt& c){
  // The basic rotation amount along the 1st dimension
    long rotAmount = ea.getContext().getZMStar().OrderOf(0) / BlockWords;
    cout<< "rotAmount " << rotAmount <<endl;
    c.cleanUp();
    // 循环左移   3  4  8 9 12 14
    // 即循环右移 13 12 8 7  4  2
    Ctxt c3(c), c4(c), c8(c), c9(c), c12(c), c14(c);
    // ea.rotate1D(c3, 0, 13*rotAmount);
    // ea.rotate1D(c4, 0, 12*rotAmount);
    // ea.rotate1D(c8, 0, 8*rotAmount);
    // ea.rotate1D(c9, 0, 7*rotAmount);
    // ea.rotate1D(c12, 0, 4*rotAmount);
    ea.rotate1D(c14, 0, 2*rotAmount);
    
    // c3.cleanUp();  c4.cleanUp(); c8.cleanUp();
    // c9.cleanUp();  c12.cleanUp();  c14.cleanUp();

    // c +=c3; 
    // c +=c4; c +=c8; c +=c9; c +=c12;  
    c += c14;
    c.cleanUp();
}

void Transcipher1_F_p::FHE_YuxDecrypt(vector<Ctxt>& eData, const vector<Ctxt>& symKey, const Vec<uint64_t> inBytes)
{
  {
    Vec<ZZX> encodedBytes;
    encodeTo1Ctxt(encodedBytes, inBytes, nslots); // encode as HE plaintext 
    // Allocate space for the output ciphertexts, initialized to zero
    //eData.resize(encodedBytes.length());
    eData.resize(encodedBytes.length(), Ctxt(ZeroCtxtLike,symKey[0]));
    for (long i=0; i<(long)eData.size(); i++)   // encode ptxt as HE ctxt
      eData[i].DummyEncrypt(encodedBytes[i]);
  }
    //-----------------------------------------------------------------------------
  long rotAmount = ea.getContext().getZMStar().OrderOf(0) / BlockWords;
  cout << " dimension() = " << ea.dimension() <<endl;
  ea.rotate1D(eData[0],0,3*rotAmount);
  eData[0].cleanUp();

  //------------------------------------------------------------------------

  // FHE_YuxDecrypt(eData, symKey); // do the real work
}


// Encode plaintext/ciphertext bytes as native HE plaintext
void Transcipher1_F_p::encodeTo1Ctxt(Vec<ZZX>& encData, const Vec<uint64_t>& data,
		long s)
{
  long nAllBlocks = divc(data.length(), BlockWords); // ceil( data.length()/16 )
  cout<< "nBlocks = " << nAllBlocks << endl;
  long blocksPerCtxt = ea.size() / 16;  // = nSlots/16
  long nCtxt = divc(nAllBlocks, blocksPerCtxt);

  // We encode blocksPerCtxt = n/16 blocks in the slots of one ctxt.
  encData.SetLength(nCtxt);

  for (long i=0; i<nCtxt; i++) {         // i is the cipehrtext number
    // Copy the bytes into Hypercube<GF2X>'es to be used for encoding
    vector<long> slotsData(0);
    for (long j=0; j<blocksPerCtxt; j++) { // j is the block number in this ctxt
      long beginIdx = (i*blocksPerCtxt +j)*BlockWords;  // point to block
      slotsData.insert(slotsData.begin()+j*BlockWords, data.begin()+beginIdx+i*BlockWords, data.begin()+beginIdx+(i+1)*BlockWords);
    }
    slotsData.resize(nslots);
    if(i<=10) {
      printState_p(slotsData);
    }
    ea.encode(encData[i], slotsData);
  }
}




void Transcipher1_F_p::buildRoundConstant(Ctxt& encA)
{
  // long --> ZZX -->Ctxt 
  vector<long> slots(ea.size(), roundConstant);
  ZZX ZZXConstant;
  ea.encode(ZZXConstant, slots);
  encA.DummyEncrypt(ZZXConstant);
}


vector<long> Transcipher1_F_p::decrypt(helib::Ctxt& in, long n) {
  vector<long> p;
  ea.decrypt(in, he_sk, p);
  p.resize(n);
  return p;
}

