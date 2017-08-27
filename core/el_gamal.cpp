/*
SeComLib
Copyright 2012-2013 TU Delft, Information Security & Privacy Lab (http://isplab.tudelft.nl/)

Contributors:
Inald Lagendijk (R.L.Lagendijk@TUDelft.nl)
Mihai Todor (todormihai@gmail.com)
Thijs Veugen (P.J.M.Veugen@tudelft.nl)
Zekeriya Erkin (z.erkin@tudelft.nl)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/**
@file core/el_gamal.cpp
@brief Implementation of class ElGamal.
@details Implementation described in the paper "A secure and optimally efficient multi-authority election scheme" by Ronald Cramer, Rosario Gennaro, Berry Schoenmakers, 1997
The decription of [0] without using the decryption map was suggested in the paper "An Efficient and Verifiable Solution to the Millionaire Problem" by Kun Peng, Colin Boyd, Ed Dawson, Byoungcheon Lee, 2005
@author Mihai Todor (todormihai@gmail.com)
*/

#include "el_gamal.h"

namespace SeComLib {
namespace Core {
	/**
	Initializes @f$ x @f$ and @f$ y @f$ with @f$ 0 @f$
	*/
	ElGamalRandomizer::ElGamalRandomizer () {
	}

	/**
	@param x @f$ x @f$ value
	@param y @f$ y @f$ value
	*/
	ElGamalRandomizer::ElGamalRandomizer (const BigInteger &x, const BigInteger &y) : x(x), y(y) {
	}

	/**
	Sets the specified key size from the configuration file (defaults to 1024).

	@param precomputeDecryptionMap Populate the decryption map, required to do full decryption (defaults to false)
	*/
	ElGamal::ElGamal (const bool precomputeDecryptionMap) : CryptoProvider<ElGamalPublicKey, ElGamalPrivateKey, ElGamalCiphertext, ElGamalRandomizer>(Utils::Config::GetInstance().GetParameter("Core.ElGamal.keySize", 1024)),
		messageSpaceThreshold(BigInteger(2).Pow(Utils::Config::GetInstance().GetParameter<unsigned long>("Core.ElGamal.messageSpaceThresholdBitSize"))),
		precomputeDecryptionMap(precomputeDecryptionMap) {
	}

	/**
	Sets the specified key size from the configuration file (defaults to 1024).

	Performs required precomputations.

	@param publicKey a ElGamalPublicKey structure
	*/
	ElGamal::ElGamal (const ElGamalPublicKey &publicKey) : CryptoProvider<ElGamalPublicKey, ElGamalPrivateKey, ElGamalCiphertext, ElGamalRandomizer>(publicKey, Utils::Config::GetInstance().GetParameter("Core.ElGamal.keySize", 1024)),
		messageSpaceThreshold(BigInteger(2).Pow(Utils::Config::GetInstance().GetParameter<unsigned long>("Core.ElGamal.messageSpaceThresholdBitSize"))) {
		//C++ doesn't allow us to call a virtual method in the constructor of the base class
		this->doPrecomputations();
	}

	/**
	Sets the specified key size from the configuration file (defaults to 1024).

	@param publicKey a ElGamalPublicKey structure
	@param privateKey a ElGamalPrivateKey structure
	@param precomputeDecryptionMap Populate the decryption map, required to do full decryption (defaults to false)
	*/
	ElGamal::ElGamal (const ElGamalPublicKey &publicKey, const ElGamalPrivateKey &privateKey, const bool precomputeDecryptionMap) : CryptoProvider<ElGamalPublicKey, ElGamalPrivateKey, ElGamalCiphertext, ElGamalRandomizer>(publicKey, privateKey, Utils::Config::GetInstance().GetParameter("Core.ElGamal.keySize", 1024)),
		messageSpaceThreshold(BigInteger(2).Pow(Utils::Config::GetInstance().GetParameter<unsigned long>("Core.ElGamal.messageSpaceThresholdBitSize"))),
		precomputeDecryptionMap(precomputeDecryptionMap) {
		//C++ doesn't allow us to call a virtual method in the constructor of the base class
		this->doPrecomputations();
	}

	/**
	* Generates the ElGamal cryptosystem keys.
	* 
	* @f$ g @f$ is computed using algorithms described in the Handbook of Applied Cryptography by Alfred J. Menezes, Paul C. van Oorschot and Scott A. Vanstone (http://cacr.uwaterloo.ca/hac/).
	* 
	* Specifically, we use <b>Algorithm 4.80</b>, Chapter 4: Finding a generator of a cyclic group
	* 
	* INPUT: a cyclic group @f$ G @f$ of order @f$ n @f$, and the prime factorization @f$ n = p_1^{e_1} p_2^{e_2} \cdots p_k^{e_k} @f$
	* 
	* OUTPUT: a generator @f$ \alpha @f$ of @f$ G @f$
	* 1. Choose a random element @f$ \alpha @f$ in @f$ G @f$
	* 2. For @f$ i @f$ from @f$ 1 @f$ to @f$ k @f$ do the following:
	*	1. Compute @f$ b \gets a^{n/p_i} @f$ (N.B. @f$ \pmod n @f$)
	*	2. If @f$ b = 1 @f$ then go to step 1.
	* 3. Return @f$ \alpha @f$.
	* 
	* @return Always true, for now.
	* @throws std::runtime_error parameter errors
	*/
	bool ElGamal::GenerateKeys () {
		/// Fetch the size of the large prime factor which @f$ p - 1 @f$ must have (defaults to 160)
		unsigned int largePrimeFactorSize = Utils::Config::GetInstance().GetParameter("Core.ElGamal.largePrimeFactorSize", 160);

		if (largePrimeFactorSize >= this->keyLength) {
			/// @todo Throw a custom exception here!
			throw std::runtime_error("Please choose a smaller prime factor size.");
		}

		/// Generate @f$ p @f$ ensuring that @f$ p - 1 @f$ has a large prime factor, @f$ q @f$: @f$ p - 1 = r q @f$.
		/// Because we will need to obtain a generator of @f$ \mathbb{Z}_{p}^* @f$, we impose that @f$ r = 2 m n @f$, where @f$ m @f$ and @f$ n @f$ are two random primes.

		BigInteger r, m, n;
		unsigned int sizeR = this->keyLength - largePrimeFactorSize;
		unsigned int sizeMN = (sizeR - 1) / 2;
		do {
			//pick a random prime @f$ q @f$ of size specified by largePrimeFactorSize
			this->publicKey.q = RandomProvider::GetInstance().GetMaxLengthRandomPrime(largePrimeFactorSize);

			//generate two random primes in the interval (0, 2^((sizeR - 1) / 2))
			m = RandomProvider::GetInstance().GetMaxLengthRandomPrime(sizeMN);
			n = RandomProvider::GetInstance().GetMaxLengthRandomPrime(sizeMN);

			//compute r
			r = m * n * 2;

			//q and r must divide p - 1
			this->publicKey.p = this->publicKey.q * r + 1;
		}
		while (!this->publicKey.p.IsPrime());

		/// Pick @f$ g @f$ - a random generator of the cyclic group @f$ \mathbb{Z}_p^* @f$, using Algorithm 4.80
		do {
			//generate random g in the interval [0, p)
			this->g = RandomProvider::GetInstance().GetRandomInteger(this->publicKey.p);
		}
		//ensure that g is a generator of Z_{p}^*
		while (BigInteger::Gcd(this->g, this->publicKey.p) != 1 ||
				this->g.GetPowModN(this->publicKey.q * m * n, this->publicKey.p) == 1 ||
				this->g.GetPowModN(this->publicKey.q * m * 2, this->publicKey.p) == 1 ||
				this->g.GetPowModN(this->publicKey.q * n * 2, this->publicKey.p) == 1 ||
				this->g.GetPowModN(m * n * 2, this->publicKey.p) == 1);

		/// Pick @f$ g_q @f$ of order @f$ q @f$ in @f$ \mathbb{Z}_{p}^* @f$
		this->publicKey.gq = this->g.GetPowModN(r, this->publicKey.p);

		/// Generate @f$ s \in \mathbb{Z}_q @f$
		do {
			this->privateKey.s = RandomProvider::GetInstance().GetRandomInteger(this->publicKey.q);
		}
		//s must be != 0
		while (this->privateKey.s == 0);

		/// @f$ h = g^s \in \mathbb{Z}_p @f$
		this->publicKey.h = this->publicKey.gq.GetPowModN(this->privateKey.s, this->publicKey.p);

		//precompute values for optimization purposes
		this->doPrecomputations();

		return true;
	}

	/**
	If @f$ plaintext \in [0, 2^t) \Rightarrow plaintext \geq 0 @f$ otherwise if @f$ plaintext \in [q - 2^t, q) \Rightarrow plaintext = plaintext - messageSpaceUpperBound  @f$

	@param ciphertext the ciphertext integer
	@return Deciphered plaintext
	@throws std::runtime_error the ciphertext can not be decrypted
	@throws std::runtime_error operation requires the private key
	*/
	BigInteger ElGamal::DecryptInteger (const ElGamal::Ciphertext &ciphertext) const {
		if (!this->hasPrivateKey) {
			throw std::runtime_error("This operation requires the private key.");
		}

		if (!this->precomputeDecryptionMap) {
			throw std::runtime_error("This operation requires the decryption map.");
		}

		/// Compute @f$ c.y * c.x^{-s} \pmod p @f$
		BigInteger cyCxPowMinusSModP = (ciphertext.data.y * ciphertext.data.x.GetPowModN(-this->privateKey.s, this->publicKey.p)) % this->publicKey.p;

		/// Shortcut: if @f$ c.y * c.x^{-s} \pmod p = 1 @f$, then @f$ c = [0] @f$
		if (cyCxPowMinusSModP == 1) {
			return 0;
		}

		/// @f$ m \in \mathbb{Z}_q \ (2^t, \lfloor q / 2 \rfloor + 2^t) @f$ is uniquely determined by @f$ g_q^m \pmod p @f$.
		/// Since we cannot determine m directly, we precompute all @f$ g_q^m \pmod p @f$ values, we store them in an std::map and we try to find m that matches @f$ c.y * c.x^{-s} \pmod p @f$
		BigInteger output;

		//get an iterator to the required element
		DecryptionMap::const_iterator iterator = this->decryptionMap.find(cyCxPowMinusSModP);

		//make sure the key exists
		if (this->decryptionMap.end() != iterator) {
			output = BigInteger(iterator->second);
		}
		else {
			throw std::runtime_error("Can't decrypt ciphertext.");
		}

		if (output > this->positiveNegativeBoundary) {
			output -= this->GetMessageSpaceUpperBound();
		}
		
		return output;
	}

	/**
	Contains the ElGamal encryption algorithm.

	@param plaintext the plaintext integer
	@return Encrypted ciphertext
	*/
	ElGamal::Ciphertext ElGamal::EncryptIntegerNonrandom (const BigInteger &plaintext) const {
		ElGamal::Ciphertext output(this->encryptionModulus);

		/// If @f$ plaintext < 0 @f$, we remap it to the second half of the message space

		/// Set @f$ x = 1 @f$ and randomize it later (replace it with @f$ g_q^r @f$)
		output.data.x = 1;
		if (plaintext < 0) {
			output.data.y = this->publicKey.gq.GetPowModN(this->GetMessageSpaceUpperBound() + plaintext, this->publicKey.p);
		}
		else {
			output.data.y = this->publicKey.gq.GetPowModN(plaintext, this->publicKey.p);
		}

		return output;
	}

	/**
	Generates a random integer @f$ r \in \mathbb{Z}_q @f$ and computes the randomization pair @f$ (g_q^r \pmod p, h^r \pmod p) @f$

	@return the random factor
	*/
	ElGamal::Randomizer ElGamal::GetRandomizer () const {
		BigInteger random = RandomProvider::GetInstance().GetRandomInteger(this->publicKey.q);

		return Randomizer(this->publicKey.gq.GetPowModN(random, this->publicKey.p), this->publicKey.h.GetPowModN(random, this->publicKey.p));
	}

	/**
	Computes the pair @f$ (g_q^r \pmod p, h^r c \pmod p) @f$

	@param ciphertext the ciphertext integer
	@return The randomized ciphertext
	*/
	ElGamal::Ciphertext ElGamal::RandomizeCiphertext (const ElGamal::Ciphertext &ciphertext) const {
		//assign a randomizer to the output
		Randomizer randomizer = this->randomizerCache->Pop().randomizer;
		Ciphertext output(this->encryptionModulus);

		//compose the output with the ciphertext
		output.data.x = ciphertext.data.x * randomizer.x % this->GetEncryptionModulus();
		output.data.y = ciphertext.data.y * randomizer.y % this->GetEncryptionModulus();
		
		return output;
	}

#ifdef ENABLE_CRYPTO_PROVIDER_HOMOMORPHIC_OPERATIONS
	/**
	Computes @f$ [lhs + rhs] = [lhs] [rhs] = (x_{lhs} x_{rhs} \pmod n, y_{lhs} y_{rhs} \pmod n) @f$
	@param lhs left hand side encrypted operand
	@param rhs right hand side encrypted operand
	@return A new instance containing @f$ [lhs + rhs] @f$
	*/
	ElGamal::Ciphertext ElGamal::HomomorphicAdd (const ElGamal::Ciphertext &lhs, const ElGamal::Ciphertext &rhs) const {
		ElGamal::Ciphertext output;

		output.x = (lhs.x * rhs.x) % this->GetEncryptionModulus();
		output.y = (lhs.y * rhs.y) % this->GetEncryptionModulus();

		return output;
	}

	/**
	Computes @f$ [-input] = [input]^{-1} \pmod n = (x_{input}^{-1} \pmod n, y_{input}^{-1} \pmod n) @f$
	@param input an encrypted value
	@return A new instance containing @f$ [-input] @f$
	*/
	ElGamal::Ciphertext ElGamal::GetHomomorphicInverse (const ElGamal::Ciphertext &input) const {
		ElGamal::Ciphertext output;

		output.x = input.x.GetInverseModN(this->GetEncryptionModulus());
		output.y = input.y.GetInverseModN(this->GetEncryptionModulus());

		return output;
	}

	/**
	Computes @f$ [lhs - rhs] = [lhs] [rhs]^{-1} = (x_{lhs} x_{rhs}^{-1} \pmod n, y_{lhs} y_{rhs}^{-1} \pmod n) @f$
	@param lhs left hand side encrypted operand
	@param rhs right hand side encrypted operand
	@return A new instance containing @f$ [lhs - rhs] @f$
	*/
	ElGamal::Ciphertext ElGamal::HomomorphicSubtract (const ElGamal::Ciphertext &lhs, const ElGamal::Ciphertext &rhs) const {
		ElGamal::Ciphertext output;

		output.x = (lhs.x * rhs.x.GetInverseModN(this->GetEncryptionModulus())) % this->GetEncryptionModulus();
		output.y = (lhs.y * rhs.y.GetInverseModN(this->GetEncryptionModulus())) % this->GetEncryptionModulus();

		return output;
	}

	/**
	Computes @f$ [lhs * rhs] = [lhs]^rhs = (x_{lhs}^rhs \pmod n, y_{lhs}^rhs \pmod n) @f$.

	@param lhs left hand side encrypted operand
	@param rhs right hand side plaintext operand
	@return A new instance containing @f$ [lhs * rhs] @f$
	*/
	ElGamal::Ciphertext ElGamal::HomomorphicMultiply (const ElGamal::Ciphertext &lhs, const BigInteger &rhs) const {
		if (rhs == 0) {
			throw std::runtime_error("The plaintext term should not be 0.");
		}

		ElGamal::Ciphertext output = lhs;

		output.x = output.x.GetPowModN(rhs, this->GetEncryptionModulus());
		output.y = output.y.GetPowModN(rhs, this->GetEncryptionModulus());

		return output;
	}
#endif

	/**
	@return @f$ q @f$
	*/
	const BigInteger &ElGamal::GetMessageSpaceUpperBound () const {
		return this->publicKey.q;
	}

	/**
	@return The message space bit size.
	*/
	size_t ElGamal::GetMessageSpaceSize () const {
		return this->publicKey.q.GetSize();
	}

	/**
	If and only if @f$ m = 0 @f$, then @f$ c.y * c.x^{-s} \pmod p = 1 @f$.

	This is faster than the actual decryption, since the table lookup is not required.

	@param ciphertext a DGK ciphertext
	@return True if ciphertext = [0] and fase otherwise
	*/
	bool ElGamal::IsEncryptedZero (const Ciphertext &ciphertext) const {
		if (!this->hasPrivateKey) {
			throw std::runtime_error("This operation requires the private key.");
		}

		BigInteger test = (ciphertext.data.y * ciphertext.data.x.GetPowModN(-this->privateKey.s, this->publicKey.p)) % this->publicKey.p;

		return test == 1 ? true : false;
	}

	/**
	Precomputes the message space delimiter between positive and negative values.

	Precomputes [0] and [1].
	*/
	void ElGamal::doPrecomputations () {
		if (this->hasPrivateKey) {
			/// Precompute all possible values of @f$ g_q^m \pmod p @f$, where @f$ m \in \mathbb{Z}_q \ (2^t, \lfloor q / 2 \rfloor + 2^t) @f$, and it is required for decryption.
			if (this->precomputeDecryptionMap) {
				//we handle the first part (for m >= 0)
				for (BigInteger i = 0; i < this->messageSpaceThreshold; ++i) {
					this->decryptionMap[this->publicKey.gq.GetPowModN(i, this->publicKey.p)] = i;
				}
				//and the second part (for m < 0) - we do one less iteration here, because size(positives \ {0}) = size(negatives)
				for (BigInteger i = this->publicKey.q - this->messageSpaceThreshold + 1; i < this->publicKey.q; ++i) {
					this->decryptionMap[this->publicKey.gq.GetPowModN(i, this->publicKey.p)] = i;
				}
			}
		}
		
		//set the encryption modulus, @f$ p @f$
		this->encryptionModulus = std::make_shared<BigInteger>(this->publicKey.p);

		this->positiveNegativeBoundary = this->messageSpaceThreshold;
		
		/// Populate the randomizer cache
		this->randomizerCache = std::unique_ptr<RandomizerCacheType>(new RandomizerCacheType(*this, "Core.RandomizerCache"));

		this->encryptedZero = this->EncryptInteger(BigInteger(0));

		this->encryptedOne = this->EncryptInteger(BigInteger(1));
	}

}//namespace Core
}//namespace SeComLib