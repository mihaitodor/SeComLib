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
@file core/dgk.cpp
@brief Implementation of class Dgk.
@details The implementation is described in papers "Efficient and Secure Comparison for On-Line Auctions" by Ivan Damgard, Martin Geisler and Mikkel Kroigaard, 2007
and "A correction to Effcient and Secure Comparison for On-Line Auctions" by Ivan Damgard, Martin Geisler and Mikkel Kroigaard, 2009
@author Mihai Todor (todormihai@gmail.com)
*/

#include "dgk.h"

namespace SeComLib {
namespace Core {
	/**
	Does not initialize the encryptionModulus.
	*/
	DgkCiphertext::DgkCiphertext () :
		CiphertextBase<DgkCiphertext> () {
	}

	/**
	Initializes the encryptionModulus
	@param encryptionModulus The encryption modulus
	*/
	DgkCiphertext::DgkCiphertext (const std::shared_ptr<BigInteger> &encryptionModulus) :
		CiphertextBase<DgkCiphertext> (encryptionModulus) {
	}

	/**
	Initializes the data and the encryptionModulus
	@param data the ciphertext data
	@param encryptionModulus The encryption modulus
	*/
	DgkCiphertext::DgkCiphertext (const BigInteger &data, const std::shared_ptr<BigInteger> &encryptionModulus) :
		CiphertextBase<DgkCiphertext> (data, encryptionModulus) {
	}

	/**
	*/
	DgkRandomizer::DgkRandomizer () : RandomizerBase() {
	}

	/**
	Initializes the data
	@param data the randomizer data
	*/
	DgkRandomizer::DgkRandomizer (const BigInteger &data) : RandomizerBase(data) {
	}

	/**
	Sets the specified key size from the configuration file (defaults to 1024).
	
	Sets parameters t (defaults to 160) and l (defaults to 16)

	@param precomputeDecryptionMap Populate the decryption map, required to do full decryption (defaults to false)
	*/
	Dgk::Dgk (const bool precomputeDecryptionMap) : CryptoProvider<DgkPublicKey, DgkPrivateKey, DgkCiphertext, DgkRandomizer>(Utils::Config::GetInstance().GetParameter("Core.Dgk.k", 1024)),
		t(Utils::Config::GetInstance().GetParameter("Core.Dgk.t", 160)),
		l(Utils::Config::GetInstance().GetParameter("Core.Dgk.l", 16)),
		precomputeDecryptionMap(precomputeDecryptionMap) {
		this->validateParameters();
	}

	/**
	Performs required precomputations.

	@param publicKey a PublicKey structure
	*/
	Dgk::Dgk (const DgkPublicKey &publicKey) : CryptoProvider<DgkPublicKey, DgkPrivateKey, DgkCiphertext, DgkRandomizer>(publicKey, Utils::Config::GetInstance().GetParameter("Core.Dgk.k", 1024)),
		t(Utils::Config::GetInstance().GetParameter("Core.Dgk.t", 160)),
		l(Utils::Config::GetInstance().GetParameter("Core.Dgk.l", 16)) {
		this->validateParameters();

		//precompute values for optimization purposes
		this->doPrecomputations();
	}

	/**
	Performs required precomputations.

	@param publicKey a DgkPublicKey structure
	@param privateKey a DgkPrivateKey structure
	@param precomputeDecryptionMap Populate the decryption map, required to do full decryption (defaults to false)
	*/
	Dgk::Dgk (const DgkPublicKey &publicKey, const DgkPrivateKey &privateKey, const bool precomputeDecryptionMap) : CryptoProvider<DgkPublicKey, DgkPrivateKey, DgkCiphertext, DgkRandomizer>(publicKey, privateKey, Utils::Config::GetInstance().GetParameter("Core.Dgk.k", 1024)),
		t(Utils::Config::GetInstance().GetParameter("Core.Dgk.t", 160)),
		l(Utils::Config::GetInstance().GetParameter("Core.Dgk.l", 16)),
		precomputeDecryptionMap(precomputeDecryptionMap) {
		this->validateParameters();

		//precompute values for optimization purposes
		this->doPrecomputations();
	}

	/**
	* Generates the public and private keys via the generateKeys private method and ensures that they are successfully generated.
	*
	* Precomputes the decryption map and values required for speeding-up the encryption.
	* 
	* @f$ h @f$ and @f$ g @f$ are computed using algorithms described in the Handbook of Applied Cryptography by Alfred J. Menezes, Paul C. van Oorschot and Scott A. Vanstone (http://cacr.uwaterloo.ca/hac/).
	* 
	* Specifically, we use <b>Algorithm 4.83</b>, Chapter 4: Selecting an element of maximum order in @f$ \mathbb{Z}_n^* @f$, where @f$ n = p q @f$
	* 
	* INPUT: two distinct odd primes, @f$ p @f$, @f$ q @f$, and the factorizations of @f$ p - 1 @f$ and @f$ q - 1 @f$.
	* 
	* OUTPUT: an element @f$ \alpha @f$ of maximum order @f$ lcm(p - 1; q - 1) @f$ in @f$ \mathbb{Z}_n^* @f$, where @f$ n = p q @f$.
	* 1. Use Algorithm 4.80 with @f$ G = \mathbb{Z}_p^* @f$ and @f$ n = p - 1 @f$ to find a generator @f$ a @f$ of @f$ \mathbb{Z}_p^* @f$.
	* 2. Use Algorithm 4.80 with @f$ G = \mathbb{Z}_q^* @f$ and @f$ n = q - 1 @f$ to find a generator @f$ b @f$ of @f$ \mathbb{Z}_q^* @f$.
	* 3. Use Gauss's algorithm (Algorithm 2.121) to find an integer @f$ \alpha @f$, @f$ 1 \leq \alpha \leq n - 1 @f$, satisfying @f$ \alpha \equiv a \pmod p @f$ and @f$ \alpha \equiv b \pmod q @f$.
	* 4. Return @f$ \alpha @f$.
	* 
	* For completeness, here are the two algorithms referenced above in Algorithm 4.83:
	* 
	* <b>Algorithm 4.80</b>, Chapter 4: Finding a generator of a cyclic group
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
	* <b>Algorithm 2.121</b>, Chapter 2 (Gauss's algorithm):
	* The solution @f$ x @f$ to the simultaneous congruences in the Chinese Remainder Theorem (Fact 2.120) may be computed as 
	* @f$ \sum_{i = 1}^{k}{a_i N_i M_i \pmod n} @f$, where @f$ N_i = n / n_i @f$ and @f$ M_i = N_i^{-1} \pmod {n_i} @f$.
	* These computations can be performed in @f$ O((\lg n)^2) @f$ bit operations.
	* 
	* <b>Fact 2.120</b>, Chapter 2: (Chinese remainder theorem, CRT) If the integers @f$ n_1 @f$, @f$ n_2 @f$, ..., @f$ n_k @f$ are pairwise relatively prime, then the system of simultaneous congruences
	* <p>@f$ x \equiv a_1 \pmod {n_1} @f$</p>
	* <p>@f$ x \equiv a_2 \pmod {n_2} @f$</p>
	* <p>@f$ \vdots @f$</p>
	* <p>@f$ x \equiv a_k \pmod {n_k} @f$</p>
	* has a unique solution modulo @f$ n = n_1 n_2 \cdots n_k @f$.
	* 
	* @return Always true, for now.
	* @throws std::runtime_error parameter errors.
	*/
	bool Dgk::GenerateKeys() {
		/// Generate @f$ u @f$ as the smallest prime having more than @f$ \ell + 2 @f$ bits.
		this->publicKey.u = BigInteger(2).GetPow(this->l + 2).GetNextPrime();

		//std::cout << "Message space: " << this->publicKey.u.ToString(10).c_str() << std::endl;

		/// Generate @f$ v_p @f$ and @f$ v_q @f$, two t bit primes.
		this->privateKey.vp = RandomProvider::GetInstance().GetMaxLengthRandomPrime(this->t);
		do {
			this->privateKey.vq = RandomProvider::GetInstance().GetMaxLengthRandomPrime(this->t);
		}
		/// We need to prevent @f$ v_p @f$ and @f$ v_q @f$ from dividing both p - 1 and q - 1, so we ensure that @f$ v_p \neq v_q @f$.
		/// Otherwise, one could compute @f$ a = (n - 1) / u^j @f$, where @f$ u^j @f$ is the maximal power of @f$ u @f$ that divides @f$ n - 1@f$, and, thus, it can be determined which numbers have order @f$ a @f$ in @f$ H @f$.
		while (this->privateKey.vq == this->privateKey.vp);

		/// Generate @f$ p = 2 p_r v_p u + 1 @f$ and @f$ q = 2 q_r v_q u + 1 @f$, where @f$ p_r @f$ and @f$ q_r @f$ are prime numbers.
		/// We impose @f$ p - 1 = 2 p_r v_p u @f$ and @f$ q - 1 = 2 q_r v_q u @f$ because, in order to generate @f$ h @f$ and @f$ g @f$, we need to have the factorization of @f$ p - 1 @f$ and @f$ q - 1 @f$.
		/// The factor 2 is required because the product of three odd primes is odd, and, thus, by adding one, we get an even number larger than 2 (which can't be prime)
		/// @f$ p @f$ and @f$ q @f$ must have @f$ k/2 @f$ bits length.
		BigInteger pRand, qRand;
		BigInteger aux;
		size_t sizeRand;

		//precompute 2 * u * vp
		aux = BigInteger(2) * this->publicKey.u * this->privateKey.vp;
		//compute the required length of the random part of p
		sizeRand = this->keyLength / 2 - aux.GetSize();

		if (0 == sizeRand) {
			/// @todo Throw a custom exception here!
			throw std::runtime_error("Parameter k is too small.");
		}

		do {
			//generate a prime number in the interval [0, 2^sizeRand)
			pRand = RandomProvider::GetInstance().GetMaxLengthRandomPrime(sizeRand);

			//p = pRand * 2 * u * vp + 1
			this->privateKey.p = pRand * aux + 1;
		}
		while (!this->privateKey.p.IsPrime());

		//precompute 2 * u * vq
		aux = BigInteger(2) * this->publicKey.u * this->privateKey.vq;

		sizeRand = this->keyLength / 2 - aux.GetSize();

		if (0 == sizeRand) {
			/// @todo Throw a custom exception here!
			throw std::runtime_error("Parameter k is too small.");
		}

		do {
			//generate a prime number in the interval [0, 2^sizeRand)
			qRand = RandomProvider::GetInstance().GetMaxLengthRandomPrime(sizeRand);
			
			//q = qRand * 2 * u * vq + 1
			this->privateKey.q = qRand * aux + 1;
		}
		while (!this->privateKey.q.IsPrime());

		/// Compute @f$ n = p q @f$
		this->publicKey.n = this->privateKey.p * this->privateKey.q;
		
		/// Compute @f$ h @f$ and @f$ g @f$:
		/// We compute @f$ h_r @f$ and @f$ g_r @f$ of order @f$ LCM(p - 1, q - 1) = (p - 1)(q - 1) / GCD(p - 1, q - 1) = 2 u p_r v_p q_r v_q @f$ in @f$ \mathbb{Z}_n^* @f$ with Algorithm 4.83

		BigInteger hRandP;
		do {
			//generate a random number in the interval [0, p)
			hRandP = RandomProvider::GetInstance().GetRandomInteger(this->privateKey.p);
		}
		//this loop can be optimized by precomputing the partial products
		while (hRandP == 1 ||
				BigInteger::Gcd(hRandP, this->privateKey.p) != 1 ||
				hRandP.GetPowModN(this->privateKey.vp * this->publicKey.u * 2, this->privateKey.p) == 1 ||
				hRandP.GetPowModN(pRand * this->publicKey.u * 2, this->privateKey.p) == 1 ||
				hRandP.GetPowModN(pRand * this->privateKey.vp * 2, this->privateKey.p) == 1 ||
				hRandP.GetPowModN(pRand * this->privateKey.vp * this->publicKey.u, this->privateKey.p) == 1);

		BigInteger hRandQ;
		do {
			//generate a random number in the interval [0, q)
			hRandQ = RandomProvider::GetInstance().GetRandomInteger(this->privateKey.q);
		}
		//this loop can be optimized by precomputing the partial products
		while (hRandQ == 1 ||
				BigInteger::Gcd(hRandQ, this->privateKey.q) != 1 ||
				hRandQ.GetPowModN(this->privateKey.vq * this->publicKey.u * 2, this->privateKey.q) == 1 ||
				hRandQ.GetPowModN(qRand * this->publicKey.u * 2, this->privateKey.q) == 1 ||
				hRandQ.GetPowModN(qRand * this->privateKey.vq * 2, this->privateKey.q) == 1 ||
				hRandQ.GetPowModN(qRand * this->privateKey.vq * this->publicKey.u, this->privateKey.q) == 1);

		//construct hRand with the Chinese Remainder Theorem
		BigInteger hRand = (hRandP * this->privateKey.q * this->privateKey.q.GetInverseModN(this->privateKey.p) + hRandQ * this->privateKey.p * this->privateKey.p.GetInverseModN(this->privateKey.q)) % this->publicKey.n;

		/// Since @f$ h @f$ must have order @f$ v_p v_q @f$ in @f$ \mathbb{Z}_n^* @f$, compute @f$ h = h_r^{2 u p_r q_r} \pmod n @f$
		this->publicKey.h = hRand.GetPowModN(BigInteger(2) * this->publicKey.u * pRand * qRand, this->publicKey.n);

		BigInteger gRandP;
		do {
			//generate a random number in the interval [0, p)
			gRandP = RandomProvider::GetInstance().GetRandomInteger(this->privateKey.p);
			
		}
		//this loop can be optimized by precomputing the partial products
		while (gRandP == 1 ||
				BigInteger::Gcd(gRandP, this->privateKey.p) != 1 ||
				gRandP.GetPowModN(this->privateKey.vp * this->publicKey.u * 2, this->privateKey.p) == 1 ||
				gRandP.GetPowModN(pRand * this->publicKey.u * 2, this->privateKey.p) == 1 ||
				gRandP.GetPowModN(pRand * this->privateKey.vp * 2, this->privateKey.p) == 1 ||
				gRandP.GetPowModN(pRand * this->privateKey.vp * this->publicKey.u, this->privateKey.p) == 1);
		
		BigInteger gRandQ;
		do {
			//generate a random number in the interval [0, q)
			gRandQ = RandomProvider::GetInstance().GetRandomInteger(this->privateKey.q);
			
		}
		//this loop can be optimized by precomputing the partial products
		while (gRandQ == 1 ||
				BigInteger::Gcd(gRandQ, this->privateKey.q) != 1 ||
				gRandQ.GetPowModN(this->privateKey.vq * this->publicKey.u * 2, this->privateKey.q) == 1 ||
				gRandQ.GetPowModN(qRand * this->publicKey.u * 2, this->privateKey.q) == 1 ||
				gRandQ.GetPowModN(qRand * this->privateKey.vq * 2, this->privateKey.q) == 1 ||
				gRandQ.GetPowModN(qRand * this->privateKey.vq * this->publicKey.u, this->privateKey.q) == 1);

		//construct gRand with the Chinese Remainder Theorem
		BigInteger gRand = (gRandP * this->privateKey.q * this->privateKey.q.GetInverseModN(this->privateKey.p) + gRandQ * this->privateKey.p * this->privateKey.p.GetInverseModN(this->privateKey.q)) % this->publicKey.n;

		/// Since @f$ g @f$ must have order @f$ u v_p v_q @f$ in @f$ \mathbb{Z}_n^* @f$, compute @f$ g = g_r^{2 p_r q_r} \pmod n @f$
		this->publicKey.g = gRand.GetPowModN(pRand * qRand * 2, this->publicKey.n);

		//precompute values for optimization purposes
		this->doPrecomputations();

		return true;
	}

	/**
	If @f$ plaintext \geq \lfloor messagespace / 2 @f$, it is remapped to a negative value.

	@param ciphertext the ciphertext integer
	@return Deciphered plaintext
	@throws std::runtime_error the ciphertext can not be decrypted
	@throws std::runtime_error operation requires the private key
	@throws std::runtime_error operation requires the decryption map
	*/
	BigInteger Dgk::DecryptInteger (const Dgk::Ciphertext &ciphertext) const {
		if (!this->hasPrivateKey) {
			throw std::runtime_error("This operation requires the private key.");
		}

		if (!this->precomputeDecryptionMap) {
			throw std::runtime_error("This operation requires the decryption map.");
		}

		/// @f$ m @f$ is uniquely determined by either @f$ E_{pk}(m,r)^{v_p} = g^{v_p m} \pmod p @f$ or @f$ E_{pk}(m,r)^{v_q} = g^{v_q m} \pmod q @f$.
		/// Since we cannot determine @f$ m @f$ directly, we precompute all @f$ g^{v_p m} \pmod p @f$ values, we store them in an std::map and we try to find m that matches @f$ c^{v_p} \pmod p @f$

		BigInteger cPowVpModP = ciphertext.data.GetPowModN(this->privateKey.vp, this->privateKey.p);

		/// Shortcut: if @f$ c^{v_p} \pmod p = 1 @f$, then @f$ c = \llbracket 0 \rrbracket @f$
		if (cPowVpModP == 1) {
			return 0;
		}

		BigInteger output;

		//get an iterator to the required element
		DecryptionMap::const_iterator iterator = this->decryptionMap.find(cPowVpModP);

		//make sure the key exists
		if (this->decryptionMap.end() != iterator) {
			output = BigInteger(iterator->second);
		}
		else {
			//@todo custom exception
			throw std::runtime_error("Can't decrypt ciphertext.");
		}

		/// If @f$ plaintext < \lfloor messagespace / 2 \rfloor \Rightarrow plaintext \geq 0 @f$ otherwise if @f$ plaintext < 0 \Rightarrow plaintext = plaintext - messageSpaceUpperBound  @f$
		if (output > this->positiveNegativeBoundary) {
			output -= this->GetMessageSpaceUpperBound();
		}

		return output;
	}

	/**
	Computes @f$ c_{nonrand} = g^m \pmod n @f$

	@param plaintext the plaintext integer
	@return Encrypted ciphertext
	*/
	Dgk::Ciphertext Dgk::EncryptIntegerNonrandom (const BigInteger &plaintext) const {
		/**
		* - "Standard" version: @f$ c = g^m h^r \pmod n @f$
		* - "Shortcut" version - use the Chinese Remainder Theorem @f$ \left( x = \sum_{i} a_i \frac{N}{n_i} \left[\left(\frac{N}{n_i}\right)^{-1}\right]_{n_i} \right) @f$ to speed up computations:
		*	- @f$ c_{nonrand} = g^m \pmod n = (g^m \bmod p) q (q^{-1}\bmod p) + (g^m \bmod q) p (p^{-1}\bmod q) \pmod n @f$
		*	- @f$ r_h = h^r \pmod {n} = (h^r \bmod p) q (q^{-1}\bmod p) + (h^r \bmod q) p (p^{-1}\bmod q) \pmod n @f$
		*
		* The computation is performed in two steps:
		* - encrypt data (compute @f$ c_{nonrand} @f$)
		* - randomize ciphertext (compute @f$ c_{nonrand} r_h \pmod n @f$)
		*/

		Ciphertext output(this->encryptionModulus);

		/// If @f$ plaintext < 0 @f$, we remap it to the second half of the message space

		/// @todo Speedup hint: remove the modulo n reduction, since it's performed later in RandomizeCiphertext...???

		if (!this->hasPrivateKey) {
			/// Standard version: @f$ c_{nonrand} = g^m \pmod n @f$
			if (plaintext < 0) {
				output.data = this->publicKey.g.GetPowModN(this->GetMessageSpaceUpperBound() + plaintext, this->publicKey.n);
			}
			else {
				output.data = this->publicKey.g.GetPowModN(plaintext, this->publicKey.n);
			}
		}
		else {
			/// Fast version: @f$ c_{nonrand} = (g^m \bmod p) q (q^{-1}\bmod p) + (g^m \bmod q) p (p^{-1}\bmod q) \pmod n @f$
			if (plaintext < 0) {
				output.data = (this->publicKey.g.GetPowModN(this->GetMessageSpaceUpperBound() + plaintext, this->privateKey.p) * this->qTimesQInvModP + this->publicKey.g.GetPowModN(this->GetMessageSpaceUpperBound() + plaintext, this->privateKey.q) * this->pTimesPInvModQ) % this->publicKey.n;
			}
			else {
				output.data = (this->publicKey.g.GetPowModN(plaintext, this->privateKey.p) * this->qTimesQInvModP + this->publicKey.g.GetPowModN(plaintext, this->privateKey.q) * this->pTimesPInvModQ) % this->publicKey.n;
			}
		}

		return output;
	}

	/**
	Selects random @f$ r \in \mathbb{Z}_{v_p v_q} @f$ and computes @f$ h^r \pmod n @f$

	Speedup hint: remove the modulo n reduction?
	@return the random factor
	*/
	Dgk::Randomizer Dgk::GetRandomizer () const {
		/*
		Notes from the paper:

		A final word on performance of encryption: if we want to make sure
		that h^r mod n is uniform in the group generated by h, we should choose
		r somewhat longer than 2t bits, say of length 2.5t bits - since in the cor-
		rected system, the order of h is 2t bits long. This will cause the encryption
		to take about 25% more time compared to the original system. However, if
		one is willing to make the additional assumption that raising h to a 2t-bit
		exponent produces an element that is computationally indistinguishable
		from uniform in H, then one can keep the original encryption algorithm
		and this means that using the corrected system in the protocols from
		[1, 2] will produce exactly the same performance as reported there.
		*/

		/// The public key does not allow us to compute @f$ v_p * v_q @f$, so we choose a random number of size @f$ 2 t @f$
		BigInteger random = RandomProvider::GetInstance().GetRandomInteger(2 * this->t);

		if (!this->hasPrivateKey) {
			/// "Standard" version: @f$ h^r \pmod n @f$
			return Randomizer(this->publicKey.h.GetPowModN(random, this->publicKey.n));
		}
		else {
			/// "Shortcut" version: @f$ h^r \pmod {n} = (h^r \bmod p) q (q^{-1}\bmod p) + (h^r \bmod q) p (p^{-1}\bmod q) \pmod n @f$
			return Randomizer((this->publicKey.h.GetPowModN(random, this->privateKey.p) * this->qTimesQInvModP + this->publicKey.h.GetPowModN(random, this->privateKey.q) * this->pTimesPInvModQ) % this->publicKey.n);
		}
	}

	/**
	Computes @f$ c = c h^r \pmod n @f$

	@param ciphertext the ciphertext integer
	@return The randomized ciphertext
	*/
	Dgk::Ciphertext Dgk::RandomizeCiphertext (const Dgk::Ciphertext &ciphertext) const {
		return Ciphertext((ciphertext.data * this->randomizerCache->Pop().randomizer.data) % this->GetEncryptionModulus(), this->encryptionModulus);
	}

	/**
	@return @f$ u @f$
	*/
	const BigInteger &Dgk::GetMessageSpaceUpperBound () const {
		return this->publicKey.u;
	}

	/**
	@return The message space bit size.
	*/
	size_t Dgk::GetMessageSpaceSize () const {
		return this->publicKey.u.GetSize();
	}

	/**
	If and only if @f$ m = 0 @f$, then both @f$ c^{v_p} \pmod p = 1 @f$ and @f$ c^{v_q} \pmod q = 1 @f$. It suffices to test only @f$ c^{v_p} \pmod p @f$.

	This is faster than the actual decryption, since the table lookup is not required.

	@param ciphertext a DGK ciphertext
	@return True if ciphertext = [0] and fase otherwise
	*/
	bool Dgk::IsEncryptedZero (const Ciphertext &ciphertext) const {
		if (!this->hasPrivateKey) {
			throw std::runtime_error("This operation requires the private key.");
		}

		BigInteger test = ciphertext.data.GetPowModN(this->privateKey.vp, this->privateKey.p);

		return test == 1 ? true : false;
	}

	/**
	@throws std::runtime_error the configuration parameters are invalid
	*/
	void Dgk::validateParameters () {
		/// @todo Throw custom parameter exceptions below!!!
		/* See here https://www.cryptool.org/trac/CrypTool2/browser/trunk/CrypPlugins/DGK/DGKKeyGenerator.cs for the original source of parameter validation */
		if (this->l < 8 || this->l > 32) {
			throw std::runtime_error("The l parameter must obey the following constraints: 8 <= l <= 32.");
		}
		if (this->t <= this->l) {
			throw std::runtime_error("Parameter t must be greater than l.");
		}
		if (this->keyLength <= this->t) {
			throw std::runtime_error("Parameter k must be greater than t.");
		}

		if (this->keyLength % 2 != 0) {
			throw std::runtime_error("The k parameter must be even.");
		}
		/* These need to be revised...
		if (!((this->keyLength / 2 > (this->l + 4)) && (this->keyLength / 2 > (this->t + 1)))) {
			throw std::runtime_error("The k parameter must obey the following constraints: k / 2 > l + 4 and k / 2 > t + 1.");
		}
		*/
		if (this->keyLength / 2 < this->l + this->t + 10) {
			throw std::runtime_error("Choose parameters k, l, t such that k / 2 >= l + t + 10.");
		}
	}

	/**
	Precomputes the message space delimiter between positive and negative values.

	Precomputes [0] and [1].
	*/
	void Dgk::doPrecomputations () {
		if (this->hasPrivateKey) {
			/// Precompute all possible values of @f$ g^{v_p m} \pmod p @f$ or @f$ g^{v_q m} \pmod q @f$ to speed up decryption, where @f$ m \in \mathbb{Z}_u @f$.
			/// We choose to compute @f$ g^{v_p m} \pmod p @f$
			if (this->precomputeDecryptionMap) {
				for (BigInteger i = 0; i < this->publicKey.u; ++i) {
					this->decryptionMap[this->publicKey.g.GetPowModN(this->privateKey.vp * i, this->privateKey.p)] = i;
				}
			}

			/// Speed optimizations for encryption: compute @f$ p (p^{-1} \pmod q) @f$ and @f$ q (q^{-1} \pmod p) @f$
			try {
				this->pTimesPInvModQ = this->privateKey.p * this->privateKey.p.GetInverseModN(this->privateKey.q);
				this->qTimesQInvModP = this->privateKey.q * this->privateKey.q.GetInverseModN(this->privateKey.p);
			}
			/// @todo Catch a custom exception here
			catch (std::runtime_error) {
				//if gcd(p, q) != 1, throw an error
				throw std::runtime_error("p and q are not coprime.");
			}
		}

		//set the encryption modulus, @f$ n @f$
		this->encryptionModulus = std::make_shared<BigInteger>(this->publicKey.n);

		//precompute the limit between positive and negative values in the message space
		this->positiveNegativeBoundary = this->GetMessageSpaceUpperBound() / 2;
		
		/// Populate the randomizer cache
		this->randomizerCache = std::unique_ptr<RandomizerCacheType>(new RandomizerCacheType(*this, "Core.RandomizerCache"));

		this->encryptedZero = this->EncryptInteger(BigInteger(0));

		this->encryptedOne = this->EncryptInteger(BigInteger(1));
	}

}//namespace Core
}//namespace SeComLib