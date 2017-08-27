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
@file core/paillier.cpp
@brief Implementation of class Paillier.
@details Implementation described in the paper "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes" by Pacal Paillier, 1999 (using CRT to speedup decryption)
@author Mihai Todor (todormihai@gmail.com)
*/

#include "paillier.h"

namespace SeComLib {
namespace Core {
	/**
	Does not initialize the encryptionModulus.
	*/
	PaillierCiphertext::PaillierCiphertext () :
		CiphertextBase<PaillierCiphertext> () {
	}

	/**
	Initializes the encryptionModulus
	@param encryptionModulus The encryption modulus
	*/
	PaillierCiphertext::PaillierCiphertext (const std::shared_ptr<BigInteger> &encryptionModulus) :
		CiphertextBase<PaillierCiphertext> (encryptionModulus) {
	}

	/**
	Initializes the data and the encryptionModulus
	@param data the ciphertext data
	@param encryptionModulus The encryption modulus
	*/
	PaillierCiphertext::PaillierCiphertext (const BigInteger &data, const std::shared_ptr<BigInteger> &encryptionModulus) :
		CiphertextBase<PaillierCiphertext> (data, encryptionModulus) {
	}

	/**
	*/
	PaillierRandomizer::PaillierRandomizer () : RandomizerBase() {
	}

	/**
	Initializes the data
	@param data the randomizer data
	*/
	PaillierRandomizer::PaillierRandomizer (const BigInteger &data) : RandomizerBase(data) {
	}

	/**
	Sets the specified key size from the configuration file (defaults to 1024)
	*/
	Paillier::Paillier () : CryptoProvider<PaillierPublicKey, PaillierPrivateKey, PaillierCiphertext, PaillierRandomizer>(Utils::Config::GetInstance().GetParameter("Core.Paillier.keySize", 1024)) {
	}

	/**
	Performs required precomputations.

	@param publicKey a PaillierPublicKey structure
	*/
	Paillier::Paillier (const PaillierPublicKey &publicKey) : CryptoProvider<PaillierPublicKey, PaillierPrivateKey, PaillierCiphertext, PaillierRandomizer>(publicKey, Utils::Config::GetInstance().GetParameter("Core.Paillier.keySize", 1024)) {
		//C++ doesn't allow us to call a virtual method in the constructor of the base class
		this->doPrecomputations();
	}

	/**
	Performs required precomputations.

	@param publicKey a PaillierPublicKey structure
	@param privateKey a PaillierPrivateKey structure
	*/
	Paillier::Paillier (const PaillierPublicKey &publicKey, const PaillierPrivateKey &privateKey) :
		CryptoProvider<PaillierPublicKey, PaillierPrivateKey, PaillierCiphertext, PaillierRandomizer>(publicKey, privateKey, Utils::Config::GetInstance().GetParameter("Core.Paillier.keySize", 1024)) {
		//C++ doesn't allow us to call a virtual method in the constructor of the base class
		this->doPrecomputations();
	}

	/**
	Generates the Paillier cryptosystem keys.

	Produces @f$ p @f$ and @f$ q @f$, each having half of the key length, and computes @f$ n = p q @f$, enforcing @f$ n @f$ to have the length specified by the key length.

	@return Always true, for now
	*/
	bool Paillier::GenerateKeys () {
		/// Set the length of primes p and q
		unsigned int primeLength = (unsigned int)(this->keyLength / 2);

		do {
			this->privateKey.p = RandomProvider::GetInstance().GetMaxLengthRandomPrime(primeLength);
			this->privateKey.q = RandomProvider::GetInstance().GetMaxLengthRandomPrime(primeLength);

			//std::cout << this->privateKey.p.GetSize() << std::endl;
			//std::cout << this->privateKey.q.GetSize() << std::endl;
	
			/// If both are equal (highly unlikely) seek another prime
			while (this->privateKey.p == this->privateKey.q) {
				this->privateKey.p = RandomProvider::GetInstance().GetMaxLengthRandomPrime(primeLength);
			}

			/// Compute @f$ n = p q @f$
			this->publicKey.n = this->privateKey.p * this->privateKey.q;

			this->nMinusOne = this->publicKey.n - 1;
			this->nSquared = this->publicKey.n.GetPow(2);

			//std::cout << this->n.GetSize() << std::endl;
		}
		while (this->publicKey.n.GetSize() != this->keyLength);/// Need to guarantee that n always has the specified length? There should be a faster implementation for this...

		//std::cout << this->publicKey.n.GetSize() << std::endl;

	#ifdef USE_STANDARD_PAILLIER_ALGORITHM
		/// "Standard" version:
		
		/// @f$ \lambda = lcm(p - 1, q - 1) @f$
		this->privateKey.lambda = BigInteger::Lcm(this->privateKey.p - 1, this->privateKey.q - 1);

		/// Select random @f$ g @f$ from interval @f$ (0, keyLength^2] @f$
		this->publicKey.g = RandomProvider::GetInstance().GetRandomInteger(this->keyLength * this->keyLength);

		/// @f$ \mu = {L(g^{\lambda} \pmod {n^2})}^{-1} \pmod n @f$
		this->privateKey.mu = this->L(this->publicKey.g.GetPowModN(this->privateKey.lambda, this->nSquared), this->publicKey.n).InvertModN(this->publicKey.n);

	#else
		/// "Shortcut" version:

		/// Set @f$ g = n + 1 @f$
		this->publicKey.g = this->publicKey.n + 1;

		/// @f$ \phi(n) @f$, @f$ \lambda @f$ and @f$ \mu @f$ are required by the "shortcut version" of the algorithm, but are no longer needed if decryption is done via CRT
		/*
		/// Compute Euler's totient function @f$ \phi(n) = (q - 1)*(p - 1) @f$
		BigInteger phi = (this->privateKey.p - 1) * (this->privateKey.q - 1);
		/// @f$ \lambda = \phi @f$
		this->privateKey.lambda = phi;
		/// @f$ \mu = \phi^{-1} \pmod n @f$
		this->privateKey.mu = phi.InvertModN(this->publicKey.n);
		*/

	#endif

		//precompute values for optimization purposes
		this->doPrecomputations();

		return true;
	}

	/**
	If @f$ plaintext \geq \lfloor messagespace / 2 @f$, it is remapped to a negative value.

	@param ciphertext the ciphertext integer
	@return Deciphered plaintext
	@throws std::runtime_error operation requires the private key
	*/
	BigInteger Paillier::DecryptInteger (const Paillier::Ciphertext &ciphertext) const {
		if (!this->hasPrivateKey) {
			throw std::runtime_error("This operation requires the private key.");
		}

	#ifdef USE_STANDARD_PAILLIER_ALGORITHM
		/// @f$ plaintext = L(c^{\lambda} \pmod {n^2}) \mu \pmod n @f$
		///
		/// @f$ L(u) = \frac{u - 1}{n} @f$
		BigInteger output = (this->L(ciphertext.data.GetPowModN(this->privateKey.lambda, this->nSquared), this->publicKey.n) * this->privateKey.mu) % this->publicKey.n;
	#else
		/**
		Apply CRT for decryption:
		@f$ h_p = L_p(g^{p - 1} (\pmod p^2))^{-1} \pmod p @f$
		@f$ h_q = L_q(g^{q - 1} (\pmod q^2))^{-1} \pmod q @f$
		@f$ m_p = L_p(c^{p - 1} (\pmod p^2)) h_p \pmod p @f$
		@f$ m_q = L_q(c^{q - 1} (\pmod q^2)) h_q \pmod q @f$
		@f$ m = (m_p q (q^{-1} \pmod p) + m_q p (p^{-1} \pmod q)) (\pmod n) @f$
		*/
		BigInteger mp = (this->L(ciphertext.data.GetPowModN(this->pMinusOne, this->pSquared), this->privateKey.p) * this->hp) % this->privateKey.p;
		BigInteger mq = (this->L(ciphertext.data.GetPowModN(this->qMinusOne, this->qSquared), this->privateKey.q) * this->hq) % this->privateKey.q;
		BigInteger output = (mp * this->qTimesQInvModP + mq * this->pTimesPInvModQ) % this->publicKey.n;
	#endif

		/// If @f$ plaintext \leq \lfloor messagespace / 2 \rfloor \Rightarrow plaintext \geq 0 @f$ otherwise @f$ plaintext < 0 \Rightarrow plaintext = plaintext - messagespace  @f$
		if (output > this->positiveNegativeBoundary) {
			output -= this->GetMessageSpaceUpperBound();
		}

		return output;
	}

	/**
	Contains the "standard" and "shortcut" versions of the Paillier encryption algorithm without randomization.

	@param plaintext the plaintext integer
	@return Encrypted ciphertext
	*/
	Paillier::Ciphertext Paillier::EncryptIntegerNonrandom (const BigInteger &plaintext) const {
		/**
		* - "Standard" version: @f$ c = g^m r^n \pmod {n^2} @f$
		* - "Shortcut" version: @f$ c = (n*m + 1) r^n \pmod {n^2} @f$
		* The computation is performed in two steps:
		* - encrypt data
		* - randomize ciphertext
		*/

		Ciphertext output(this->encryptionModulus);

		/// If @f$ plaintext < 0 @f$, we remap it to the second half of the message space

	#ifdef USE_STANDARD_PAILLIER_ALGORITHM
		/// "Standard" version: @f$ c = g^m \pmod {n^2} @f$

		//compute c = g^m (mod n^2)
		if (plaintext < 0) {
			output.data = this->publicKey.g.GetPowModN(this->GetMessageSpaceUpperBound() + plaintext, this->nSquared);
		}
		else {
			output.data = this->publicKey.g.GetPowModN(plaintext, this->nSquared);
		}
	#else
		/// "Shortcut" version: @f$ c = (n*m + 1) \pmod {n^2} @f$

		//compute c = n * m + 1 (we skip the modulo operation, since it's done in RandomizeCiphertext)
		if (plaintext < 0) {
			output.data = this->publicKey.n * (this->GetMessageSpaceUpperBound() + plaintext) + 1;
		}
		else {
			output.data = this->publicKey.n * plaintext + 1;
		}
	#endif

		return output;
	}

	/**
	Generates a random number @f$ r \in \mathbb{Z}_n^* @f$ and computes @f$ r^n \pmod {n^2} @f$.

	Computes @f$ r^n \pmod {n^2} @f$.

	@return the randomizer
	*/
	Paillier::Randomizer Paillier::GetRandomizer () const {
		return Randomizer((RandomProvider::GetInstance().GetRandomInteger(this->nMinusOne) + 1).GetPowModN(this->publicKey.n, this->nSquared));
	}

	/**
	Computes @f$ c = c r^n \pmod {n^2} @f$.

	@param ciphertext the ciphertext integer
	@return The randomized ciphertext
	*/
	Paillier::Ciphertext Paillier::RandomizeCiphertext (const Paillier::Ciphertext &ciphertext) const {
		return Ciphertext((ciphertext.data * this->randomizerCache->Pop().randomizer.data) % this->GetEncryptionModulus(), this->encryptionModulus);
	}

	/**
	@return @f$ n @f$
	*/
	const BigInteger &Paillier::GetMessageSpaceUpperBound () const {
		return this->publicKey.n;
	}

	/**
	@return The message space bit size.
	*/
	size_t Paillier::GetMessageSpaceSize () const {
		return this->publicKey.n.GetSize();
	}

	/**
	Computes @f$ L(u) = \frac{u - 1}{d} @f$

	@param input the function variable
	@param d the divisor
	@return L(input)
	*/
	BigInteger Paillier::L (const BigInteger &input, const BigInteger &d) const {
		BigInteger output;

		output = (input - 1) / d;

		return output;
	}

	/**
	*/
	void Paillier::doPrecomputations () {
		if (this->precomputeSpeedupValues) {
			this->nSquared = this->publicKey.n.GetPow(2);
			this->nMinusOne = this->publicKey.n - 1;
		}

		if (this->hasPrivateKey) {
			/// Precompute @f$ h_p = L_p(g^{p - 1} (\pmod p^2))^{-1} \pmod p @f$ and @f$ h_q = L_q(g^{q - 1} (\pmod q^2))^{-1} \pmod q @f$ to speed up decryption via CRT
			this->pMinusOne = this->privateKey.p - 1;
			this->qMinusOne = this->privateKey.q - 1;
			this->pSquared = this->privateKey.p * this->privateKey.p;
			this->qSquared = this->privateKey.q * this->privateKey.q;
			this->hp = this->L(this->publicKey.g.GetPowModN(this->pMinusOne, this->pSquared), this->privateKey.p).InvertModN(this->privateKey.p);
			this->hq = this->L(this->publicKey.g.GetPowModN(this->qMinusOne, this->qSquared), this->privateKey.q).InvertModN(this->privateKey.q);

			/// Speed optimizations for decryption: precompute @f$ p (p^{-1} \pmod q) @f$ and @f$ q (q^{-1} \pmod p) @f$
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

		//set the encryption modulus, @f$ n^2 @f$
		this->encryptionModulus = std::make_shared<BigInteger>(this->nSquared);

		//precompute the limit between positive and negative values in the message space
		this->positiveNegativeBoundary = this->GetMessageSpaceUpperBound() / 2;

		/// Populate the randomizer cache
		this->randomizerCache = std::unique_ptr<RandomizerCacheType>(new RandomizerCacheType(*this, "Core.RandomizerCache"));

		this->encryptedZero = this->EncryptInteger(BigInteger(0));

		this->encryptedOne = this->EncryptInteger(BigInteger(1));
	}

}//namespace Core
}//namespace SeComLib