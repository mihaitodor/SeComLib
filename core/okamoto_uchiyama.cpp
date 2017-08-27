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
@file core/okamoto_uchiyama.cpp
@brief Implementation of class OkamotoUchiyama.
@details Implementation described in the paper "Accelerating Okamoto-Uchiyama's Public-Key Cryptosystem" by Jean-Sebastien Coron, David Naccache and Pascal Paillier, 1999
@author Mihai Todor (todormihai@gmail.com)
*/

#include "okamoto_uchiyama.h"

namespace SeComLib {
namespace Core {
	/**
	Does not initialize the encryptionModulus.
	*/
	OkamotoUchiyamaCiphertext::OkamotoUchiyamaCiphertext () :
		CiphertextBase<OkamotoUchiyamaCiphertext> () {
	}

	/**
	Initializes the encryptionModulus 
	@param encryptionModulus The encryption modulus
	*/
	OkamotoUchiyamaCiphertext::OkamotoUchiyamaCiphertext (const std::shared_ptr<BigInteger> &encryptionModulus) :
		CiphertextBase<OkamotoUchiyamaCiphertext> (encryptionModulus) {
	}

	/**
	Initializes the data and the encryptionModulus 
	@param data the ciphertext data
	@param encryptionModulus The encryption modulus
	*/
	OkamotoUchiyamaCiphertext::OkamotoUchiyamaCiphertext (const BigInteger &data, const std::shared_ptr<BigInteger> &encryptionModulus) :
		CiphertextBase<OkamotoUchiyamaCiphertext> (data, encryptionModulus) {
	}

	/**
	*/
	OkamotoUchiyamaRandomizer::OkamotoUchiyamaRandomizer () : RandomizerBase() {
	}

	/**
	Initializes the data
	@param data the randomizer data
	*/
	OkamotoUchiyamaRandomizer::OkamotoUchiyamaRandomizer (const BigInteger &data) : RandomizerBase(data) {
	}

	/**
	Fetch the key lengh from the configuration file (defaults to 1024).
	*/
	OkamotoUchiyama::OkamotoUchiyama () :
		CryptoProvider<OkamotoUchiyamaPublicKey, OkamotoUchiyamaPrivateKey, OkamotoUchiyamaCiphertext, OkamotoUchiyamaRandomizer>(Utils::Config::GetInstance().GetParameter("Core.OkamotoUchiyama.keySize", 1024)),
		messageSpaceSize(Utils::Config::GetInstance().GetParameter<size_t>("Core.OkamotoUchiyama.messageSpaceSize")) {
	}

	/**
	Performs required precomputations.

	@param publicKey a OkamotoUchiyamaPublicKey structure
	*/
	OkamotoUchiyama::OkamotoUchiyama (const OkamotoUchiyamaPublicKey &publicKey) :
		CryptoProvider<OkamotoUchiyamaPublicKey, OkamotoUchiyamaPrivateKey, OkamotoUchiyamaCiphertext, OkamotoUchiyamaRandomizer>(publicKey, Utils::Config::GetInstance().GetParameter("Core.OkamotoUchiyama.keySize", 1024)),
		messageSpaceSize(Utils::Config::GetInstance().GetParameter<size_t>("Core.OkamotoUchiyama.messageSpaceSize")) {
		//precompute values for optimization purposes
		this->doPrecomputations();
	}

	/**
	Performs required precomputations.

	@param publicKey a OkamotoUchiyamaPublicKey structure
	@param privateKey a OkamotoUchiyamaPrivateKey structure
	*/
	OkamotoUchiyama::OkamotoUchiyama (const OkamotoUchiyamaPublicKey &publicKey, const OkamotoUchiyamaPrivateKey &privateKey) :
		CryptoProvider<OkamotoUchiyamaPublicKey, OkamotoUchiyamaPrivateKey, OkamotoUchiyamaCiphertext, OkamotoUchiyamaRandomizer>(publicKey, privateKey, Utils::Config::GetInstance().GetParameter("Core.OkamotoUchiyama.keySize", 1024)),
		messageSpaceSize(Utils::Config::GetInstance().GetParameter<size_t>("Core.OkamotoUchiyama.messageSpaceSize")) {
		//precompute values for optimization purposes
		this->doPrecomputations();
	}

	/**
	Generates the Okamoto-Uchiyama cryptosystem keys.

	@return Always true, for now.
	@throws std::runtime_error parameter errors
	*/
	bool OkamotoUchiyama::GenerateKeys() {
		/// Fetch the size of the parameter @f$ t @f$ from the configuration file (defaults to 160)
		unsigned int sizeT = Utils::Config::GetInstance().GetParameter("Core.OkamotoUchiyama.sizeT", 160);

		/// Set the length of primes p and q
		unsigned int primeLength = static_cast<unsigned int>(this->keyLength / 3);
		if (sizeT >= primeLength) {
			/// @todo Throw a custom exception here!
			throw std::runtime_error("Key size must be larger than the t parameter.");
		}

		/// Generate primes @f$ p @f$ and @f$ q @f$ of roughly size keyLength / 3, ensuring that @f$ p - 1 @f$ has a large prime factor of size specified by the t parameter

		//pick a random prime t of size specified by sizeT
		this->privateKey.t = RandomProvider::GetInstance().GetMaxLengthRandomPrime(sizeT);

		/// @f$ p - 1 = t u @f$, where @f$ u @f$ is a random number in @f$ \mathbb{Z}_n @f$
		/// u - local variable required for cumputing p, H and G
		BigInteger u;
		unsigned int sizeU = primeLength - sizeT;
		do {
			//generate a random number in the interval [0, 2^(sizeU - 1))
			u = RandomProvider::GetInstance().GetRandomInteger(sizeU - 1);

			//shift number to the interval [2^(sizeU - 1), 2^sizeU)
			u.SetBit(sizeU - 1);

			//u and t must divide p - 1
			this->privateKey.p = this->privateKey.t * u + 1;
		}
		while (!this->privateKey.p.IsPrime());

		//precompute p^2 and store it for the decryption operation
		this->pSquared = this->privateKey.p.GetPow(2);

		/// Generate prime q of size keyLength
		this->privateKey.q = RandomProvider::GetInstance().GetMaxLengthRandomPrime(primeLength);

		/// Compute @f$ n = p^2 q @f$
		this->publicKey.n = this->pSquared * this->privateKey.q;

		/// @warning n will probably have size at most keySize - 1 bits. Is this a problem?
		//std::cout << this->publicKey.n.GetSize() << std::endl;

		/// Select random @f$ g < n @f$, @f$g \in \mathbb{Z}_{p^2}^* @f$, such that @f$ g_p = g^{p - 1} \pmod {p^2} @f$ is of order @f$ p @f$ in @f$ \mathbb{Z}_{p^2}^* @f$
		do {
			do {
				//generate random g in the interval [0, n)
				this->g = RandomProvider::GetInstance().GetRandomInteger(this->publicKey.n);
			}
			//ensure that g is in the cyclic group Z_{p^2}*
			while (BigInteger::Gcd(this->g, this->privateKey.p) != 1);

			//gp = g^(p - 1) (mod p^2)
			this->privateKey.gp = this->g.GetPowModN(this->privateKey.p - 1, this->pSquared);
		}
		//ensure that gp^p = 1 (mod p^2)
		while (this->privateKey.gp.GetPowModN(this->privateKey.p, this->pSquared) != 1);

		/// Compute @f$ G = g^u \pmod n @f$
		this->publicKey.G = this->g.GetPowModN(u, this->publicKey.n);

		/// Select random @f$ g' \in \mathbb{Z}_n @f$, @f$g' \in \mathbb{Z}_{p^2}^* @f$, and compute @f$ H = g'^{n u} \pmod n @f$
		BigInteger gPrime;

		do {
			//generate random g' in the interval [0, n)
			gPrime = RandomProvider::GetInstance().GetRandomInteger(this->publicKey.n);
		}
		//ensure that g' is in the cyclic group Z_n*
		while (BigInteger::Gcd(gPrime, this->publicKey.n) != 1);

		//H = g'^(n * u) (mod n)
		this->publicKey.H = gPrime.GetPowModN(this->publicKey.n * u, this->publicKey.n);

		//precompute values for optimization purposes
		this->doPrecomputations();

		return true;
	}

	/**
	If @f$ plaintext \geq \lfloor messagespace / 2 @f$, it is remapped to a negative value.

	Algoithm:
	1. @f$ c' = c^{p - 1} \pmod {p^2} = g^{m (p - 1)} g'^{n r (p - 1)} = g_p^m \pmod {p^2} @f$
	2. @f$ m = L(c') L(g_p)^{-1} \pmod p @f$, where @f$ L(u) = \frac{u - 1}{n} @f$

	@param ciphertext the ciphertext integer
	@return Deciphered plaintext
	@throws std::runtime_error operation requires the private key
	*/
	BigInteger OkamotoUchiyama::DecryptInteger (const OkamotoUchiyama::Ciphertext &ciphertext) const {
		if (!this->hasPrivateKey) {
			throw std::runtime_error("This operation requires the private key.");
		}

		/// Compute @f$ m = L(c^t \pmod {p^2}) L(g_p)^{-1} \pmod p @f$
		BigInteger output = (this->L(ciphertext.data.GetPowModN(this->privateKey.t, this->pSquared)) * this->lgpInv) % this->privateKey.p;

		/// If @f$ plaintext \leq \lfloor messagespace / 2 \rfloor \Rightarrow plaintext \geq 0 @f$ otherwise @f$ plaintext < 0 \Rightarrow plaintext = plaintext - messagespace  @f$
		if (output > this->positiveNegativeBoundary) {
			output -= this->GetMessageSpaceUpperBound();
		}

		return output;
	}

	/**
	Contains the Okamoto-Uchiyama encryption algorithm without randomization.
	@param plaintext the plaintext integer
	@return Encrypted ciphertext
	*/
	OkamotoUchiyama::Ciphertext OkamotoUchiyama::EncryptIntegerNonrandom (const BigInteger &plaintext) const {
		/**
		* @f$ c = G^m H^r \pmod n @f$, where @f$ r \in \mathbb{Z}_n @f$
		*
		* The computation is performed in two steps:
		* - encrypt data
		* - randomize ciphertext
		*/

		Ciphertext output(this->encryptionModulus);

		/// Compute @f$ c = G^m \pmod n @f$

		/// If @f$ plaintext < 0 @f$, we remap it to the second half of the message space
		if (plaintext < 0) {
			if (this->hasPrivateKey) {
				output.data = this->publicKey.G.GetPowModN(this->GetMessageSpaceUpperBound() + plaintext, this->GetEncryptionModulus());
			}
			/**
			If the private key is not available, we remap the message by computing the inverse of the ciphertext modulo @f$ n @f$ (which is equivalent to a homomorphic multiplication with @f$ -1 @f$).
			Note that this operation is slower than remapping the value in plain text.
			*/
			else {
				output.data = this->publicKey.G.GetPowModN(plaintext.GetAbs(), this->GetEncryptionModulus()).GetInverseModN(this->GetEncryptionModulus());
			}
		}
		else {
			output.data = this->publicKey.G.GetPowModN(plaintext, this->GetEncryptionModulus());
		}

		return output;
	}

	/**
	Generates a random number @f$ r \in \mathbb{Z}_n^* @f$ and computes @f$ r^n \pmod {n^2} @f$.

	Computes @f$ H^r \pmod n @f$.

	@return the random factor
	*/
	OkamotoUchiyama::Randomizer OkamotoUchiyama::GetRandomizer () const {
		return Randomizer(this->publicKey.H.GetPowModN((RandomProvider::GetInstance().GetRandomInteger(this->publicKey.n - 1) + 1), this->publicKey.n));
	}

	/**
	Computes @f$ c = c H^r \pmod n @f$

	@param ciphertext the ciphertext integer
	@return The randomized ciphertext
	*/
	OkamotoUchiyama::Ciphertext OkamotoUchiyama::RandomizeCiphertext (const OkamotoUchiyama::Ciphertext &ciphertext) const {
		return Ciphertext((ciphertext.data * this->randomizerCache->Pop().randomizer.data) % this->GetEncryptionModulus(), this->encryptionModulus);
	}

	/**
	@return @f$ n @f$
	*/
	const BigInteger &OkamotoUchiyama::GetMessageSpaceUpperBound () const {
		return this->messageSpace;
	}

	/**
	@return The message space bit size.
	*/
	size_t OkamotoUchiyama::GetMessageSpaceSize () const {
		return this->messageSpaceSize;
	}

	/**
	Computes @f$ L(u) = \frac{u - 1}{n} @f$
	@param input the function variable
	@return L(input)
	*/
	BigInteger OkamotoUchiyama::L (const BigInteger &input) const {
		BigInteger output;

		output = (input - 1) / this->privateKey.p;

		return output;
	}

	/**
	Precomputes the message space delimiter between positive and negative values.

	Precomputes [0] and [1].
	*/
	void OkamotoUchiyama::doPrecomputations () {
		if (this->precomputeSpeedupValues) {
			/// Decryption spedup: Precompute @f$ p^2 @f$
			this->pSquared = this->privateKey.p.GetPow(2);
		}

		if (this->hasPrivateKey) {
			this->messageSpace = this->privateKey.p;
			this->messageSpaceSize = this->privateKey.p.GetSize();

			/// Decryption spedup: Precompute @f$ L(g_p)^{-1} \pmod p @f$
			this->lgpInv = this->L(this->privateKey.gp).GetInverseModN(this->privateKey.p);
		}
		/**
		If the private key is not available, then we threshold the message space with a number smaller than @f$ p @f$.
		Basically, this will create a gap of unused values in the middle of the @f$ [0, p) @f$ interval.
		Homomorphic operations will be possible between ciphertexts produced by cryptoProviders which have the private key and crypto providers which do not.
		*/
		else {
			this->messageSpace = BigInteger(2).GetPow(static_cast<unsigned long>(this->messageSpaceSize));
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