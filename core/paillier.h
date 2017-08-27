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
@file core/paillier.h
@brief Definition of class Paillier.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef PAILLIER_HEADER_GUARD
#define PAILLIER_HEADER_GUARD

#include "big_integer.h"
#include "random_provider.h"
#include "ciphertext_base.h"
#include "crypto_provider.h"
#include "utils/config.h"

//include C++ headers
#include <stdexcept>

namespace SeComLib {
namespace Core {
	//uncomment this to use the standard version of the Paillier key generation and encryption algorithms
	//#define USE_STANDARD_PAILLIER_ALGORITHM

	/**
	@brief The public key container structure for the Paillier cryptosystem
	*/
	struct PaillierPublicKey {
	public:
		/// @f$ n @f$
		BigInteger n;
		/// @f$ g @f$
		BigInteger g;
	};

	/**
	@brief The private key container structure for the Paillier cryptosystem
	*/
	struct PaillierPrivateKey {
	public:
		/// @f$ p @f$
		BigInteger p;//required if decrypting using CRT
		/// @f$ q @f$
		BigInteger q;//required if decrypting using CRT
	#ifdef USE_STANDARD_PAILLIER_ALGORITHM
		/// @f$ \lambda @f$
		BigInteger lambda;
		/// @f$ \mu @f$
		BigInteger mu;
	#endif
	};

	/**
	@brief Paillier cipertext
	*/
	class PaillierCiphertext : public CiphertextBase<PaillierCiphertext> {
	public:
		/// Default constructor
		PaillierCiphertext ();

		/// Constructor with encryption modulus initialization
		PaillierCiphertext (const std::shared_ptr<BigInteger> &encryptionModulus);

		/// Constructor with data and encryption modulus initialization
		PaillierCiphertext (const BigInteger &data, const std::shared_ptr<BigInteger> &encryptionModulus);
	};

	/**
	@brief The randomizer type for Paillier
	*/
	struct PaillierRandomizer : public RandomizerBase {
		/// Default constructor
		PaillierRandomizer ();

		/// Constructor with initialization
		PaillierRandomizer (const BigInteger &data);
	};

	/**
	@brief Implementation of the public-key Paillier Cryptosystem
	*/
	class Paillier : public CryptoProvider<PaillierPublicKey, PaillierPrivateKey, PaillierCiphertext, PaillierRandomizer> {
	public:
		/// Default constructor
		Paillier ();

		/// Creates an instance of the class for homomorphic operations and ecryption
		Paillier (const PaillierPublicKey &publicKey);

		/// Creates an instance of the class for homomorphic operations, ecryption and decryption
		Paillier (const PaillierPublicKey &publicKey, const PaillierPrivateKey &privateKey);

		/// Destructor
		~Paillier () {}

		/* Base class methods */

		/// Generate the public and private keys
		/// @todo Implement a non-heuristic algorithm for insuring that @f$ n @f$ always has the specified length
		virtual bool GenerateKeys ();

		/// Decrypt number
		virtual BigInteger DecryptInteger (const Ciphertext &ciphertext) const;

		/// Encrypt number without randomization
		virtual Ciphertext EncryptIntegerNonrandom (const BigInteger &plaintext) const;

		/// Compute the random factor required for the encryption operation
		virtual Randomizer GetRandomizer () const;

		/// Randomize encrypted number with a self-generated random value
		virtual Ciphertext RandomizeCiphertext (const Ciphertext &ciphertext) const;

		/// Returns the message space upper bound
		virtual const BigInteger &GetMessageSpaceUpperBound () const;

		/// Returns the message space bit size
		virtual size_t GetMessageSpaceSize () const;

		/* /Base class methods */

	private:
		/// @f$ p - 1 @f$
		BigInteger pMinusOne;

		/// @f$ q - 1 @f$
		BigInteger qMinusOne;

		/// Contains @f$ n - 1 @f$
		BigInteger nMinusOne;

		/// @f$ p^2 @f$
		BigInteger pSquared;

		/// @f$ q^2 @f$
		BigInteger qSquared;

		/// Contains @f$ n^2 @f$
		BigInteger nSquared;

		/// @f$ p (p^{-1} \pmod q) @f$
		BigInteger pTimesPInvModQ;

		/// @f$ q (q^{-1} \pmod p) @f$
		BigInteger qTimesQInvModP;

		/// @f$ L_p(g^{p - 1} (\pmod p^2))^{-1} \pmod p @f$
		BigInteger hp;

		/// @f$ L_q(g^{q - 1} (\pmod q^2))^{-1} \pmod q @f$
		BigInteger hq;

		/// L function evaluator
		BigInteger L (const BigInteger &input, const BigInteger &d) const;

		/* Base class methods */

		/// Do nothing for now
		virtual void validateParameters () {}

		/// Precompute values for speedups
		virtual void doPrecomputations ();

		/* /Base class methods */

		/// Copy constructor - not implemented
		Paillier (const Paillier &);

		/// Copy assignment operator - not implemented
		Paillier operator= (const Paillier &);
	};
}//namespace Core
}//namespace SeComLib

#endif//PAILLIER_HEADER_GUARD