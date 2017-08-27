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
@file core/el_gamal.h
@brief Definition of class ElGamal.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef EL_GAMAL_HEADER_GUARD
#define EL_GAMAL_HEADER_GUARD

#include "big_integer.h"
#include "random_provider.h"
#include "crypto_provider.h"
#include "utils/config.h"
#include "el_gamal_ciphertext.h"

//include C++ headers
#include <map>
#include <stdexcept>

namespace SeComLib {
namespace Core {
	/**
	@brief The public key container structure for the ElGamal cryptosystem
	*/
	struct ElGamalPublicKey {
	public:
		/// @f$ p @f$
		BigInteger p;
		/// @f$ q @f$
		BigInteger q;
		/// @f$ g_q @f$
		BigInteger gq;
		/// @f$ h @f$
		BigInteger h;
	};

	/**
	@brief The private key container structure for the ElGamal cryptosystem
	*/
	struct ElGamalPrivateKey {
	public:
		/// @f$ s @f$
		BigInteger s;
	};

	/**
	@brief The randomizer type for Paillier
	*/
	struct ElGamalRandomizer {
		/// @f$ g_q^r \pmod p @f$
		BigInteger x;

		/// @f$  h^r \pmod p @f$
		BigInteger y;

		/// Default constructor
		ElGamalRandomizer ();

		/// Constructor with initialization
		ElGamalRandomizer (const BigInteger &x, const BigInteger &y);
	};

	/**
	@brief Implementation of the public-key ElGamal Cryptosystem
	*/
	class ElGamal : public CryptoProvider<ElGamalPublicKey, ElGamalPrivateKey, ElGamalCiphertext, ElGamalRandomizer> {
	public:
		/// Default constructor
		ElGamal (const bool precomputeDecryptionMap = false);

		/// Creates an instance of the class for homomorphic operations and ecryption
		ElGamal (const ElGamalPublicKey &publicKey);

		/// Creates an instance of the class for homomorphic operations, ecryption and decryption
		ElGamal (const ElGamalPublicKey &publicKey, const ElGamalPrivateKey &privateKey, const bool precomputeDecryptionMap = false);

		/// Destructor
		~ElGamal () {}

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

	#ifdef ENABLE_CRYPTO_PROVIDER_HOMOMORPHIC_OPERATIONS
		/// Compute the homomorphic addition of two encrypted values
		Ciphertext HomomorphicAdd (const Ciphertext &lhs, const Ciphertext &rhs) const;

		/// Compute the additive inverse of the encrypted input
		Ciphertext GetHomomorphicInverse (const Ciphertext &input) const;

		/// Compute the homomorphic subtraction of two encrypted values
		Ciphertext HomomorphicSubtract (const Ciphertext &lhs, const Ciphertext &rhs) const;

		/// Compute the homomorphic multiplication of a ciphertext and a plaintext value
		Ciphertext HomomorphicMultiply (const Ciphertext &lhs, const BigInteger &rhs) const;
	#endif

		/// Returns the message space upper bound
		virtual const BigInteger &GetMessageSpaceUpperBound () const;

		/// Returns the message space bit size
		virtual size_t GetMessageSpaceSize () const;

		/* /Base class methods */

		/// Determines if ciphertext contains an encryption of 0 or not
		bool IsEncryptedZero (const Ciphertext &ciphertext) const;

	private:
		/// std::map template specialization
		typedef std::map<const BigInteger, BigInteger> DecryptionMap;

		/// @f$ m \in \mathbb{Z}_q \ (2^t, \lfloor q / 2 \rfloor + 2^t) @f$
		BigInteger messageSpaceThreshold;

		/// A generator of @f$ Z_{p}^* @f$
		BigInteger g;

		/// If true, full decryptions are enabled and the decryption map is (pre)computed
		bool precomputeDecryptionMap;

		/// Contains all possible values of @f$ g_q^m \pmod p @f$, where @f$ m \in \mathbb{Z}_q @f$, and it is required for decryption.
		DecryptionMap decryptionMap;

		/* Base class methods */

		/// Do nothing for now
		virtual void validateParameters () {}

		/// Precompute values for speedups
		virtual void doPrecomputations ();

		/* /Base class methods */

		/// Copy constructor - not implemented
		ElGamal (const ElGamal &);

		/// Copy assignment operator - not implemented
		ElGamal operator= (const ElGamal &);
	};
}//namespace Core
}//namespace SeComLib

#endif//EL_GAMAL_HEADER_GUARD