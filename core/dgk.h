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
@file core/dgk.h
@brief Definition of class Dgk.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef DGK_HEADER_GUARD
#define DGK_HEADER_GUARD

#include "big_integer.h"
#include "ciphertext_base.h"
#include "crypto_provider.h"
#include "random_provider.h"
#include "utils/config.h"

//include C++ headers
#include <stdexcept>
#include <map>

namespace SeComLib {
namespace Core {
	/**
	@brief The public key container structure for the Dgk cryptosystem
	*/
	struct DgkPublicKey {
	public:
		/// @f$ n @f$
		BigInteger n;
		/// @f$ g @f$
		BigInteger g;
		/// @f$ h @f$
		BigInteger h;
		/// @f$ u @f$ - The message space upper bound
		BigInteger u;
	};

	/**
	@brief The private key container structure for the Dgk cryptosystem
	*/
	struct DgkPrivateKey {
	public:
		/// @f$ p @f$
		BigInteger p;
		/// @f$ q @f$
		BigInteger q;
		/// @f$ v_p @f$
		BigInteger vp;
		/// @f$ v_q @f$
		BigInteger vq;
	};

	/**
	@brief DGK cipertext
	*/
	class DgkCiphertext : public CiphertextBase<DgkCiphertext> {
	public:
		/// Default constructor
		DgkCiphertext ();

		/// Constructor with encryption modulus initialization
		DgkCiphertext (const std::shared_ptr<BigInteger> &encryptionModulus);

		/// Constructor with data and encryption modulus initialization
		DgkCiphertext (const BigInteger &data, const std::shared_ptr<BigInteger> &encryptionModulus);
	};

	/**
	@brief The randomizer type for DGK
	*/
	struct DgkRandomizer : public RandomizerBase {
		/// Default constructor
		DgkRandomizer ();

		/// Constructor with initialization
		DgkRandomizer (const BigInteger &data);
	};

	/**
	@brief Implementation of the public-key DGK Cryptosystem
	@todo Disable encryption speedups if we do not have the private key
	*/
	class Dgk : public CryptoProvider<DgkPublicKey, DgkPrivateKey, DgkCiphertext, DgkRandomizer> {
	public:
		/// Default constructor
		/// @todo Create a custom exception class for parameter validation.
		Dgk (const bool precomputeDecryptionMap = false);

		/// Creates an instance of the class for homomorphic operations and ecryption
		Dgk (const DgkPublicKey &publicKey);

		/// Creates an instance of the class for homomorphic operations, ecryption and decryption
		Dgk (const DgkPublicKey &publicKey, const DgkPrivateKey &privateKey, const bool precomputeDecryptionMap = false);

		/// Destructor
		~Dgk () {}

		/* Base class methods */

		/// Generate the public and private keys
		virtual bool GenerateKeys ();

		/// Decrypt number
		/// @todo Throw a custom exception!!!
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

		/// Determines if ciphertext contains an encryption of 0 or not
		bool IsEncryptedZero (const Ciphertext &ciphertext) const;

	private:
		/// std::map template specialization
		typedef std::map<const BigInteger, BigInteger> DecryptionMap;

		/// Parameter @f$ t @f$
		const unsigned int t;

		/// Parameter @f$ \ell @f$
		const unsigned int l;

		/// If true, full decryptions are enabled and the decryption map is (pre)computed
		bool precomputeDecryptionMap;

		/// Contains all possible values of @f$ (g^{v_p v_q})^m \pmod n @f$, where @f$ m \in \mathbb{Z}_u @f$, and it is required for decryption.
		DecryptionMap decryptionMap;

		/// Contains @f$ p (p^{-1} \pmod q) @f$
		BigInteger pTimesPInvModQ;
		/// Contains @f$ q (q^{-1} \pmod p) @f$
		BigInteger qTimesQInvModP;

		/* Base class methods */

		/// Validate configuration parameters
		virtual void validateParameters ();

		/// Precompute values for speedups
		virtual void doPrecomputations ();

		/* /Base class methods */

		/// Copy constructor - not implemented
		Dgk (const Dgk &);

		/// Copy assignment operator - not implemented
		Dgk operator= (const Dgk &);
	};
}//namespace Core
}//namespace SeComLib

#endif//DGK_HEADER_GUARD