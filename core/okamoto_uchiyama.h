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
@file core/okamoto_uchiyama.h
@brief Definition of class OkamotoUchiyama.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef OKAMOTO_UCHIYAMA_HEADER_GUARD
#define OKAMOTO_UCHIYAMA_HEADER_GUARD

#include "big_integer.h"
#include "random_provider.h"
#include "ciphertext_base.h"
#include "crypto_provider.h"
#include "utils/config.h"

//include C++ headers
#include <stdexcept>

namespace SeComLib {
namespace Core {
	/**
	@brief The public key container structure for the Okamoto-Uchiyama cryptosystem
	*/
	struct OkamotoUchiyamaPublicKey {
	public:
		/// @f$ n @f$
		BigInteger n;
		/// @f$ G @f$
		BigInteger G;
		/// @f$ H @f$
		BigInteger H;
	};

	/**
	@brief The private key container structure for the Okamoto-Uchiyama cryptosystem
	*/
	struct OkamotoUchiyamaPrivateKey {
	public:
		/// @f$ p @f$
		BigInteger p;
		/// @f$ q @f$
		BigInteger q;
		/// @f$ g_p = g^{p - 1} \pmod p^2 @f$
		BigInteger gp;
		/// @f$ t @f$, the prime factor of @f$ p - 1 @f$
		BigInteger t;
	};

	/**
	@brief Okamoto-Uchiyama cipertext
	*/
	class OkamotoUchiyamaCiphertext : public CiphertextBase<OkamotoUchiyamaCiphertext> {
	public:
		/// Default constructor
		OkamotoUchiyamaCiphertext ();

		/// Constructor with encryption modulus initialization
		OkamotoUchiyamaCiphertext (const std::shared_ptr<BigInteger> &encryptionModulus);

		/// Constructor with data and encryption modulus initialization
		OkamotoUchiyamaCiphertext (const BigInteger &data, const std::shared_ptr<BigInteger> &encryptionModulus);
	};

	/**
	@brief The randomizer type for Okamoto-Uchiyama
	*/
	struct OkamotoUchiyamaRandomizer : public RandomizerBase {
		/// Default constructor
		OkamotoUchiyamaRandomizer ();

		/// Constructor with initialization
		OkamotoUchiyamaRandomizer (const BigInteger &data);
	};

	/**
	@brief Implementation of the public-key Okamoto-Uchiyama Cryptosystem
	*/
	class OkamotoUchiyama : public CryptoProvider<OkamotoUchiyamaPublicKey, OkamotoUchiyamaPrivateKey, OkamotoUchiyamaCiphertext, OkamotoUchiyamaRandomizer> {
	public:
		/// Default constructor
		/// @todo Throw an exception if the key generation procedure failed too many times.
		/// @todo Implement a non-heuristic algorithm for insuring that @f$ n @f$ always has the specified length
		OkamotoUchiyama ();

		/// Creates an instance of the class for homomorphic operations and ecryption
		OkamotoUchiyama (const OkamotoUchiyamaPublicKey &publicKey);

		/// Creates an instance of the class for homomorphic operations, ecryption and decryption
		OkamotoUchiyama (const OkamotoUchiyamaPublicKey &publicKey, const OkamotoUchiyamaPrivateKey &privateKey);

		/// Destructor
		~OkamotoUchiyama () {}

		/* Base class methods */

		/// Generate the public and private keys
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
		/// Contains @f$ p^2 @f$, required for the decryption operation. Precompute it for optimization purposes.
		BigInteger pSquared;

		/// The message space
		BigInteger messageSpace;

		/// Contains the bit size of the message space
		size_t messageSpaceSize;

		/// Stores @f$ g @f$, required for the decryption operation.
		BigInteger g;

		/// Stores precomputed value @f$ L(g_p)^{-1} \pmod p @f$ used to speedup decyption
		BigInteger lgpInv;

		/// L function evaluator
		BigInteger L (const BigInteger &input) const;

		/* Base class methods */

		/// Do nothing for now
		virtual void validateParameters () {}

		/// Precompute values for speedups
		virtual void doPrecomputations ();

		/* /Base class methods */

		/// Copy constructor - not implemented
		OkamotoUchiyama (const OkamotoUchiyama &);

		/// Copy assignment operator - not implemented
		OkamotoUchiyama operator= (const OkamotoUchiyama &);
	};
}//namespace Core
}//namespace SeComLib

#endif//OKAMOTO_UCHIYAMA_HEADER_GUARD