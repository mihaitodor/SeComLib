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
@file core/crypto_provider.h
@brief Definition of template abstract class CryptoProvider.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef CRYPTO_PROVIDER_HEADER_GUARD
#define CRYPTO_PROVIDER_HEADER_GUARD

#include "big_integer.h"
#include "ciphertext_base.h"
#include "randomizer_cache_parameters.h"
#include "randomizer_container.h"
#include "randomizer_base.h"
#include "randomizer_cache.h"

//include C++ headers
#include <memory>
#include <stdexcept>

namespace SeComLib {
namespace Core {
	//uncomment this to enable homomorphic operations on ciphertexts via crypto providers
	//#define ENABLE_CRYPTO_PROVIDER_HOMOMORPHIC_OPERATIONS

	/**
	@brief Template abstract base class for homomorphic encryption primitives

	@tparam T_PublicKey The type of the public key container
	@tparam T_PrivateKey The type of the private key container
	@tparam T_Ciphertext The type of the ciphertext
	@tparam T_Randomizer The type of the randomizer
	*/
	template <typename T_PublicKey, typename T_PrivateKey, typename T_Ciphertext, typename T_Randomizer>
	class CryptoProvider {
	public:
		/// Provide public access to the T_Ciphertext type
		typedef T_Ciphertext Ciphertext;

		/// Provide public access to the T_Randomizer type
		typedef T_Randomizer Randomizer;

		/// Constructor
		CryptoProvider (const unsigned int keyLength);

		/// Constructor
		CryptoProvider (const T_PublicKey &publicKey, const unsigned int keyLength);

		/// Constructor
		CryptoProvider (const T_PublicKey &publicKey, const T_PrivateKey &privateKey, const unsigned int keyLength);

		/// Destructor
		virtual ~CryptoProvider () {}

		/// Generate the public and private keys required by the encryption primitive
		virtual bool GenerateKeys () = 0;

		/// Encrypt an integer and apply randomization
		virtual T_Ciphertext EncryptInteger (const BigInteger &plaintext) const;

		/// Decrypt an integer
		virtual BigInteger DecryptInteger (const T_Ciphertext &ciphertext) const = 0;

		/// Encrypt number without randomization
		virtual T_Ciphertext EncryptIntegerNonrandom (const BigInteger &plaintext) const = 0;

		/// Compute the random factor required for the encryption operation
		virtual T_Randomizer GetRandomizer () const = 0;

		/// Randomize encrypted number with a self-generated random value
		virtual T_Ciphertext RandomizeCiphertext (const T_Ciphertext &ciphertext) const = 0;
		
	#ifdef ENABLE_CRYPTO_PROVIDER_HOMOMORPHIC_OPERATIONS
		/// Compute the homomorphic addition of two encrypted values
		T_Ciphertext HomomorphicAdd (const T_Ciphertext &lhs, const T_Ciphertext &rhs) const;

		/// Compute the additive inverse of the encrypted input
		T_Ciphertext GetHomomorphicInverse (const T_Ciphertext &input) const;

		/// Compute the homomorphic subtraction of two encrypted values
		T_Ciphertext HomomorphicSubtract (const T_Ciphertext &lhs, const T_Ciphertext &rhs) const;

		/// Compute the homomorphic multiplication of a ciphertext and a plaintext value
		T_Ciphertext HomomorphicMultiply (const T_Ciphertext &lhs, const BigInteger &rhs) const;
	#endif

		/// Returns the modulus required for reducing the encryption after randomization
		const BigInteger &GetEncryptionModulus () const;

		/// Returns the message space upper bound
		virtual const BigInteger &GetMessageSpaceUpperBound () const = 0;

		/// Returns the biggest positive number that can be encrypted without overflowing
		virtual const BigInteger &GetPositiveNegativeBoundary () const;

		/// Returns the message space bit size
		virtual size_t GetMessageSpaceSize () const = 0;

		/// Public key getter
		const T_PublicKey &GetPublicKey () const;

		/// Private key getter
		const T_PrivateKey &GetPrivateKey () const;

		/// Returns [0]
		Ciphertext GetEncryptedZero (const bool randomized = true) const;

		/// Returns [1]
		Ciphertext GetEncryptedOne (const bool randomized = true) const;
		
	protected:
		/// Data type of the randomizer cache
		typedef RandomizerCache<RandomizerContainer<CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext, T_Randomizer>, RandomizerCacheParameters>> RandomizerCacheType;

		/// Lazy loading randomizer cache
		std::unique_ptr<RandomizerCacheType> randomizerCache;

		/// Public key container
		T_PublicKey publicKey;

		/// Private key container
		T_PrivateKey privateKey;

		/// The key length in bits
		unsigned int keyLength;

		/// The encryption modulus
		std::shared_ptr<BigInteger> encryptionModulus;

		/// Contains the delimiter between positive and negative values in the message space (usually @f$ \lfloor messagespace / 2 \rfloor @f$)
		BigInteger positiveNegativeBoundary;

		/// Boolean flag that enables decryption if the private key is present
		bool hasPrivateKey;

		/// Boolean flag that indicates wether doPrecomputations() should precompute certain values
		bool precomputeSpeedupValues;

		/// Contains [0] used as initializer for homomorphic addition accumulators. Precompute it for optimization purposes
		T_Ciphertext encryptedZero;

		/// Contains [1]
		T_Ciphertext encryptedOne;

		/// Validates configuration parameters
		virtual void validateParameters () = 0;

		/// Computes the required precomputed values
		virtual void doPrecomputations () = 0;

	private:
		/// Copy constructor - not implemented
		//CryptoProvider (const CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext> &);//need C++11 delete to disable this

		/// Copy assignment operator - not implemented
		//CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext> operator= (const CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext> &);//need C++11 delete to disable this
	};
}//namespace Core
}//namespace SeComLib

//Separate the implementation from the declaration
#include "crypto_provider.hpp"

#endif//CRYPTO_PROVIDER_HEADER_GUARD