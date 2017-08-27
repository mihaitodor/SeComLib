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
@file core/crypto_provider.hpp
@brief Implementation of template abstract class CryptoProvider. To be included in crypto_provider.h
@details CryptoProvider is the base class for public-key cryptographic primitives
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef CRYPTO_PROVIDER_IMPLEMENTATION_GUARD
#define CRYPTO_PROVIDER_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Core {
	/**
	@param keyLength the key length in bits
	*/
	template <typename T_PublicKey, typename T_PrivateKey, typename T_Ciphertext, typename T_Randomizer>
	CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext, T_Randomizer>::CryptoProvider (const unsigned int keyLength) :
		keyLength(keyLength), hasPrivateKey(true), precomputeSpeedupValues(false) {
	}

	/**
	Sets the public key to enable homomorphic operations and encryption.

	@param publicKey a T_PublicKey structure
	@param keyLength the key length in bits
	*/
	template <typename T_PublicKey, typename T_PrivateKey, typename T_Ciphertext, typename T_Randomizer>
	CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext, T_Randomizer>::CryptoProvider (const T_PublicKey &publicKey, const unsigned int keyLength) :
		publicKey(publicKey), keyLength(keyLength), hasPrivateKey(false), precomputeSpeedupValues(true) {
	}

	/**
	Sets the public and private keys to enable homomorphic operations, encryption and decryption

	@param publicKey a T_PublicKey structure
	@param privateKey a T_PrivateKey structure
	@param keyLength the key length in bits
	*/
	template <typename T_PublicKey, typename T_PrivateKey, typename T_Ciphertext, typename T_Randomizer>
	CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext, T_Randomizer>::CryptoProvider (const T_PublicKey &publicKey, const T_PrivateKey &privateKey, const unsigned int keyLength) :
		publicKey(publicKey), privateKey(privateKey), keyLength(keyLength), hasPrivateKey(true), precomputeSpeedupValues(true) {
	}

	/**
	@param plaintext the plaintext integer
	@return Randomized ciphertext
	*/
	template <typename T_PublicKey, typename T_PrivateKey, typename T_Ciphertext, typename T_Randomizer>
	T_Ciphertext CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext, T_Randomizer>::EncryptInteger (const BigInteger &plaintext) const {
		return this->RandomizeCiphertext(this->EncryptIntegerNonrandom(plaintext));
	}

#ifdef ENABLE_CRYPTO_PROVIDER_HOMOMORPHIC_OPERATIONS
	/**
	Computes @f$ [lhs + rhs] = [lhs] [rhs] \pmod n @f$
	@param lhs left hand side encrypted operand
	@param rhs right hand side encrypted operand
	@return A new instance containing @f$ [lhs + rhs] @f$
	*/
	template <typename T_PublicKey, typename T_PrivateKey, typename T_Ciphertext, typename T_Randomizer>
	T_Ciphertext CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext, T_Randomizer>::HomomorphicAdd (const T_Ciphertext &lhs, const T_Ciphertext &rhs) const {
		return (lhs * rhs) % this->GetEncryptionModulus();
	}

	/**
	Computes @f$ [-input] = [input]^{-1} \pmod n @f$
	@param input an encrypted value
	@return A new instance containing @f$ [-input] @f$
	*/
	template <typename T_PublicKey, typename T_PrivateKey, typename T_Ciphertext, typename T_Randomizer>
	T_Ciphertext CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext, T_Randomizer>::GetHomomorphicInverse (const T_Ciphertext &input) const {
		return input.GetInverseModN(this->GetEncryptionModulus());
	}

	/**
	Computes @f$ [lhs - rhs] = [lhs] [rhs]^{-1} \pmod n @f$
	@param lhs left hand side encrypted operand
	@param rhs right hand side encrypted operand
	@return A new instance containing @f$ [lhs - rhs] @f$
	*/
	template <typename T_PublicKey, typename T_PrivateKey, typename T_Ciphertext, typename T_Randomizer>
	T_Ciphertext CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext, T_Randomizer>::HomomorphicSubtract (const T_Ciphertext &lhs, const T_Ciphertext &rhs) const {
		return (lhs * rhs.GetInverseModN(this->GetEncryptionModulus())) % this->GetEncryptionModulus();
	}

	/**
	Computes @f$ [lhs * rhs] = [lhs]^rhs \pmod n @f$.

	@param lhs left hand side encrypted operand
	@param rhs right hand side plaintext operand
	@return A new instance containing @f$ [lhs * rhs] @f$
	*/
	template <typename T_PublicKey, typename T_PrivateKey, typename T_Ciphertext, typename T_Randomizer>
	T_Ciphertext CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext, T_Randomizer>::HomomorphicMultiply (const T_Ciphertext &lhs, const BigInteger &rhs) const {
		if (rhs == 0) {
			throw std::runtime_error("The plaintext term should not be 0.");
		}

		return lhs.GetPowModN(rhs, this->GetEncryptionModulus());
	}
#endif

	/**
	@return a read-only reference to the encryption modulus
	*/
	template <typename T_PublicKey, typename T_PrivateKey, typename T_Ciphertext, typename T_Randomizer>
	const BigInteger &CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext, T_Randomizer>::GetEncryptionModulus () const {
		return *this->encryptionModulus;
	}

	/**
	@return a read-only reference to the positive/negative boundary
	*/
	template <typename T_PublicKey, typename T_PrivateKey, typename T_Ciphertext, typename T_Randomizer>
	const BigInteger &CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext, T_Randomizer>::GetPositiveNegativeBoundary () const {
		return this->positiveNegativeBoundary;
	}

	/**
	@return a read-only reference to the public key
	*/
	template <typename T_PublicKey, typename T_PrivateKey, typename T_Ciphertext, typename T_Randomizer>
	const T_PublicKey &CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext, T_Randomizer>::GetPublicKey () const {
		return this->publicKey;
	}

	/**
	@return a read-only reference to the private key
	*/
	template <typename T_PublicKey, typename T_PrivateKey, typename T_Ciphertext, typename T_Randomizer>
	const T_PrivateKey &CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext, T_Randomizer>::GetPrivateKey () const {
		return this->privateKey;
	}

	/**
	@param randomized if true, the encryption will be randomized (defaults to true)
	@return Re-randomized [0]
	*/
	template <typename T_PublicKey, typename T_PrivateKey, typename T_Ciphertext, typename T_Randomizer>
	T_Ciphertext CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext, T_Randomizer>::GetEncryptedZero (const bool randomized) const {
		if (randomized) {
			return this->RandomizeCiphertext(this->encryptedZero);
		}
		else {
			return this->encryptedZero;
		}
	}

	/**
	@param randomized if true, the encryption will be randomized (defaults to true)
	@return Re-randomized [1]
	*/
	template <typename T_PublicKey, typename T_PrivateKey, typename T_Ciphertext, typename T_Randomizer>
	T_Ciphertext CryptoProvider<T_PublicKey, T_PrivateKey, T_Ciphertext, T_Randomizer>::GetEncryptedOne (const bool randomized) const {
		if (randomized) {
			return this->RandomizeCiphertext(this->encryptedOne);
		}
		else {
			return this->encryptedOne;
		}

	}
}//namespace Core
}//namespace SeComLib

#endif//CRYPTO_PROVIDER_IMPLEMENTATION_GUARD