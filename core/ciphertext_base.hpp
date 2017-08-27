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
@file core/ciphertext_base.hpp
@brief Implementation of template class CiphertextBase. To be included in ciphertext_base.h
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef CIPHERTEXT_BASE_IMPLEMENTATION_GUARD
#define CIPHERTEXT_BASE_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Core {
	/**
	Does not initialize the encryptionModulus.
	*/
	template <typename T_CiphertextImpl>
	CiphertextBase<T_CiphertextImpl>::CiphertextBase () {
	}

	/**
	Initializes the encryptionModulus
	@param encryptionModulus The encryption modulus
	*/
	template <typename T_CiphertextImpl>
	CiphertextBase<T_CiphertextImpl>::CiphertextBase (const std::shared_ptr<BigInteger> &encryptionModulus) : encryptionModulus(encryptionModulus) {
	}

	/**
	Initializes the data and the encryptionModulus
	@param data the ciphertext data
	@param encryptionModulus The encryption modulus
	*/
	template <typename T_CiphertextImpl>
	CiphertextBase<T_CiphertextImpl>::CiphertextBase (const BigInteger &data, const std::shared_ptr<BigInteger> &encryptionModulus) : data(data), encryptionModulus(encryptionModulus) {
	}

	/**
	Computes @f$ [-this] = [this]^{-1} \pmod n @f$
	@return A new instance containing @f$ [-this] @f$
	*/
	template <typename T_CiphertextImpl>
	T_CiphertextImpl CiphertextBase<T_CiphertextImpl>::operator- () const {
		if (!this->encryptionModulus) {
			throw std::runtime_error("This operation requires the encryption modulus.");
		}

		T_CiphertextImpl output(this->data.GetInverseModN(*this->encryptionModulus), this->encryptionModulus);

		return output;
	}

	/**
	Computes @f$ [this + input] = [this] [input] \pmod n @f$
	@param input encrypted input
	@return A new instance containing @f$ [this + input] @f$
	*/
	template <typename T_CiphertextImpl>
	T_CiphertextImpl CiphertextBase<T_CiphertextImpl>::operator+ (const T_CiphertextImpl &input) const {
		if (!this->encryptionModulus) {
			throw std::runtime_error("This operation requires the encryption modulus.");
		}

		T_CiphertextImpl output((this->data * input.data) % (*this->encryptionModulus), this->encryptionModulus);

		return output;
	}

	/**
	Computes @f$ [this - input] = [this] [input]^{-1} \pmod n @f$
	@param input encrypted input
	@return A new instance containing @f$ [this - input] @f$
	*/
	template <typename T_CiphertextImpl>
	T_CiphertextImpl CiphertextBase<T_CiphertextImpl>::operator- (const T_CiphertextImpl &input) const {
		if (!this->encryptionModulus) {
			throw std::runtime_error("This operation requires the encryption modulus.");
		}

		T_CiphertextImpl output((this->data * input.data.GetInverseModN(*this->encryptionModulus)) % (*this->encryptionModulus), this->encryptionModulus);

		return output;
	}

	/**
	
	*/
	/**
	Computes @f$ [this * input] = [this]^input \pmod n @f$.

	@param input plaintext input
	@tparam T_DataType Supported types: int, unsigned int, long, unsigned long, BigInteger
	@return A new instance containing @f$ [this * input] @f$
	*/
	template <typename T_CiphertextImpl>
	template <typename T_DataType>
	T_CiphertextImpl CiphertextBase<T_CiphertextImpl>::operator* (const T_DataType &input) const {
		if (!this->encryptionModulus) {
			throw std::runtime_error("This operation requires the encryption modulus.");
		}

		if (input == 0) {
			throw std::runtime_error("The plaintext term should not be 0.");
		}

		T_CiphertextImpl output(this->data.GetPowModN(input, *this->encryptionModulus), this->encryptionModulus);

		return output;
	}
}//namespace Core
}//namespace SeComLib

#endif//CIPHERTEXT_BASE_IMPLEMENTATION_GUARD