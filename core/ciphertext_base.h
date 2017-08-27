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
@file core/ciphertext_base.h
@brief Definition of template class CiphertextBase.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef CIPHERTEXT_BASE_HEADER_GUARD
#define CIPHERTEXT_BASE_HEADER_GUARD

#include "big_integer.h"

//include C++ headers
#include <memory>
#include <stdexcept>

namespace SeComLib {
namespace Core {
	/**
	@brief CiphertextBase template class
	@tparam T_CiphertextImpl The ciphertext implementation, derived from this class (via CRTP)
	*/
	template <typename T_CiphertextImpl>
	class CiphertextBase {
	public:
		/// The ciphertext data
		BigInteger data;

		/// Default constructor
		CiphertextBase ();

		/// Constructor with encryption modulus initialization
		CiphertextBase (const std::shared_ptr<BigInteger> &encryptionModulus);

		/// Constructor with data and encryption modulus initialization
		CiphertextBase (const BigInteger &data, const std::shared_ptr<BigInteger> &encryptionModulus);

		/// Homomorphic negation unary operator
		T_CiphertextImpl operator- () const;

		/// Homomorphic addition binary operator
		T_CiphertextImpl operator+ (const T_CiphertextImpl &input) const;

		/// Homomorphic subtraction binary operator
		T_CiphertextImpl operator- (const T_CiphertextImpl &input) const;

		/// Homomorphic multiplication binary operator
		template <typename T_DataType>
		T_CiphertextImpl operator* (const T_DataType &input) const;

	private:
		/// The encryption modulus
		std::shared_ptr<BigInteger> encryptionModulus;
	};
}//namespace Core
}//namespace SeComLib

//Separate the implementation from the declaration
#include "ciphertext_base.hpp"

#endif//CIPHERTEXT_BASE_HEADER_GUARD