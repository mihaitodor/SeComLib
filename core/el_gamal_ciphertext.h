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
@file core/el_gamal_ciphertext.h
@brief Definition of class ElGamalCiphertext.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef EL_GAMAL_CIPHERTEXT_HEADER_GUARD
#define EL_GAMAL_CIPHERTEXT_HEADER_GUARD

#include "big_integer.h"

//include C++ headers
#include <memory>
#include <stdexcept>

namespace SeComLib {
namespace Core {
	/**
	@brief ElGamal cipertext
	*/
	class ElGamalCiphertext {
	public:
		/**
		@brief ElGamal cipertext container structure
		*/
		struct Data {
		public:
			/// @f$ g^{\alpha} @f$
			BigInteger x;

			/// @f$ h^{\alpha} g^m @f$
			BigInteger y;

			/// Default constructor
			Data ();

			/// Constructor with member initialization
			Data (const BigInteger &x, const BigInteger &y);
		};

		/// Cipertext container
		Data data;

		/// Default constructor
		ElGamalCiphertext ();

		/// Constructor with encryption modulus initialization
		ElGamalCiphertext (const std::shared_ptr<BigInteger> &encryptionModulus);

		/// Constructor with data and encryption modulus initialization
		ElGamalCiphertext (const BigInteger &x, const BigInteger &y, const std::shared_ptr<BigInteger> &encryptionModulus);

		/// Homomorphic negation unary operator
		ElGamalCiphertext operator- () const;

		/// Homomorphic addition binary operator
		ElGamalCiphertext operator+ (const ElGamalCiphertext &input) const;

		/// Homomorphic subtraction binary operator
		ElGamalCiphertext operator- (const ElGamalCiphertext &input) const;

		/// Homomorphic multiplication binary operator
		template <typename T_DataType>
		ElGamalCiphertext operator* (const T_DataType &input) const;

	private:
		/// The encryption modulus
		std::shared_ptr<BigInteger> encryptionModulus;
	};

}//namespace Core
}//namespace SeComLib

//Separate the implementation from the declaration
#include "el_gamal_ciphertext.hpp"

#endif//EL_GAMAL_CIPHERTEXT_HEADER_GUARD