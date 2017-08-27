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
@file core/el_gamal_ciphertext.hpp
@brief Implementation of template methods from class ElGamalCiphertext. To be included in el_gamal_ciphertext.h
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef EL_GAMAL_CIPHERTEXT_IMPLEMENTATION_GUARD
#define EL_GAMAL_CIPHERTEXT_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Core {
	/**
	Computes @f$ [this * input] = [this]^input \pmod n = (x_{this}^input \pmod n, y_{this}^input \pmod n) @f$.

	@param input plaintext input
	@tparam T_DataType Supported types: int, unsigned int, long, unsigned long, BigInteger
	@return A new instance containing @f$ [this * input] @f$
	*/
	template <typename T_DataType>
	ElGamalCiphertext ElGamalCiphertext::operator* (const T_DataType &input) const {
		if (!this->encryptionModulus) {
			throw std::runtime_error("This operation requires the encryption modulus.");
		}

		if (input == 0) {
			throw std::runtime_error("The plaintext term should not be 0.");
		}

		ElGamalCiphertext output(this->data.x.GetPowModN(input, *this->encryptionModulus), this->data.y.GetPowModN(input, *this->encryptionModulus), this->encryptionModulus);

		return output;
	}
}//namespace Core
}//namespace SeComLib

#endif//EL_GAMAL_CIPHERTEXT_IMPLEMENTATION_GUARD