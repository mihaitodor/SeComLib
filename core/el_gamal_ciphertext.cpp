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
@file core/el_gamal_ciphertext.cpp
@brief Implementation of class ElGamalCiphertext.
@details Implementation of overloaded operators for homomorphic operations.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "el_gamal_ciphertext.h"

namespace SeComLib {
namespace Core {
	/**
	Initializes @f$ x @f$ and @f$ y @f$ with @f$ 0 @f$
	*/
	ElGamalCiphertext::Data::Data () {
	}

	/**
	@param x @f$ x @f$ value
	@param y @f$ y @f$ value
	*/
	ElGamalCiphertext::Data::Data (const BigInteger &x, const BigInteger &y) : x(x), y(y) {
	}

	/**
	Does not initialize the encryptionModulus.
	*/
	ElGamalCiphertext::ElGamalCiphertext () {
	}

	/**
	Initializes the encryptionModulus 
	@param encryptionModulus The encryption modulus
	*/
	ElGamalCiphertext::ElGamalCiphertext (const std::shared_ptr<BigInteger> &encryptionModulus) : encryptionModulus(encryptionModulus) {
	}

	/**
	Initializes the data and the encryptionModulus
	@param x @f$ x @f$ value
	@param y @f$ y @f$ value
	@param encryptionModulus The encryption modulus
	*/
	ElGamalCiphertext::ElGamalCiphertext (const BigInteger &x, const BigInteger &y, const std::shared_ptr<BigInteger> &encryptionModulus) : data(Data(x, y)), encryptionModulus(encryptionModulus) {
	}

	/**
	Computes @f$ [-this] = [this]^{-1} \pmod n = (x_{this}^{-1} \pmod n, y_{this}^{-1} \pmod n) @f$
	@return A new instance containing @f$ [-this] @f$
	*/
	ElGamalCiphertext ElGamalCiphertext::operator- () const {
		if (!this->encryptionModulus) {
			throw std::runtime_error("This operation requires the encryption modulus.");
		}

		ElGamalCiphertext output(this->data.x.GetInverseModN(*this->encryptionModulus), this->data.y.GetInverseModN(*this->encryptionModulus), this->encryptionModulus);

		return output;
	}

	/**
	Computes @f$ [this + input] = [this] [input] \pmod n = (x_{this} x_{input} \pmod n, y_{this} y_{input} \pmod n) @f$
	@param input encrypted input
	@return A new instance containing @f$ [this + input] @f$
	*/
	ElGamalCiphertext ElGamalCiphertext::operator+ (const ElGamalCiphertext &input) const {
		if (!this->encryptionModulus) {
			throw std::runtime_error("This operation requires the encryption modulus.");
		}

		ElGamalCiphertext output((this->data.x * input.data.x) % (*this->encryptionModulus), (this->data.y * input.data.y) % (*this->encryptionModulus), this->encryptionModulus);

		return output;
	}

	/**
	Computes @f$ [this - input] = [this] [input]^{-1} \pmod n = (x_{this} x_{input}^{-1} \pmod n, y_{this} y_{input}^{-1} \pmod n) @f$
	@param input encrypted input
	@return A new instance containing @f$ [this - input] @f$
	*/
	ElGamalCiphertext ElGamalCiphertext::operator- (const ElGamalCiphertext &input) const {
		if (!this->encryptionModulus) {
			throw std::runtime_error("This operation requires the encryption modulus.");
		}

		ElGamalCiphertext output((this->data.x * input.data.x.GetInverseModN(*this->encryptionModulus)) % (*this->encryptionModulus), (this->data.y * input.data.y.GetInverseModN(*this->encryptionModulus)) % (*this->encryptionModulus), this->encryptionModulus);

		return output;
	}
}//namespace Core
}//namespace SeComLib