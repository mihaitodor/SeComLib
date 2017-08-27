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
@file core/secure_multiplication_blinding_factor_container.hpp
@brief Implementation of struct SecureMultiplicationBlindingFactorContainer.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SECURE_MULTIPLICATION_BLINDING_FACTOR_CONTAINER_IMPLEMENTATION_GUARD
#define SECURE_MULTIPLICATION_BLINDING_FACTOR_CONTAINER_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Core {
	/**
	Computes:
	- @f$ [-r_1] @f$
	- @f$ [-r_2] @f$
	- @f$ [-r_1 r_2] @f$

	@param cryptoProvider the crypto provider
	@param parameters configuration parameters
	*/
	template <typename T_CryptoProvider, typename T_Parameters>
	SecureMultiplicationBlindingFactorContainer<T_CryptoProvider, T_Parameters>::SecureMultiplicationBlindingFactorContainer (const T_CryptoProvider &cryptoProvider, const T_Parameters &parameters) {
		/// The size of the blinding factors is @f$ \kappa + l + 1 @f$
		this->r1 = RandomProvider::GetInstance().GetRandomInteger(parameters.l + 1 + parameters.kappa);
		this->r2 = RandomProvider::GetInstance().GetRandomInteger(parameters.l + 1 + parameters.kappa);
		this->encryptedMinusR1 = cryptoProvider.EncryptInteger(-this->r1);
		this->encryptedMinusR2 = cryptoProvider.EncryptInteger(-this->r2);
		this->encryptedMinusR1R2 = cryptoProvider.EncryptInteger(-this->r1 * this->r2);
	}

}//namespace Core
}//namespace SeComLib

#endif//SECURE_MULTIPLICATION_BLINDING_FACTOR_CONTAINER_IMPLEMENTATION_GUARD