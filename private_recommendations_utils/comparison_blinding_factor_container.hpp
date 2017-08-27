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
@file private_recommendations_utils/comparison_blinding_factor_container.hpp
@brief Implementation of struct ComparisonBlindingFactorContainer.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef COMPARISON_BLINDING_FACTOR_CONTAINER_IMPLEMENTATION_GUARD
#define COMPARISON_BLINDING_FACTOR_CONTAINER_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace PrivateRecommendationsUtils {
	/**
	Computes:
	- @f$ r \pmod 2^l @f$
	- @f$ [r] @f$
	- @f$ [r \div 2^l] @f$

	@param cryptoProvider the crypto provider
	@param parameters configuration parameters
	*/
	template <typename T_CryptoProvider, typename T_Parameters>
	ComparisonBlindingFactorContainer<T_CryptoProvider, T_Parameters>::ComparisonBlindingFactorContainer (const T_CryptoProvider &cryptoProvider, const T_Parameters &parameters) {
		/// @f$ r \in_R \mathbb{N} @f$ of size @f$ l + 1 + \kappa @f$ bits
		this->r = RandomProvider::GetInstance().GetRandomInteger(parameters.l + 1 + parameters.kappa);

		this->rModTwoPowL = this->r % parameters.twoPowL;
		this->encryptedR = cryptoProvider.EncryptInteger(this->r);
		this->encryptedRDivTwoPowL = cryptoProvider.EncryptInteger(this->r / parameters.twoPowL);
	}

}//namespace PrivateRecommendationsUtils
}//namespace SeComLib

#endif//COMPARISON_BLINDING_FACTOR_CONTAINER_IMPLEMENTATION_GUARD