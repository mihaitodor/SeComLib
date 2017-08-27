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
@file private_recommendations_utils/decryption_blinding_factor_container.hpp
@brief Implementation of struct DecryptionBlindingFactorContainer.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef DECRYPTION_BLINDING_FACTOR_CONTAINER_IMPLEMENTATION_GUARD
#define DECRYPTION_BLINDING_FACTOR_CONTAINER_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace PrivateRecommendationsUtils {
	/**
	@param cryptoProvider the crypto provider
	@param parameters configuration parameters
	*/
	template <typename T_CryptoProvider, typename T_Parameters>
	DecryptionBlindingFactorContainer<T_CryptoProvider, T_Parameters>::DecryptionBlindingFactorContainer (const T_CryptoProvider &cryptoProvider, const T_Parameters &parameters) {
		/// Generate @f$ r @f$
		this->r = RandomProvider::GetInstance().GetRandomInteger(parameters.l + 1 + parameters.kappa);

		/// Compute @f$ [r] @f$
		this->encryptedR = cryptoProvider.EncryptInteger(r);
	}

}//namespace PrivateRecommendationsUtils
}//namespace SeComLib

#endif//DECRYPTION_BLINDING_FACTOR_CONTAINER_IMPLEMENTATION_GUARD