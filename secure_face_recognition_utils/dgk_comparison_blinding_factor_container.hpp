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
@file secure_face_recognition_utils/dgk_comparison_blinding_factor_container.hpp
@brief Implementation of struct DgkComparisonBlindingFactorContainer.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef DGK_COMPARISON_BLINDING_FACTOR_CONTAINER_IMPLEMENTATION_GUARD
#define DGK_COMPARISON_BLINDING_FACTOR_CONTAINER_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace SecureFaceRecognitionUtils {
	/**
	Computes @f$ l + 1 @f$ random numbers and their encryptions

	@param cryptoProvider the crypto provider
	@param parameters configuration parameters
	*/
	template <typename T_CryptoProvider, typename T_Parameters>
	DgkComparisonBlindingFactorContainer<T_CryptoProvider, T_Parameters>::DgkComparisonBlindingFactorContainer (const T_CryptoProvider &cryptoProvider, const T_Parameters &parameters) {
		/// Generate @f$ R_{-1}, ..., R_{l - 1} \in_R \mathbb{Z}_u^* @f$
		for (size_t i = 0; i < parameters.lPlusOne; ++i) {
			this->R.emplace_back(RandomProvider::GetInstance().GetRandomInteger(cryptoProvider.GetMessageSpaceSize() - 1) + 1);
			this->encryptedR.emplace_back(cryptoProvider.EncryptIntegerNonrandom(this->R.back()));
		}
	}

}//namespace SecureFaceRecognitionUtils
}//namespace SeComLib

#endif//DGK_COMPARISON_BLINDING_FACTOR_CONTAINER_IMPLEMENTATION_GUARD