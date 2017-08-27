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
@file private_recommendations_utils/decryption_blinding_factor_container.h
@brief Definition of struct DecryptionBlindingFactorContainer.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef DECRYPTION_BLINDING_FACTOR_CONTAINER_HEADER_GUARD
#define DECRYPTION_BLINDING_FACTOR_CONTAINER_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "core/big_integer.h"

//include C++ libraries
#include <string>
#include <deque>
#include <stdexcept>

namespace SeComLib {
using namespace Core;

namespace PrivateRecommendationsUtils {
	/**
	@brief Stores precomputed random data

	@tparam T_CryptoProvider The type of the crypto provider, derived from template class CryptoProvider
	@tparam T_Parameters A struct of configuration parameters, derived from struct RandomizerCacheParameters
	*/
	template <typename T_CryptoProvider, typename T_Parameters>
	struct DecryptionBlindingFactorContainer {
	public:
		/// Exposes the crypto provider type
		typedef T_CryptoProvider CryptoProvider;

		/// Exposes the parameters container type
		typedef T_Parameters Parameters;

		/// @f$ r @f$
		BigInteger r;

		/// @f$ [r] @f$
		typename T_CryptoProvider::Ciphertext encryptedR;

		/// Constructor
		DecryptionBlindingFactorContainer (const T_CryptoProvider &cryptoProvider, const T_Parameters &parameters);
	};

}//namespace PrivateRecommendationsUtils
}//namespace SeComLib

//Separate the implementation from the declaration
#include "decryption_blinding_factor_container.hpp"

#endif//DECRYPTION_BLINDING_FACTOR_CONTAINER_HEADER_GUARD