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
@file secure_face_recognition_utils/dgk_comparison_blinding_factor_cache_parameters.h
@brief Definition of struct DgkComparisonBlindingFactorCacheParameters.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef DGK_COMPARISON_BLINDING_FACTOR_CACHE_PARAMETERS_HEADER_GUARD
#define DGK_COMPARISON_BLINDING_FACTOR_CACHE_PARAMETERS_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "core/big_integer.h"
#include "core/randomizer_cache_parameters.h"

namespace SeComLib {
using namespace Core;

namespace SecureFaceRecognitionUtils {
	/**
	@brief Comparison blinding factor cache parameter container struct
	*/
	struct DgkComparisonBlindingFactorCacheParameters : public RandomizerCacheParameters {
	public:
		/// the bit size of the comparison operands
		size_t lPlusOne;

		/// Constructor
		DgkComparisonBlindingFactorCacheParameters (const std::string &configurationPath, const size_t lPlusOne);
	};
}//namespace SecureFaceRecognitionUtils
}//namespace SeComLib

#endif//DGK_COMPARISON_BLINDING_FACTOR_CACHE_PARAMETERS_HEADER_GUARD