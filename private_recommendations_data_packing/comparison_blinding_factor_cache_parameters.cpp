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
@file private_recommendations_data_packing/comparison_blinding_factor_cache_parameters.cpp
@brief Implementation of struct ComparisonBlindingFactorCacheParameters.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "comparison_blinding_factor_cache_parameters.h"

namespace SeComLib {
namespace PrivateRecommendationsDataPacking {
	/**
	@param configurationPath the configuration path for parameters
	@param l bitsize of blinded values
	@param emptyBuckets @f$ (2^{l + 2})^i @f$
	*/
	ComparisonBlindingFactorCacheParameters::ComparisonBlindingFactorCacheParameters (const std::string &configurationPath, const size_t l, const std::deque<BigInteger> &emptyBuckets) :
		BlindingFactorCacheParameters(configurationPath, l),
		emptyBuckets(emptyBuckets) {
	}
}//namespace PrivateRecommendationsUtils
}//namespace SeComLib