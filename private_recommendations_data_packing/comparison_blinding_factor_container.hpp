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
@file private_recommendations_data_packing/comparison_blinding_factor_container.hpp
@brief Implementation of struct ComparisonBlindingFactorContainer.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef COMPARISON_BLINDING_FACTOR_CONTAINER_IMPLEMENTATION_GUARD
#define COMPARISON_BLINDING_FACTOR_CONTAINER_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace PrivateRecommendationsDataPacking {
	/**
	Computes:
	- @f$ r @f$
	- @f$ [r] @f$
	- @f$ r^{(i)} @f$

	@param cryptoProvider the crypto provider
	@param parameters configuration parameters
	*/
	template <typename T_CryptoProvider, typename T_Parameters>
	ComparisonBlindingFactorContainer<T_CryptoProvider, T_Parameters>::ComparisonBlindingFactorContainer (const T_CryptoProvider &cryptoProvider, const T_Parameters &parameters) {
		/// @f$ r \in_R \mathbb{N} @f$ of size @f$ l + 1 + \kappa @f$ bits, where l is the size of a data bucket times the number of buckets
		this->r = RandomProvider::GetInstance().GetRandomInteger(parameters.l + 1 + parameters.kappa);

		/// Compute @f$ [r] @f$
		this->encryptedR = cryptoProvider.EncryptInteger(this->r);

		/// Compute @f$ r^{(i)} @f$ such that @f$ r \pmod {2^{N(l + 2)}} = \displaystyle\sum_{i = 0}^{N -1}{r^{(i)}(2^{l + 2})^i} @f$
		for (size_t i = 0; i < parameters.emptyBuckets.size(); ++i) {
			if (i < parameters.emptyBuckets.size() - 1) {
				this->ri.emplace_back((this->r % parameters.emptyBuckets[i + 1]) / parameters.emptyBuckets[i]);
			}
			else {
				this->ri.emplace_back(this->r / parameters.emptyBuckets[i]);
			}
		}
	}
}//namespace PrivateRecommendationsDataPacking
}//namespace SeComLib

#endif//COMPARISON_BLINDING_FACTOR_CONTAINER_IMPLEMENTATION_GUARD