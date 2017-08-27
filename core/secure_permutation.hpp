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
@file core/secure_permutation.hpp
@brief Implementation of template members from class SecurePermutation. To be included in secure_permutation.h
@details SecurePermutation performs the Fisher-Yates (Knuth) shuffle algorithm on a vector.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SECURE_PERMUTATION_IMPLEMENTATION_GUARD
#define SECURE_PERMUTATION_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Core {
	/**
	@tparam T_DataType The type of the input vector to be shuffled
	@param vector a vector of elements
	@throws std::runtime_error The input vector doesn't have the expected size
	*/
	template <typename T_DataType>
	void SecurePermutation::Permute (T_DataType &vector) const {
		if (this->vectorSize != vector.size()) {
			throw std::runtime_error("The input vector doesn't have the expected size.");
		}

		for (PermutationVector::const_iterator permutation = permutations.begin(); permutation != permutations.end(); ++permutation) {
			std::swap(vector[permutation->first], vector[permutation->second]);
		}
	}

	/**
	@tparam T_DataType The type of the input vector to be shuffled
	@param vector a vector of elements
	@throws std::runtime_error The input vector doesn't have the expected size
	*/
	template <typename T_DataType>
	void SecurePermutation::InvertPermutation (T_DataType &vector) const {
		if (this->vectorSize != vector.size()) {
			throw std::runtime_error("The input vector doesn't have the expected size.");
		}

		for (PermutationVector::const_reverse_iterator permutation = permutations.rbegin(); permutation != permutations.rend(); ++permutation) {
			std::swap(vector[permutation->first], vector[permutation->second]);
		}
	}

}//namespace Core
}//namespace SeComLib

#endif//SECURE_PERMUTATION_IMPLEMENTATION_GUARD