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
@file core/secure_permutation.cpp
@brief Implementation of class SecurePermutation.
@details Implements the Fisher-Yates (Knuth) shuffle algorithm.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "secure_permutation.h"

namespace SeComLib {
namespace Core {
	/**
	Populates the internal permutations vector.

	@param size the length of the vector which needs to be shuffled
	*/
	SecurePermutation::SecurePermutation (const size_t size) : vectorSize(size) {
		//store the the Fisher-Yates (Knuth) shuffle permutations
		for (size_t index = size - 1; index > 0; --index) {
			//generate a random number in the interval [0, index]
			size_t randomValue = static_cast<size_t>(RandomProvider::GetInstance().GetRandomInteger(BigInteger(static_cast<unsigned long>(index + 1))).ToUnsignedLong());

			this->permutations.emplace_back(std::pair<size_t, size_t>(index , randomValue));
		}
	}
}//namespace Core
}//namespace SeComLib