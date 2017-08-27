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
@file core/secure_permutation.h
@brief Definition of class SecurePermutation.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SECURE_PERMUTATION_HEADER_GUARD
#define SECURE_PERMUTATION_HEADER_GUARD

#include "random_provider.h"

//include C++ headers
#include <deque>

namespace SeComLib {
namespace Core {
	/**
	@brief Permutation class which implements the Fisher-Yates (Knuth) shuffle algorithm.
	*/
	class SecurePermutation {
	public:
		/// Define the permutation map container
		typedef std::deque<std::pair<size_t, size_t>> PermutationVector;

		/// Default constructor
		SecurePermutation (const size_t size);

		/// Destructor
		~SecurePermutation () {}

		/// Applies the permutations to the input vector
		template <typename T_DataType>
		void Permute (T_DataType &vector) const;

		/// Applies the permutations in reverse to the input verctor
		template <typename T_DataType>
		void InvertPermutation (T_DataType &vector) const;

	private:
		/// The size of the vectors that can be permuted
		const size_t vectorSize;

		/// The vector of permutations
		PermutationVector permutations;

		/// Copy constructor - not implemented
		SecurePermutation (SecurePermutation const &);

		/// Copy assignment operator - not implemented
		SecurePermutation operator= (SecurePermutation const &);
	};
}//namespace Core
}//namespace SeComLib

//Separate the implementation from the declaration of template methods
#include "secure_permutation.hpp"

#endif//SECURE_PERMUTATION_HEADER_GUARD