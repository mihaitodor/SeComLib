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
@file core/random_provider_gmp.h
@brief Definition of class RandomProviderGmp.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef RANDOM_PROVIDER_GMP_HEADER_GUARD
#define RANDOM_PROVIDER_GMP_HEADER_GUARD

//defined for WIN64 as well
#ifdef _WIN32
	//required by iostream to include the Windows function errno_t rand_s(unsigned int* randomValue)
	#define _CRT_RAND_S
#endif

#include "random_provider_base.h"

//include C++ headers
#include <iostream>
#include <fstream>
#include <stdexcept>

namespace SeComLib {
namespace Core {
	/**
	@brief Wrapper for the required GMP library random number specific functions.
	*/
	class RandomProviderGmp {
	public:
		/// Generic alias required by RandomGeneratorBase to define the underlying random state member
		typedef gmp_randstate_t RandomGeneratorState;

		/// Initializes the underlying random state from input
		static void Initialize(RandomProviderBase<RandomProviderGmp> &input);

		/// Destroys the underlying data from input
		static void Destroy(RandomProviderBase<RandomProviderGmp> &input);

		/// Generates a random integer having at most numberOfBits bits
		static void GetRandomInteger(BigIntegerBase<BigIntegerGmp> &output, RandomProviderBase<RandomProviderGmp> &input, const size_t numberOfBits);

		/// Generates a random integer in the interval @f$ [0, maximumValue) @f$
		static void GetRandomInteger(BigIntegerBase<BigIntegerGmp> &output, RandomProviderBase<RandomProviderGmp> &input, const BigIntegerBase<BigIntegerGmp> &maximumValue);

		/// Generates a random prime, guaranteed to have numberOfBits length
		static void GetMaxLengthRandomPrime(BigIntegerBase<BigIntegerGmp> &output, RandomProviderBase<RandomProviderGmp> &input, const size_t numberOfBits);
	};
}//namespace Core
}//namespace SeComLib

#endif//RANDOM_PROVIDER_GMP_HEADER_GUARD