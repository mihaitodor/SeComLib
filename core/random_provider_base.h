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
@file core/random_provider_base.h
@brief Definition of class RandomProviderBase.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef RANDOM_PROVIDER_BASE_HEADER_GUARD
#define RANDOM_PROVIDER_BASE_HEADER_GUARD

//this header also includes the 3rd party library specific headers
#include "big_integer.h"

//include C++ headers
#include <iostream>
#include <stdexcept>

namespace SeComLib {
namespace Core {
	/**
	@brief Template class which masks various RandomProvider implementations and provides a common interface that all of them must implement.

	Works as a singleton: RandomProvider::GetInstance().DoStuff()

	@tparam T_Impl The random provider library wrapper
	*/
	template <typename T_Impl>
	class RandomProviderBase {
	public:
		/// The random provider implementation requires access to the underlying data
		friend T_Impl;

		/// Returns a reference to the singleton
		static RandomProviderBase<T_Impl> &GetInstance ();

		/// Generates a random integer having at most numberOfBits bits
		BigInteger GetRandomInteger (const size_t numberOfBits);

		/// Generates a random integer in the interval @f$ [0, maximumValue) @f$
		BigInteger GetRandomInteger (const BigInteger &maximumValue);

		/// Generates a random prime, guaranteed to have numberOfBits length
		BigInteger GetMaxLengthRandomPrime (const size_t &numberOfBits);

	private:
		/// Implementation-defined random generator state
		typename T_Impl::RandomGeneratorState randomGeneratorState;

		/// Random seed required for the random generator state initialization
		unsigned int randomSeed;

		/// Default constructor (private, Singleton Pattern)
		/// @todo Use the BOOST libray to produce the seed.
		/// @todo Create a custom exception class.
		RandomProviderBase ();

		/// Destructor (private, Singleton Pattern)
		~RandomProviderBase ();

		/// Copy constructor - not implemented
		RandomProviderBase (RandomProviderBase<T_Impl> const &);

		/// Copy assignment operator - not implemented
		RandomProviderBase operator= (RandomProviderBase<T_Impl> const &);
	};

}//namespace Core
}//namespace SeComLib

//Separate the implementation from the declaration of template methods
#include "random_provider_base.hpp"

#endif//RANDOM_PROVIDER_BASE_HEADER_GUARD