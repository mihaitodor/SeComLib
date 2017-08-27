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
@file core/random_provider_base.hpp
@brief Implementation of class RandomProviderBase. To be included in random_provider_base.h
@details Template class which masks various RandomProvider implementations and provides a common interface that all of them must implement.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef RANDOM_PROVIDER_BASE_IMPLEMENTATION_GUARD
#define RANDOM_PROVIDER_BASE_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Core {
	/**
	Creates a static instance of this class and returns it.
	The instance will be destroyed when the application terminates (singleton pattern).

	@return The static instance of this class
	*/
	template <typename T_Impl>
	inline RandomProviderBase<T_Impl> &RandomProviderBase<T_Impl>::GetInstance () {
		static RandomProviderBase<T_Impl> instance;
		return instance;
	}

	/**
	@note Can't use const correctness, since it changes the random generator state
	@param numberOfBits the maximum bit length of the generated random number
	@return An instance of BigInteger containing the generated random number
	*/
	template <typename T_Impl>
	inline BigInteger RandomProviderBase<T_Impl>::GetRandomInteger (const size_t numberOfBits) {
		BigInteger output;

		T_Impl::GetRandomInteger(output, *this, numberOfBits);

		return output;
	}

	/**
	@note Can't use const correctness, since it changes the random generator state
	@param maximumValue the upper limit of the generated random number (non-inclusive)
	@return An instance of BigInteger containing the generated random number
	*/
	template <typename T_Impl>
	inline BigInteger RandomProviderBase<T_Impl>::GetRandomInteger (const BigInteger &maximumValue) {
		BigInteger output;

		T_Impl::GetRandomInteger(output, *this, maximumValue);

		return output;
	}

	/**
	@note Can't use const correctness, since it changes the random generator state by calling RandomProviderGmp::GetRandomInteger
	@param numberOfBits the bit length of the generated prime
	@return An instance of BigInteger containing the generated prime
	*/
	template <typename T_Impl>
	inline BigInteger RandomProviderBase<T_Impl>::GetMaxLengthRandomPrime (const size_t &numberOfBits) {
		BigInteger output;

		T_Impl::GetMaxLengthRandomPrime(output, *this, numberOfBits);

		return output;
	}

	/**
	Initializes the current instance.
	*/
	template <typename T_Impl>
	RandomProviderBase<T_Impl>::RandomProviderBase () {
		T_Impl::Initialize(*this);
	}

	/**
	Destroys the current instance.
	*/
	template <typename T_Impl>
	RandomProviderBase<T_Impl>::~RandomProviderBase () {
		T_Impl::Destroy(*this);
	}

}//namespace Core
}//namespace SeComLib

#endif//RANDOM_PROVIDER_BASE_IMPLEMENTATION_GUARD