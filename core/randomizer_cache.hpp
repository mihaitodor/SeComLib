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
@file core/randomizer_cache.hpp
@brief Implementation of template class RandomizerCache.
@details Pre-computed randomizer cache.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef RANDOMIZER_CACHE_IMPLEMENTATION_GUARD
#define RANDOMIZER_CACHE_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Core {
	/**
	Populates the cache.

	@param cryptoProvider the Crypto Provider
	@param configurationPath configuration parameters
	*/
	template <typename T_Container>
	RandomizerCache<T_Container>::RandomizerCache (const typename T_Container::CryptoProvider &cryptoProvider, const std::string &configurationPath) :
		cryptoProvider(cryptoProvider),
		parameters(configurationPath),
		index(0) {
		this->initialize();
	}

	/**
	Populates the cache.

	@param cryptoProvider the Crypto Provider
	@param parameters configuration parameters
	*/
	template <typename T_Container>
	RandomizerCache<T_Container>::RandomizerCache (const typename T_Container::CryptoProvider &cryptoProvider, const typename T_Container::Parameters &parameters) :
		cryptoProvider(cryptoProvider),
		parameters(parameters),
		index(0) {
		this->initialize();
	}

	/**
	This implementation reuses cache items once all of them are depleted.

	@return A reference to a T_Container.
	*/
	template <typename T_Container>
	const T_Container &RandomizerCache<T_Container>::Pop () {
		size_t currentIndex = this->index;
		
		++this->index;
		//wrap the index around once the cache is exhausted
		this->index %= this->parameters.capacity;

		return this->cache[currentIndex];
	}

	/**
	Reserves space for the required amount of items and fills the cache.
	*/
	template <typename T_Container>
	void RandomizerCache<T_Container>::initialize () {
		this->cache.reserve(this->parameters.capacity);

		for (size_t i = 0; i < this->parameters.capacity; ++i) {
			this->cache.emplace_back(T_Container(this->cryptoProvider, this->parameters));
		}
	}
}//namespace Core
}//namespace SeComLib

#endif//RANDOMIZER_CACHE_IMPLEMENTATION_GUARD