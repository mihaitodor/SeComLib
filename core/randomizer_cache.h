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
@file core/randomizer_cache.h
@brief Definition of template class RandomizerCache.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef RANDOMIZER_CACHE_HEADER_GUARD
#define RANDOMIZER_CACHE_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "big_integer.h"

//include C++ libraries
#include <vector>

namespace SeComLib {
namespace Core {
	/**
	@brief Randomizer cache
		
	This should be associated with a background thread that fills the cache once only a few unused items remain and a call to Pop should actually remove an element from the internal vector, but, for now,
	we pre-generate a constant quantity of random numbers and reuse them once they are depleted.

	@tparam T_Container A struct container for the randomizers
	*/
	template <typename T_Container>
	class RandomizerCache {
	public:
		/// Constructor
		RandomizerCache (const typename T_Container::CryptoProvider &cryptoProvider, const std::string &configurationPath);

		/// Constructor
		RandomizerCache (const typename T_Container::CryptoProvider &cryptoProvider, const typename T_Container::Parameters &parameters);

		/// Destructor - void implementation
		~RandomizerCache () {}

		/// Extracts one element
		const T_Container &Pop ();

	private:
		/// Internal cache vector
		std::vector<T_Container> cache;

		/// Reference to the crypto provider
		const typename T_Container::CryptoProvider &cryptoProvider;

		/// Parameters required to build the cache
		const typename T_Container::Parameters parameters;

		/// The index of the next element that will be retrieved
		size_t index;

		/// Populates the cache
		void initialize ();

		/// Copy constructor - not implemented
		RandomizerCache (const RandomizerCache &);

		/// Copy assignment operator - not implemented
		RandomizerCache operator= (const RandomizerCache &);
	};
}//namespace Core
}//namespace SeComLib

//Separate the implementation from the declaration
#include "randomizer_cache.hpp"

#endif//RANDOMIZER_CACHE_HEADER_GUARD