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
@file core/randomizer_container.hpp
@brief Implementation of struct RandomizerContainer.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef RANDOMIZER_CONTAINER_IMPLEMENTATION_GUARD
#define RANDOMIZER_CONTAINER_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Core {
	/**
	@note Parameters is unused here.

	@param cryptoProvider the crypto provider
	@param parameters unused parameter
	*/
	template <typename T_CryptoProvider, typename T_Parameters>
	RandomizerContainer<T_CryptoProvider, T_Parameters>::RandomizerContainer (const T_CryptoProvider &cryptoProvider, const T_Parameters &/*parameters*/) :
		randomizer(cryptoProvider.GetRandomizer()) {
	}

}//namespace Core
}//namespace SeComLib

#endif//RANDOMIZER_CONTAINER_IMPLEMENTATION_GUARD