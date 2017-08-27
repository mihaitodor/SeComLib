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
@file core/randomizer_base.h
@brief Definition of struct RandomizerBase.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef RANDOMIZER_BASE_HEADER_GUARD
#define RANDOMIZER_BASE_HEADER_GUARD

#include "big_integer.h"

namespace SeComLib {
namespace Core {
	/**
	@brief RandomizerBase struct
	*/
	struct RandomizerBase {
	public:
		/// The randomizer data
		BigInteger data;

		/// Default constructor
		RandomizerBase ();

		/// Constructor with initialization
		RandomizerBase (const BigInteger &data);
	};
}//namespace Core
}//namespace SeComLib

#endif//RANDOMIZER_BASE_HEADER_GUARD