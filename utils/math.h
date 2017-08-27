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
@file utils/math.h
@brief Definition of class Math.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef MATH_HEADER_GUARD
#define MATH_HEADER_GUARD

//include C++ headers
#include <cmath>
#include <vector>

namespace SeComLib {
namespace Utils {
	/**
	@brief Utilitary class providing custom math functions
	*/
	class Math {
	public:
		/// Rounds input to the nearest integer
		template <typename T_Input, typename T_Output>
		static T_Output Round (const T_Input input);

	private:
		/// Default constructor - not implemented
		Math ();

		/// Destructor - not implemented
		~Math ();

		/// Copy constructor - not implemented
		Math (Math const &);

		/// Copy assignment operator - not implemented
		Math operator= (Math const &);
	};

}//namespace Utils
}//namespace SeComLib

//Separate the implementation from the declaration of template methods
#include "math.hpp"

#endif//MATH_HEADER_GUARD