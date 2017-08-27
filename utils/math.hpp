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
@file utils/math.hpp
@brief Implementation of template members from class Math.
@details Provides specialized mathematical functions.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef MATH_IMPLEMENTATION_GUARD
#define MATH_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Utils {
	/**
	Negative numbers are rounded similar to the positive ones.

	@tparam T_Input integer or floating point type
	@tparam T_Output integer or floating point type
	@param input a integer or floating point number
	@return The rounded number
	*/
	template <typename T_Input, typename T_Output>
	T_Output Math::Round (const T_Input input) {
		return static_cast<T_Output>(input < 0.0 ? std::ceil(input - 0.5) : std::floor(input + 0.5));
	}

}//namespace Utils
}//namespace SeComLib

#endif//MATH_IMPLEMENTATION_GUARD