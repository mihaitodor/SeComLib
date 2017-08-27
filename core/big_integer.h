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
@file core/big_integer.h
@brief Defines BigInteger.
@details Masks specific big integer library wrapper classes under a common name.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef BIG_INTEGER_HEADER_GUARD
#define BIG_INTEGER_HEADER_GUARD

#include "big_integer_base.h"

//MPIR is compatible with GMPs functions
#if defined(LIB_GMP) || defined(LIB_MPIR)
	#include "big_integer_gmp.h"
#endif

namespace SeComLib {
namespace Core {
	//MPIR is compatible with GMPs functions
	#if defined(LIB_GMP) || defined(LIB_MPIR)
		/// Masks the big integer library wrapper classes under a common name
		typedef BigIntegerBase<BigIntegerGmp> BigInteger;
	#else
		#error No BigInteger implementation found
	#endif

}//namespace Core
}//namespace SeComLib

#endif//BIG_INTEGER_HEADER_GUARD