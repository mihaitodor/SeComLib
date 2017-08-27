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
@file core/big_integer_gmp.h
@brief Definition of class BigIntegerGmp.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef BIG_INTEGER_GMP_HEADER_GUARD
#define BIG_INTEGER_GMP_HEADER_GUARD

#include "big_integer_base.h"

//include C++ headers
#include <iostream>
#include <string>
#include <stdexcept>

//include 3rd party library headers
#if defined(LIB_GMP)
	#if defined(_WIN32)
		#pragma warning(push)
		#pragma warning(disable: 4127)//disable "warning C4127: conditional expression is constant"
		#pragma warning(disable: 4146)//disable "warning C4146: unary minus operator applied to unsigned type, result still unsigned"
		#include "gmp/gmp.h"
		#pragma warning(pop)//restore warnings
	#else
		#include "gmp.h"
	#endif
#elif defined(LIB_MPIR)
	#if defined(_WIN32)
		#pragma warning(push)
		#pragma warning(disable: 4127)//disable "warning C4127: conditional expression is constant"
		#include "mpir/mpir.h"
		#pragma warning(pop)//restore warnings
	#else
		#include "mpir.h"
	#endif
#endif

namespace SeComLib {
namespace Core {
	/**
	@brief The number of Miller-Rabin probabilistic primality tests to execute before a number is considered prime.

	@todo Move this parameter in the configuration file.
	@todo Should we increase this to 25 or above, as suggested by GMP's implementation of mpz_nextprime?
	@todo Consider what happens if we do get a composite.
	*/
	#define MILLER_RABIN_PRIMALITY_TEST_COUNT 10

	//forward-declare the GMP random provider wrapper
	class RandomProviderGmp;

	/**
	@brief Wrapper class for the most common functions related to the mpz_t datatype of the GMP library.
	*/
	class BigIntegerGmp {
	public:
		/// Generic alias required by BigIntegerBase to define the underlying data member
		typedef mpz_t BigIntegerType;

		/// Generic alias required by BigIntegerBase to grant the GMP random provider wrapper access to its private members
		typedef RandomProviderGmp RandomGeneratorImpl;

		/// Initializes the underlying data from input
		static void Initialize (BigIntegerBase<BigIntegerGmp> &input);
		/// Initializes the underlying data from input and sets it to the specified BigInteger value
		static void Initialize (BigIntegerBase<BigIntegerGmp> &input, const BigIntegerBase<BigIntegerGmp> &value);
		/// Initializes the underlying data from input and sets it to the specified long value
		static void Initialize (BigIntegerBase<BigIntegerGmp> &input, const long value);
		/// Initializes the underlying data from input and sets it to the specified unsigned long value
		static void Initialize (BigIntegerBase<BigIntegerGmp> &input, const unsigned long value);
		/// Initializes the underlying data from input and sets it to the specified scaled double value
		static void Initialize (BigIntegerBase<BigIntegerGmp> &input, const double value, const BigIntegerBase<BigIntegerGmp> &scaling, const bool truncate = false);
		/// Initializes the underlying data from input and sets it to the specified double value, scaled to preserve the given number of digits
		static void Initialize (BigIntegerBase<BigIntegerGmp> &input, const double value, const unsigned int numberOfDigits, const bool truncate = false);
		/// Initializes the underlying data from input and sets it to the specified string value, represented in the given base
		static void Initialize (BigIntegerBase<BigIntegerGmp> &input, const std::string &value, const int base = 0);

		/// Destroys the underlying data from input
		static void Destroy (BigIntegerBase<BigIntegerGmp> &input);

		/// Sets input to the specified BigInteger value
		static void Set (BigIntegerBase<BigIntegerGmp> &input, const BigIntegerBase<BigIntegerGmp> &value);
		/// Sets input to the specified long value
		static void Set (BigIntegerBase<BigIntegerGmp> &input, const long value);
		/// Sets input to the specified unsigned long value
		static void Set (BigIntegerBase<BigIntegerGmp> &input, const unsigned long value);

		/// Inverts the sign of input
		static void InvertSign (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input);

		/// Adds lhs and rhs
		static void Add (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs);
		/// Adds lhs and rhs
		static void Add (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const long rhs);
		/// Adds lhs and rhs
		static void Add (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const unsigned long rhs);

		/// Subtracts rhs from lhs
		static void Subtract (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs);
		/// Subtracts rhs from lhs
		static void Subtract (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const long rhs);
		/// Subtracts rhs from lhs
		static void Subtract (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const unsigned long rhs);

		/// Multiplies lhs with rhs
		static void Multiply (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs);
		/// Multiplies lhs with rhs
		static void Multiply (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const long rhs);
		/// Multiplies lhs with rhs
		static void Multiply (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const unsigned long rhs);

		/// Divides lhs by rhs
		static void Divide (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs);
		/// Divides lhs by rhs
		static void Divide (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const long rhs);
		/// Divides lhs by rhs
		static void Divide (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const unsigned long rhs);

		/// Computes input mod n
		static void Modulo (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const BigIntegerBase<BigIntegerGmp> &n);
		/// Computes input mod n
		static void Modulo (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const long n);
		/// Computes input mod n
		static void Modulo (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const unsigned long n);

		/// Compares lhs to rhs
		static int Compare (const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs);
		/// Compares lhs to rhs
		static int Compare (const BigIntegerBase<BigIntegerGmp> &lhs, const long rhs);
		/// Compares lhs to rhs
		static int Compare (const BigIntegerBase<BigIntegerGmp> &lhs, const unsigned long rhs);

		/// Bitwise right shift input by numberOfBits
		static void RightShift (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const unsigned long numberOfBits);
		/// Bitwise left shift input by numberOfBits
		static void LeftShift (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const unsigned long numberOfBits);

		/// Computes one's complement of input
		static void InvertBits (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input);

		/// Computes lhs bitwise AND rhs
		static void BitwiseAnd (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs);
		/// Computes lhs bitwise inclusive OR rhs
		static void BitwiseOr (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs);
		/// Computes lhs bitwise exclusive OR rhs
		static void BitwiseXor (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs);

		/// Computes the first prime greater than the current instance
		static void GetNextPrime (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input);
		/// Tests if input is a prime number
		static bool IsPrime (const BigIntegerBase<BigIntegerGmp> &input);

		/// Sets a bit in input at the specified index
		static void SetBit (BigIntegerBase<BigIntegerGmp> &input, const size_t index);
		/// Returns the bit specified by index
		static int GetBit (const BigIntegerBase<BigIntegerGmp> &input, const size_t index);

		/// Gets the length of the integer in the specified base
		static size_t GetSize (const BigIntegerBase<BigIntegerGmp> &input, const unsigned int base = 2);

		/// Computes the absolute value of input
		static void Abs (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input);

		/// Raises input to the specified power
		static void Pow (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const BigIntegerBase<BigIntegerGmp> &power);
		/// Raises input to the specified power
		static void Pow (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const long power);
		/// Raises input to the specified power
		static void Pow (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const unsigned long power);

		/// Raises input to the specified power modulo n
		static void PowModN (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const BigIntegerBase<BigIntegerGmp> &power, const BigIntegerBase<BigIntegerGmp> &n);
		/// Raises input to the specified power modulo n
		static void PowModN (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const long power, const BigIntegerBase<BigIntegerGmp> &n);
		/// Raises input to the specified power modulo n
		static void PowModN (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const unsigned long power, const BigIntegerBase<BigIntegerGmp> &n);

		/// Inverts input modulo n
		static void InvertModN (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const BigIntegerBase<BigIntegerGmp> &n);

		/// Swaps lhs with rhs efficiently
		static void Swap (BigIntegerBase<BigIntegerGmp> &lhs, BigIntegerBase<BigIntegerGmp> &rhs);

		/// Computes the greatest common divisor of lhs and rhs
		static void Gcd (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs);
		/// Computes the least common multiple of lhs and rhs
		static void Lcm (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs);

		/// Convert input to std::string in the specified base
		static std::string ToString (const BigIntegerBase<BigIntegerGmp> &input, const unsigned int base = 2);
		/// Convert input to unsigned long
		static unsigned long ToUnsignedLong (const BigIntegerBase<BigIntegerGmp> &input);
	};


}//namespace Core
}//namespace SeComLib

#endif//BIG_INTEGER_GMP_HEADER_GUARD