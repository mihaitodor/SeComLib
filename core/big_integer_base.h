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
@file core/big_integer_base.h
@brief Definition of class BigIntegerBase.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef BIG_INTEGER_BASE_HEADER_GUARD
#define BIG_INTEGER_BASE_HEADER_GUARD

//include C++ headers
#include <iostream>
#include <string>
#include <stdexcept>

namespace SeComLib {
namespace Core {
	/**
	@brief Template class which adds syntactic sugar to big integer operations

	@tparam T_Impl The big integer library wrapper

	@todo It would be nice to enable move semantics for this class. Even better, it should be replaced with boost::multiprecision: http://www.boost.org/doc/libs/1_53_0/libs/multiprecision/doc/html/boost_multiprecision/intro.html
	*/
	template <typename T_Impl>
	class BigIntegerBase {
		/// The big number implementation requires access to the underlying data
		friend T_Impl;

		/// The lesser evil: This way, I can separate the big integer wrapper in separate parts for big integer operations and for random number generation, without exposing the private members
		friend typename T_Impl::RandomGeneratorImpl;

	public:
		/* Constructors */

		/// Default constructor
		BigIntegerBase ();

		/// Copy constructor
		BigIntegerBase (const BigIntegerBase<T_Impl> &input);

		/// Initialize current instance with a long value
		BigIntegerBase (const long input);

		/// Initialize current instance with an unsigned long value
		BigIntegerBase (const unsigned long input);

		/// Initialize current instance with an int value
		BigIntegerBase (const int input);

		/// Initialize current instance with an unsigned int value
		BigIntegerBase (const unsigned int input);

		/// Initialize current instance with a scaled double value
		BigIntegerBase (const double input, const BigIntegerBase<T_Impl> &scaling, const bool truncate = false);

		/// Initialize current instance with a double value, scaled to preserve the specified number of digits
		BigIntegerBase (const double input, const unsigned int numberOfDigits, const bool truncate = false);

		/// Initialize current instance with a string value, represented in the given base
		BigIntegerBase (const std::string &input, const int base = 0);

		/* /Constructors */

		/// Destructor
		~BigIntegerBase ();

		/* Operator overloading */

		/// BigIntegerBase assignment operator
		BigIntegerBase<T_Impl> &operator= (const BigIntegerBase<T_Impl> &input);
		/// long assignment operator
		BigIntegerBase<T_Impl> &operator= (const long input);
		/// unsigned long assignment operator
		BigIntegerBase<T_Impl> &operator= (const unsigned long input);
		/// int assignment operator
		BigIntegerBase<T_Impl> &operator= (const int input);
		/// unsigned int assignment operator
		BigIntegerBase<T_Impl> &operator= (const unsigned int input);

		/// Unary plus operator
		BigIntegerBase<T_Impl> operator+ () const;
		/// Unary negation operator
		BigIntegerBase<T_Impl> operator- () const;

		/// Prefix increment unary operator
		BigIntegerBase<T_Impl> &operator++ ();
		/// Postfix increment unary operator
		BigIntegerBase<T_Impl> operator++ (int);
		/// Prefix decrement unary operator
		BigIntegerBase<T_Impl> &operator-- ();
		/// Postfix decrement unary operator
		BigIntegerBase<T_Impl> operator-- (int);

		/// BigIntegerBase addition binary operator
		BigIntegerBase<T_Impl> operator+ (const BigIntegerBase<T_Impl> &input) const;
		/// long addition binary operator
		BigIntegerBase<T_Impl> operator+ (const long input) const;
		/// unsigned long addition binary operator
		BigIntegerBase<T_Impl> operator+ (const unsigned long input) const;
		/// int addition binary operator
		BigIntegerBase<T_Impl> operator+ (const int input) const;
		/// unsigned int addition binary operator
		BigIntegerBase<T_Impl> operator+ (const unsigned int input) const;
		/// BigIntegerBase addition & assignment binary operator
		BigIntegerBase<T_Impl> &operator+= (const BigIntegerBase<T_Impl> &input);
		/// long addition & assignment binary operator
		BigIntegerBase<T_Impl> &operator+= (const long input);
		/// unsigned long addition & assignment binary operator
		BigIntegerBase<T_Impl> &operator+= (const unsigned long input);
		/// int addition & assignment binary operator
		BigIntegerBase<T_Impl> &operator+= (const int input);
		/// unsigned int addition & assignment binary operator
		BigIntegerBase<T_Impl> &operator+= (const unsigned int input);

		/// BigIntegerBase subtraction binary operator
		BigIntegerBase<T_Impl> operator- (const BigIntegerBase<T_Impl> &input) const;
		/// long subtraction binary operator
		BigIntegerBase<T_Impl> operator- (const long input) const;
		/// unsigned long subtraction binary operator
		BigIntegerBase<T_Impl> operator- (const unsigned long input) const;
		/// int subtraction binary operator
		BigIntegerBase<T_Impl> operator- (const int input) const;
		/// unsigned int subtraction binary operator
		BigIntegerBase<T_Impl> operator- (const unsigned int input) const;
		/// BigIntegerBase subtraction & assignment binary operator
		BigIntegerBase<T_Impl> &operator-= (const BigIntegerBase<T_Impl> &input);
		/// long subtraction & assignment binary operator
		BigIntegerBase<T_Impl> &operator-= (const long input);
		/// unsigned long subtraction & assignment binary operator
		BigIntegerBase<T_Impl> &operator-= (const unsigned long input);
		/// int subtraction & assignment binary operator
		BigIntegerBase<T_Impl> &operator-= (const int input);
		/// unsigned int subtraction & assignment binary operator
		BigIntegerBase<T_Impl> &operator-= (const unsigned int input);

		/// BigIntegerBase multiplication binary operator
		BigIntegerBase<T_Impl> operator* (const BigIntegerBase<T_Impl> &input) const;
		/// long multiplication binary operator
		BigIntegerBase<T_Impl> operator* (const long input) const;
		/// unsigned long multiplication binary operator
		BigIntegerBase<T_Impl> operator* (const unsigned long input) const;
		/// int multiplication binary operator
		BigIntegerBase<T_Impl> operator* (const int input) const;
		/// unsigned int multiplication binary operator
		BigIntegerBase<T_Impl> operator* (const unsigned int input) const;
		/// BigIntegerBase multiplication & assignment binary operator
		BigIntegerBase<T_Impl> &operator*= (const BigIntegerBase<T_Impl> &input);
		/// long multiplication & assignment binary operator
		BigIntegerBase<T_Impl> &operator*= (const long input);
		/// unsigned long multiplication & assignment binary operator
		BigIntegerBase<T_Impl> &operator*= (const unsigned long input);
		/// int multiplication & assignment binary operator
		BigIntegerBase<T_Impl> &operator*= (const int input);
		/// unsigned int multiplication & assignment binary operator
		BigIntegerBase<T_Impl> &operator*= (const unsigned int input);

		/// BigIntegerBase division binary operator
		BigIntegerBase<T_Impl> operator/ (const BigIntegerBase<T_Impl> &input) const;
		/// long division binary operator
		BigIntegerBase<T_Impl> operator/ (const long input) const;
		/// unsigned long division binary operator
		BigIntegerBase<T_Impl> operator/ (const unsigned long input) const;
		/// int division binary operator
		BigIntegerBase<T_Impl> operator/ (const int input) const;
		/// unsigned int division binary operator
		BigIntegerBase<T_Impl> operator/ (const unsigned int input) const;
		/// BigIntegerBase division & assignment binary operator
		BigIntegerBase<T_Impl> &operator/= (const BigIntegerBase<T_Impl> &input);
		/// long division & assignment binary operator
		BigIntegerBase<T_Impl> &operator/= (const long input);
		/// unsigned long division & assignment binary operator
		BigIntegerBase<T_Impl> &operator/= (const unsigned long input);
		/// int division & assignment binary operator
		BigIntegerBase<T_Impl> &operator/= (const int input);
		/// unsigned int division & assignment binary operator
		BigIntegerBase<T_Impl> &operator/= (const unsigned int input);

		/// BigIntegerBase modulus binary operator
		BigIntegerBase<T_Impl> operator% (const BigIntegerBase<T_Impl> &input) const;
		/// long modulus binary operator
		BigIntegerBase<T_Impl> operator% (const long input) const;
		/// unsigned long modulus binary operator
		BigIntegerBase<T_Impl> operator% (const unsigned long input) const;
		/// int modulus binary operator
		BigIntegerBase<T_Impl> operator% (const int input) const;
		/// unsigned int modulus binary operator
		BigIntegerBase<T_Impl> operator% (const unsigned int input) const;
		/// BigIntegerBase modulus & assignment binary operator
		BigIntegerBase<T_Impl> &operator%= (const BigIntegerBase<T_Impl> &input);
		/// long modulus & assignment binary operator
		BigIntegerBase<T_Impl> &operator%= (const long input);
		/// unsigned long modulus & assignment binary operator
		BigIntegerBase<T_Impl> &operator%= (const unsigned long input);
		/// int modulus & assignment binary operator
		BigIntegerBase<T_Impl> &operator%= (const int input);
		/// unsigned int modulus & assignment binary operator
		BigIntegerBase<T_Impl> &operator%= (const unsigned int input);

		/// BigIntegerBase equality binary operator
		bool operator== (const BigIntegerBase<T_Impl> &input) const;
		/// long equality binary operator
		bool operator== (const long input) const;
		/// unsigned long equality binary operator
		bool operator== (const unsigned long input) const;
		/// int equality binary operator
		bool operator== (const int input) const;
		/// unsigned int equality binary operator
		bool operator== (const unsigned int input) const;

		/// BigIntegerBase inequality binary operator
		bool operator!= (const BigIntegerBase<T_Impl> &input) const;
		/// long inequality binary operator
		bool operator!= (const long input) const;
		/// unsigned long inequality binary operator
		bool operator!= (const unsigned long input) const;
		/// int inequality binary operator
		bool operator!= (const int input) const;
		/// unsigned int inequality binary operator
		bool operator!= (const unsigned int input) const;

		/// BigIntegerBase less than binary operator
		bool operator< (const BigIntegerBase<T_Impl> &input) const;
		/// long less than binary operator
		bool operator< (const long input) const;
		/// unsigned long less than binary operator
		bool operator< (const unsigned long input) const;
		/// int less than binary operator
		bool operator< (const int input) const;
		/// unsigned int less than binary operator
		bool operator< (const unsigned int input) const;

		/// BigIntegerBase less than or equal to binary operator
		bool operator<= (const BigIntegerBase<T_Impl> &input) const;
		/// long less than or equal to binary operator
		bool operator<= (const long input) const;
		/// unsigned long less than or equal to binary operator
		bool operator<= (const unsigned long input) const;
		/// int less than or equal to binary operator
		bool operator<= (const int input) const;
		/// unsigned int less than or equal to binary operator
		bool operator<= (const unsigned int input) const;

		/// BigIntegerBase greater than or equal to binary operator
		bool operator>= (const BigIntegerBase<T_Impl> &input) const;
		/// long greater than or equal to binary operator
		bool operator>= (const long input) const;
		/// unsigned long greater than or equal to binary operator
		bool operator>= (const unsigned long input) const;
		/// int greater than or equal to binary operator
		bool operator>= (const int input) const;
		/// unsigned int greater than or equal to binary operator
		bool operator>= (const unsigned int input) const;

		/// BigIntegerBase greater than binary operator
		bool operator> (const BigIntegerBase<T_Impl> &input) const;
		/// long greater than binary operator
		bool operator> (const long input) const;
		/// unsigned long greater than binary operator
		bool operator> (const unsigned long input) const;
		/// int greater than binary operator
		bool operator> (const int input) const;
		/// unsigned int greater than binary operator
		bool operator> (const unsigned int input) const;

		/// Bitwise right shift binary operator
		BigIntegerBase<T_Impl> operator>> (const unsigned long input) const;
		/// Bitwise right shift & assignment binary operator
		BigIntegerBase<T_Impl> &operator>>= (const unsigned long input);
		/// Bitwise left shift binary operator
		BigIntegerBase<T_Impl> operator<< (const unsigned long input) const;
		/// Bitwise left shift & assignment binary operator
		BigIntegerBase<T_Impl> &operator<<= (const unsigned long input);

		/// One's complement unary operator
		BigIntegerBase<T_Impl> operator~ () const;

		/// Bitwise AND binary operator
		BigIntegerBase<T_Impl> operator& (const BigIntegerBase<T_Impl> &input) const;
		/// Bitwise AND & assignment binary operator
		BigIntegerBase<T_Impl> &operator&= (const BigIntegerBase<T_Impl> &input);
		/// Bitwise inclusive OR binary operator
		BigIntegerBase<T_Impl> operator| (const BigIntegerBase<T_Impl> &input) const;
		/// Bitwise inclusive OR & assignment binary operator
		BigIntegerBase<T_Impl> &operator|= (const BigIntegerBase<T_Impl> &input);
		/// Bitwise exclusive OR binary operator
		BigIntegerBase<T_Impl> operator^ (const BigIntegerBase<T_Impl> &input) const;
		/// Bitwise exclusive OR & assignment binary operator
		BigIntegerBase<T_Impl> &operator^= (const BigIntegerBase<T_Impl> &input);

		/* /Operator overloading */

		/* Utility methods */

		/// Computes the first prime greater than the current instance
		BigIntegerBase<T_Impl> GetNextPrime () const;
		/// Tests if the current instance is a prime number
		bool IsPrime () const;

		/// Sets a bit in the current instance at the specified index
		BigIntegerBase<T_Impl> &SetBit (const size_t index);
		/// Returns the bit specified by index
		int GetBit (const size_t index) const;

		/// Gets the length of the integer in the specified base
		size_t GetSize (const unsigned int base = 2) const;

		/// Sets the current instance to its absolute value
		BigIntegerBase<T_Impl> &Abs ();

		/// Computes the absolute value of the current instance
		BigIntegerBase<T_Impl> GetAbs () const;

		/// Raises the current instance to the specified BigIntegerBase power
		BigIntegerBase<T_Impl> &Pow (const BigIntegerBase<T_Impl> &power);
		/// Raises the current instance to the specified long power
		BigIntegerBase<T_Impl> &Pow (const long power);
		/// Raises the current instance to the specified unsigned long power
		BigIntegerBase<T_Impl> &Pow (const unsigned long power);
		/// Raises the current instance to the specified int power
		BigIntegerBase<T_Impl> &Pow (const int power);
		/// Raises the current instance to the specified unsigned int power
		BigIntegerBase<T_Impl> &Pow (const unsigned int power);

		/// Computes the integer raised to the specified BigIntegerBase power
		BigIntegerBase<T_Impl> GetPow (const BigIntegerBase<T_Impl> &power) const;
		/// Computes the integer raised to the specified long power
		BigIntegerBase<T_Impl> GetPow (const long power) const;
		/// Computes the integer raised to the specified unsigned long power
		BigIntegerBase<T_Impl> GetPow (const unsigned long power) const;
		/// Computes the integer raised to the specified int power
		BigIntegerBase<T_Impl> GetPow (const int power) const;
		/// Computes the integer raised to the specified unsigned int power
		BigIntegerBase<T_Impl> GetPow (const unsigned int power) const;

		/// Raises the current instance to the specified BigIntegerBase power modulo n
		BigIntegerBase<T_Impl> &PowModN (const BigIntegerBase<T_Impl> &power, const BigIntegerBase<T_Impl> &n);
		/// Raises the current instance to the specified long power modulo n
		BigIntegerBase<T_Impl> &PowModN (const long power, const BigIntegerBase<T_Impl> &n);
		/// Raises the current instance to the specified unsigned long power modulo n
		BigIntegerBase<T_Impl> &PowModN (const unsigned long power, const BigIntegerBase<T_Impl> &n);
		/// Raises the current instance to the specified int power modulo n
		BigIntegerBase<T_Impl> &PowModN (const int power, const BigIntegerBase<T_Impl> &n);
		/// Raises the current instance to the specified unsigned int power modulo n
		BigIntegerBase<T_Impl> &PowModN (const unsigned int power, const BigIntegerBase<T_Impl> &n);

		/// Computes the integer raised to the specified BigIntegerBase power modulo n
		BigIntegerBase<T_Impl> GetPowModN (const BigIntegerBase<T_Impl> &power, const BigIntegerBase<T_Impl> &n) const;
		/// Computes the integer raised to the specified long power modulo n
		BigIntegerBase<T_Impl> GetPowModN (const long power, const BigIntegerBase<T_Impl> &n) const;
		/// Computes the integer raised to the specified unsigned long power modulo n
		BigIntegerBase<T_Impl> GetPowModN (const unsigned long power, const BigIntegerBase<T_Impl> &n) const;
		/// Computes the integer raised to the specified int power modulo n
		BigIntegerBase<T_Impl> GetPowModN (const int power, const BigIntegerBase<T_Impl> &n) const;
		/// Computes the integer raised to the specified unsigned int power modulo n
		BigIntegerBase<T_Impl> GetPowModN (const unsigned int power, const BigIntegerBase<T_Impl> &n) const;

		/// Inverts the current instance modulo n
		BigIntegerBase<T_Impl> &InvertModN (const BigIntegerBase<T_Impl> &n);

		/// Computes the inverse modulo n
		BigIntegerBase<T_Impl> GetInverseModN (const BigIntegerBase<T_Impl> &n) const;

		/* /Utility methods */
		
		/* Static utility methods */

		/// Swaps lhs with rhs efficiently
		static void Swap (BigIntegerBase<T_Impl> &lhs, BigIntegerBase<T_Impl> &rhs);

		/// Computes the greatest common divisor of lhs and rhs
		static BigIntegerBase<T_Impl> Gcd (const BigIntegerBase<T_Impl> &lhs, const BigIntegerBase<T_Impl> &rhs);

		/// Computes the least common multiple of lhs and rhs
		static BigIntegerBase<T_Impl> Lcm (const BigIntegerBase<T_Impl> &lhs, const BigIntegerBase<T_Impl> &rhs);

		/* /Static utility methods */

		/* Conversion methods */
		
		/// Convert to std::string in the specified base
		std::string ToString (const unsigned int base = 2) const;

		/// Convert to unsigned long
		unsigned long ToUnsignedLong () const;

		/* /Conversion methods */

	private:
		/// Implementation-defined big integer variable
		typename T_Impl::BigIntegerType data;
	};

	/* Binary non-member operators */

	/// long addition binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator+ (const long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned long addition binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator+ (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// int addition binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator+ (const int lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned int addition binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator+ (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs);

	/// long subtraction binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator- (const long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned long subtraction binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator- (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// int subtraction binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator- (const int lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned int subtraction binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator- (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs);
	
	/// long multiplication binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator* (const long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned long multiplication binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator* (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// int multiplication binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator* (const int lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned int multiplication binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator* (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs);

	/// long division binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator/ (const long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned long division binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator/ (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// int division binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator/ (const int lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned int division binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator/ (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs);

	/// long modulus binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator% (const long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned long modulus binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator% (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// int modulus binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator% (const int lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned int modulus binary operator
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator% (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs);

	/// long equality binary operator
	template <typename T_Impl>
	bool operator== (const long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned long equality binary operator
	template <typename T_Impl>
	bool operator== (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// int equality binary operator
	template <typename T_Impl>
	bool operator== (const int lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned int equality binary operator
	template <typename T_Impl>
	bool operator== (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs);

	/// long inequality binary operator
	template <typename T_Impl>
	bool operator!= (const long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned long inequality binary operator
	template <typename T_Impl>
	bool operator!= (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// int inequality binary operator
	template <typename T_Impl>
	bool operator!= (const int lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned int inequality binary operator
	template <typename T_Impl>
	bool operator!= (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs);

	/// long less than binary operator
	template <typename T_Impl>
	bool operator< (const long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned long less than binary operator
	template <typename T_Impl>
	bool operator< (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// int less than binary operator
	template <typename T_Impl>
	bool operator< (const int lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned int less than binary operator
	template <typename T_Impl>
	bool operator< (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs);

	/// long less than or equal binary operator
	template <typename T_Impl>
	bool operator<= (const long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned long less than or equal binary operator
	template <typename T_Impl>
	bool operator<= (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// int less than or equal binary operator
	template <typename T_Impl>
	bool operator<= (const int lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned int less than or equal binary operator
	template <typename T_Impl>
	bool operator<= (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs);

	/// long greater than or equal binary operator
	template <typename T_Impl>
	bool operator>= (const long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned long greater than or equal binary operator
	template <typename T_Impl>
	bool operator>= (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// int greater than or equal binary operator
	template <typename T_Impl>
	bool operator>= (const int lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned int greater than or equal binary operator
	template <typename T_Impl>
	bool operator>= (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs);

	/// long greater than binary operator
	template <typename T_Impl>
	bool operator> (const long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned long greater than binary operator
	template <typename T_Impl>
	bool operator> (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs);
	/// int greater than binary operator
	template <typename T_Impl>
	bool operator> (const int lhs, const BigIntegerBase<T_Impl> &rhs);
	/// unsigned int greater than binary operator
	template <typename T_Impl>
	bool operator> (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs);

	/* /Binary non-member operators */

}//namespace Core
}//namespace SeComLib

//Separate the implementation from the declaration of template methods
#include "big_integer_base.hpp"

#endif//BIG_INTEGER_BASE_HEADER_GUARD