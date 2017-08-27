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
@file core/big_integer_base.hpp
@brief Implementation of class BigIntegerBase. To be included in big_integer_base.h
@details Template class for adding syntactic sugar to big integer operations.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef BIG_INTEGER_BASE_IMPLEMENTATION_GUARD
#define BIG_INTEGER_BASE_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Core {
	/* Constructors */

	/**
	Initializes the current instance.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl>::BigIntegerBase () {
		T_Impl::Initialize(*this);
	}

	/**
	@param input BigIntegerBase reference
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl>::BigIntegerBase (const BigIntegerBase<T_Impl> &input) {
		T_Impl::Initialize(*this, input);
	}

	/**
	@param input long value
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl>::BigIntegerBase (const long input) {
		T_Impl::Initialize(*this, input);
	}

	/**
	@param input unsigned long value
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl>::BigIntegerBase (const unsigned long input) {
		T_Impl::Initialize(*this, input);
	}

	/**
	@param input int value
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl>::BigIntegerBase (const int input) {
		T_Impl::Initialize(*this, static_cast<long>(input));
	}

	/**
	@param input unsigned int value
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl>::BigIntegerBase (const unsigned int input) {
		T_Impl::Initialize(*this, static_cast<unsigned long>(input));
	}

	/**
	@param input double value
	@param scaling the scaling for input
	@param truncate by default, after scaling, the remaining decimals are rounded to the nearest integer. Setting this to true discards them
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl>::BigIntegerBase (const double input, const BigIntegerBase<T_Impl> &scaling, const bool truncate) {
		T_Impl::Initialize(*this, input, scaling, truncate);
	}

	/**
	@param input double value
	@param numberOfDigits the number of digits to shift to the left of the decimal point of input before initializing the current instance
	@param truncate by default, after scaling, the remaining decimals are rounded to the nearest integer. Setting this to true discards them
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl>::BigIntegerBase (const double input, const unsigned int numberOfDigits, const bool truncate) {
		T_Impl::Initialize(*this, input, numberOfDigits, truncate);
	}

	/**
	Please see the implementation for details regarding the way the base parameter is used.

	@param input input string
	@param base the base in which the input number is represented (defaults to 0)
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl>::BigIntegerBase (const std::string &input, const int base) {
		T_Impl::Initialize(*this, input, base);
	}

	/* /Constructors */

	/**
	Destroys the current instance.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl>::~BigIntegerBase () {
		T_Impl::Destroy(*this);
	}

	/* Operator overloading */

	/**
	Gracefully handles self assignment.

	@param input BigIntegerBase reference
	@return A reference to the current instance.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator= (const BigIntegerBase<T_Impl> &input) {
		T_Impl::Set(*this, input);
		return *this;
	}

	/**
	@param input long value
	@return A reference to the current instance.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator= (const long input) {
		T_Impl::Set(*this, input);
		return *this;
	}

	/**
	@param input unsigned long value
	@return A reference to the current instance.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator= (const unsigned long input) {
		T_Impl::Set(*this, input);
		return *this;
	}

	/**
	@param input int value
	@return A reference to the current instance.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator= (const int input) {
		T_Impl::Set(*this, static_cast<long>(input));
		return *this;
	}

	/**
	@param input unsigned int value
	@return A reference to the current instance.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator= (const unsigned int input) {
		T_Impl::Set(*this, static_cast<unsigned long>(input));
		return *this;
	}

	/**
	@return A copy of the current instance.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator+ () const {
		BigIntegerBase<T_Impl> output(*this);
		return output;
	}

	/**
	@return A copy of the current instance, having the sign inverted.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator- () const {
		BigIntegerBase<T_Impl> output;

		T_Impl::InvertSign(output, *this);

		return output;
	}

	/**
	@return A reference to the current instance incremented by one.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator++ () {
		T_Impl::Add(*this, *this, 1L);
		return *this;
	}

	/**
	@return A copy of the current instance before incrementing it by one.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator++ (int) {
		BigIntegerBase<T_Impl> output(*this);

		T_Impl::Add(*this, *this, 1L);

		return output;
	}

	/**
	@return A reference to the current instance decremented by one.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator-- () {
		T_Impl::Subtract(*this, *this, 1L);
		return *this;
	}

	/**
	@return A copy of the current instance before decrementing it by one.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator-- (int) {
		BigIntegerBase<T_Impl> output(*this);

		T_Impl::Subtract(*this, *this, 1L);

		return output;
	}

	/**
	@param input BigIntegerBase reference
	@return A new instance containing the sum.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator+ (const BigIntegerBase<T_Impl> &input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Add(output, *this, input);

		return output;
	}

	/**
	@param input long value
	@return A new instance containing the sum.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator+ (const long input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Add(output, *this, input);

		return output;
	}

	/**
	@param input unsigned long value
	@return A new instance containing the sum.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator+ (const unsigned long input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Add(output, *this, input);

		return output;
	}

	/**
	@param input int value
	@return A new instance containing the sum.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator+ (const int input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Add(output, *this, static_cast<long>(input));

		return output;
	}

	/**
	@param input unsigned int value
	@return A new instance containing the sum.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator+ (const unsigned int input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Add(output, *this, static_cast<unsigned long>(input));

		return output;
	}

	/**
	@param input BigIntegerBase reference
	@return A reference to the current instance containing the sum.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator+= (const BigIntegerBase<T_Impl> &input) {
		T_Impl::Add(*this, *this, input);
		return *this;
	}

	/**
	@param input long value
	@return A reference to the current instance containing the sum.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator+= (const long input) {
		T_Impl::Add(*this, *this, input);
		return *this;
	}

	/**
	@param input unsigned long value
	@return A reference to the current instance containing the sum.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator+= (const unsigned long input) {
		T_Impl::Add(*this, *this, input);
		return *this;
	}

	/**
	@param input int value
	@return A reference to the current instance containing the sum.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator+= (const int input) {
		T_Impl::Add(*this, *this, static_cast<long>(input));
		return *this;
	}

	/**
	@param input unsigned int value
	@return A reference to the current instance containing the sum.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator+= (const unsigned int input) {
		T_Impl::Add(*this, *this, static_cast<unsigned long>(input));
		return *this;
	}

	/**
	@param input BigIntegerBase reference
	@return A new instance containing the difference.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator- (const BigIntegerBase<T_Impl> &input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Subtract(output, *this, input);

		return output;
	}

	/**
	@param input long value
	@return A new instance containing the difference.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator- (const long input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Subtract(output, *this, input);

		return output;
	}

	/**
	@param input unsigned long value
	@return A new instance containing the difference.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator- (const unsigned long input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Subtract(output, *this, input);

		return output;
	}

	/**
	@param input int value
	@return A new instance containing the difference.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator- (const int input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Subtract(output, *this, static_cast<long>(input));

		return output;
	}

	/**
	@param input unsigned int value
	@return A new instance containing the difference.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator- (const unsigned int input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Subtract(output, *this, static_cast<unsigned long>(input));

		return output;
	}

	/**
	@param input BigIntegerBase reference
	@return A reference to the current instance containing the difference.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator-= (const BigIntegerBase<T_Impl> &input) {
		T_Impl::Subtract(*this, *this, input);
		return *this;
	}

	/**
	@param input long value
	@return A reference to the current instance containing the difference.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator-= (const long input) {
		T_Impl::Subtract(*this, *this, input);
		return *this;
	}

	/**
	@param input unsigned long value
	@return A reference to the current instance containing the difference.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator-= (const unsigned long input) {
		T_Impl::Subtract(*this, *this, input);
		return *this;
	}

	/**
	@param input int value
	@return A reference to the current instance containing the difference.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator-= (const int input) {
		T_Impl::Subtract(*this, *this, static_cast<long>(input));
		return *this;
	}

	/**
	@param input unsigned int value
	@return A reference to the current instance containing the difference.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator-= (const unsigned int input) {
		T_Impl::Subtract(*this, *this, static_cast<unsigned long>(input));
		return *this;
	}

	/**
	@param input BigIntegerBase reference
	@return A new instance containing the product.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator* (const BigIntegerBase<T_Impl> &input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Multiply(output, *this, input);

		return output;
	}

	/**
	@param input long value
	@return A new instance containing the product.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator* (const long input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Multiply(output, *this, input);

		return output;
	}

	/**
	@param input unsigned long value
	@return A new instance containing the product.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator* (const unsigned long input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Multiply(output, *this, input);

		return output;
	}

	/**
	@param input int value
	@return A new instance containing the product.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator* (const int input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Multiply(output, *this, static_cast<long>(input));

		return output;
	}

	/**
	@param input unsigned int value
	@return A new instance containing the product.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator* (const unsigned int input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Multiply(output, *this, static_cast<unsigned long>(input));

		return output;
	}

	/**
	@param input BigIntegerBase reference
	@return A reference to the current instance containing the product.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator*= (const BigIntegerBase<T_Impl> &input) {
		T_Impl::Multiply(*this, *this, input);
		return *this;
	}

	/**
	@param input long value
	@return A reference to the current instance containing the product.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator*= (const long input) {
		T_Impl::Multiply(*this, *this, input);
		return *this;
	}

	/**
	@param input unsigned long value
	@return A reference to the current instance containing the product.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator*= (const unsigned long input) {
		T_Impl::Multiply(*this, *this, input);
		return *this;
	}

	/**
	@param input int value
	@return A reference to the current instance containing the product.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator*= (const int input) {
		T_Impl::Multiply(*this, *this, static_cast<long>(input));
		return *this;
	}

	/**
	@param input unsigned int value
	@return A reference to the current instance containing the product.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator*= (const unsigned int input) {
		T_Impl::Multiply(*this, *this, static_cast<unsigned long>(input));
		return *this;
	}

	/**
	@param input BigIntegerBase reference
	@return A new instance containing the quotient.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator/ (const BigIntegerBase<T_Impl> &input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Divide(output, *this, input);

		return output;
	}

	/**
	@param input long value
	@return A new instance containing the quotient.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator/ (const long input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Divide(output, *this, input);

		return output;
	}

	/**
	@param input unsigned long value
	@return A new instance containing the quotient.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator/ (const unsigned long input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Divide(output, *this, input);

		return output;
	}

	/**
	@param input int value
	@return A new instance containing the quotient.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator/ (const int input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Divide(output, *this, static_cast<long>(input));

		return output;
	}

	/**
	@param input unsigned int value
	@return A new instance containing the quotient.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator/ (const unsigned int input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Divide(output, *this, static_cast<unsigned long>(input));

		return output;
	}

	/**
	@param input BigIntegerBase reference
	@return A reference to the current instance containing the quotient.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator/= (const BigIntegerBase<T_Impl> &input) {
		T_Impl::Divide(*this, *this, input);
		return *this;
	}

	/**
	@param input long value
	@return A reference to the current instance containing the quotient.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator/= (const long input) {
		T_Impl::Divide(*this, *this, input);
		return *this;
	}

	/**
	@param input unsigned long value
	@return A reference to the current instance containing the quotient.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator/= (const unsigned long input) {
		T_Impl::Divide(*this, *this, input);
		return *this;
	}

	/**
	@param input int value
	@return A reference to the current instance containing the quotient.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator/= (const int input) {
		T_Impl::Divide(*this, *this, static_cast<long>(input));
		return *this;
	}

	/**
	@param input unsigned int value
	@return A reference to the current instance containing the quotient.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator/= (const unsigned int input) {
		T_Impl::Divide(*this, *this, static_cast<unsigned long>(input));
		return *this;
	}

	/**
	@param input BigIntegerBase reference
	@return A new instance containing the remainder.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator% (const BigIntegerBase<T_Impl> &input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Modulo(output, *this, input);

		return output;
	}

	/**
	@param input long value
	@return A new instance containing the remainder.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator% (const long input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Modulo(output, *this, input);

		return output;
	}

	/**
	@param input unsigned long value
	@return A new instance containing the remainder.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator% (const unsigned long input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Modulo(output, *this, input);

		return output;
	}

	/**
	@param input int value
	@return A new instance containing the remainder.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator% (const int input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Modulo(output, *this, static_cast<long>(input));

		return output;
	}

	/**
	@param input unsigned int value
	@return A new instance containing the remainder.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator% (const unsigned int input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Modulo(output, *this, static_cast<unsigned long>(input));

		return output;
	}

	/**
	@param input BigIntegerBase reference
	@return A reference to the current instance containing the remainder.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator%= (const BigIntegerBase<T_Impl> &input) {
		T_Impl::Modulo(*this, *this, input);
		return *this;
	}

	/**
	@param input long value
	@return A reference to the current instance containing the remainder.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator%= (const long input) {
		T_Impl::Modulo(*this, *this, input);
		return *this;
	}

	/**
	@param input unsigned long value
	@return A reference to the current instance containing the remainder.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator%= (const unsigned long input) {
		T_Impl::Modulo(*this, *this, input);
		return *this;
	}

	/**
	@param input int value
	@return A reference to the current instance containing the remainder.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator%= (const int input) {
		T_Impl::Modulo(*this, *this, static_cast<long>(input));
		return *this;
	}

	/**
	@param input unsigned int value
	@return A reference to the current instance containing the remainder.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator%= (const unsigned int input) {
		T_Impl::Modulo(*this, *this, static_cast<unsigned long>(input));
		return *this;
	}

	/**
	@param input BigIntegerBase reference
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator== (const BigIntegerBase<T_Impl> &input) const {
		return T_Impl::Compare(*this, input) == 0 ? true : false;
	}

	/**
	@param input long value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator== (const long input) const {
		return T_Impl::Compare(*this, input) == 0 ? true : false;
	}

	/**
	@param input unsigned long value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator== (const unsigned long input) const {
		return T_Impl::Compare(*this, input) == 0 ? true : false;
	}

	/**
	@param input int value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator== (const int input) const {
		return T_Impl::Compare(*this, static_cast<long>(input)) == 0 ? true : false;
	}

	/**
	@param input unsigned int value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator== (const unsigned int input) const {
		return T_Impl::Compare(*this, static_cast<unsigned long>(input)) == 0 ? true : false;
	}

	/**
	@param input BigIntegerBase reference
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator!= (const BigIntegerBase<T_Impl> &input) const {
		return T_Impl::Compare(*this, input) != 0 ? true : false;
	}

	/**
	@param input long value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator!= (const long input) const {
		return T_Impl::Compare(*this, input) != 0 ? true : false;
	}

	/**
	@param input unsigned long value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator!= (const unsigned long input) const {
		return T_Impl::Compare(*this, input) != 0 ? true : false;
	}

	/**
	@param input int value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator!= (const int input) const {
		return T_Impl::Compare(*this, static_cast<long>(input)) != 0 ? true : false;
	}

	/**
	@param input unsigned int value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator!= (const unsigned int input) const {
		return T_Impl::Compare(*this, static_cast<unsigned long>(input)) != 0 ? true : false;
	}

	/**
	@param input BigIntegerBase reference
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator< (const BigIntegerBase<T_Impl> &input) const {
		return T_Impl::Compare(*this, input) < 0 ? true : false;
	}

	/**
	@param input long value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator< (const long input) const {
		return T_Impl::Compare(*this, input) < 0 ? true : false;
	}

	/**
	@param input unsigned long value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator< (const unsigned long input) const {
		return T_Impl::Compare(*this, input) < 0 ? true : false;
	}

	/**
	@param input int value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator< (const int input) const {
		return T_Impl::Compare(*this, static_cast<long>(input)) < 0 ? true : false;
	}

	/**
	@param input unsigned int value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator< (const unsigned int input) const {
		return T_Impl::Compare(*this, static_cast<unsigned long>(input)) < 0 ? true : false;
	}

	/**
	@param input BigIntegerBase reference
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator<= (const BigIntegerBase<T_Impl> &input) const {
		return T_Impl::Compare(*this, input) <= 0 ? true : false;
	}

	/**
	@param input long value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator<= (const long input) const {
		return T_Impl::Compare(*this, input) <= 0 ? true : false;
	}

	/**
	@param input unsigned long value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator<= (const unsigned long input) const {
		return T_Impl::Compare(*this, input) <= 0 ? true : false;
	}

	/**
	@param input int value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator<= (const int input) const {
		return T_Impl::Compare(*this, static_cast<long>(input)) <= 0 ? true : false;
	}

	/**
	@param input unsigned int value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator<= (const unsigned int input) const {
		return T_Impl::Compare(*this, static_cast<unsigned long>(input)) <= 0 ? true : false;
	}

	/**
	@param input BigIntegerBase reference
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator>= (const BigIntegerBase<T_Impl> &input) const {
		return T_Impl::Compare(*this, input) >= 0 ? true : false;
	}

	/**
	@param input long value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator>= (const long input) const {
		return T_Impl::Compare(*this, input) >= 0 ? true : false;
	}

	/**
	@param input unsigned long value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator>= (const unsigned long input) const {
		return T_Impl::Compare(*this, input) >= 0 ? true : false;
	}

	/**
	@param input int value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator>= (const int input) const {
		return T_Impl::Compare(*this, static_cast<long>(input)) >= 0 ? true : false;
	}

	/**
	@param input unsigned int value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator>= (const unsigned int input) const {
		return T_Impl::Compare(*this, static_cast<unsigned long>(input)) >= 0 ? true : false;
	}

	/**
	@param input BigIntegerBase reference
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator> (const BigIntegerBase<T_Impl> &input) const {
		return T_Impl::Compare(*this, input) > 0 ? true : false;
	}

	/**
	@param input long value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator> (const long input) const {
		return T_Impl::Compare(*this, input) > 0 ? true : false;
	}

	/**
	@param input unsigned long value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator> (const unsigned long input) const {
		return T_Impl::Compare(*this, input) > 0 ? true : false;
	}

	/**
	@param input int value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator> (const int input) const {
		return T_Impl::Compare(*this, static_cast<long>(input)) > 0 ? true : false;
	}

	/**
	@param input unsigned int value
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::operator> (const unsigned int input) const {
		return T_Impl::Compare(*this, static_cast<unsigned long>(input)) > 0 ? true : false;
	}

	/**
	@param input unsigned long value
	@return A new instance containing the bitwise right shift.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator>> (const unsigned long input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::RightShift(output, *this, input);

		return output;
	}

	/**
	@param input unsigned long value
	@return A reference to the current instance containing the bitwise right shift.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator>>= (const unsigned long input) {
		T_Impl::RightShift(*this, *this, input);
		return *this;
	}

	/**
	@param input unsigned long value
	@return A new instance containing the bitwise left shift.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator<< (const unsigned long input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::LeftShift(output, *this, input);

		return output;
	}

	/**
	@param input unsigned long value
	@return A reference to the current instance containing the bitwise right shift.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator<<= (const unsigned long input) {
		T_Impl::LeftShift(*this, *this, input);
		return *this;
	}

	/**
	@return A new instance containing one's complement of the current instance.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator~ () const {
		BigIntegerBase<T_Impl> output;

		T_Impl::InvertBits(output, *this);

		return output;
	}

	/**
	@param input unsigned long value
	@return A new instance containing the bitwise AND.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator& (const BigIntegerBase<T_Impl> &input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::BitwiseAnd(output, *this, input);

		return output;
	}

	/**
	@param input unsigned long value
	@return A reference to the current instance containing the bitwise AND.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator&= (const BigIntegerBase<T_Impl> &input) {
		T_Impl::BitwiseAnd(*this, *this, input);
		return *this;
	}

	/**
	@param input unsigned long value
	@return A new instance containing the bitwise inclusive OR.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator| (const BigIntegerBase<T_Impl> &input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::BitwiseOr(output, *this, input);

		return output;
	}

	/**
	@param input unsigned long value
	@return A reference to the current instance containing the bitwise inclusive OR.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator|= (const BigIntegerBase<T_Impl> &input) {
		T_Impl::BitwiseOr(*this, *this, input);
		return *this;
	}

	/**
	@param input unsigned long value
	@return A new instance containing the bitwise exclusive OR.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::operator^ (const BigIntegerBase<T_Impl> &input) const {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::BitwiseXor(output, *this, input);

		return output;
	}

	/**
	@param input unsigned long value
	@return A reference to the current instance containing the bitwise exclusive OR.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::operator^= (const BigIntegerBase<T_Impl> &input) {
		T_Impl::BitwiseXor(*this, *this, input);
		return *this;
	}

	/* /Operator overloading */


	/* Utility methods */

	/**
	@return A new instance containing the next prime number after the current instance.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::GetNextPrime () const {
		BigIntegerBase<T_Impl> output;

		T_Impl::GetNextPrime(output, *this);

		return output;
	}

	/**
	@return The test result (bool).
	*/
	template <typename T_Impl>
	inline bool BigIntegerBase<T_Impl>::IsPrime () const {
		return T_Impl::IsPrime(*this);
	}

	/**
	@param index the position at which to set the bit in the current instance. Indexing starts from 0
	@return A reference to the current instance having the specified bit set.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::SetBit (const size_t index) {
		T_Impl::SetBit(*this, index);
		return *this;
	}

	/**
	@param index the position at which to get the bit in the current instance. Indexing starts from 0
	@return An int containing either 1 or 0.
	*/
	template <typename T_Impl>
	inline int BigIntegerBase<T_Impl>::GetBit (const size_t index) const {
		return T_Impl::GetBit(*this, index);
	}

	/**
	Please note that size(x) = size(-x)! I'm not sure if this is always the desired behavior...

	@param base the base in which to represent the number (defaults to 2)
	@return The size of the number in the specified base.
	*/
	template <typename T_Impl>
	inline size_t BigIntegerBase<T_Impl>::GetSize (const unsigned int base) const {
		return T_Impl::GetSize(*this, base);
	}

	/**
	@return A reference to the absolute value of the current instance.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::Abs () {
		T_Impl::Abs(*this, *this);
		return *this;
	}

	/**
	@return A new instance containing the absolute value of the integer.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::GetAbs () const {
		BigIntegerBase<T_Impl> output;

		T_Impl::Abs(output, *this);

		return output;
	}

	/**
	@param power the exponent
	@return A reference to the current instance raised to the specified power.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::Pow (const BigIntegerBase<T_Impl> &power) {
		T_Impl::Pow(*this, *this, power);
		return *this;
	}

	/**
	@param power the exponent
	@return A reference to the current instance raised to the specified power.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::Pow (const long power) {
		T_Impl::Pow(*this, *this, power);
		return *this;
	}

	/**
	@param power the exponent
	@return A reference to the current instance raised to the specified power.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::Pow (const unsigned long power) {
		T_Impl::Pow(*this, *this, power);
		return *this;
	}

	/**
	@param power the exponent
	@return A reference to the current instance raised to the specified power.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::Pow (const int power) {
		T_Impl::Pow(*this, *this, static_cast<long>(power));
		return *this;
	}

	/**
	@param power the exponent
	@return A reference to the current instance raised to the specified power.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::Pow (const unsigned int power) {
		T_Impl::Pow(*this, *this, static_cast<unsigned long>(power));
		return *this;
	}

	/**
	@param power the exponent
	@return A new instance containing the integer raised to the specified power.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::GetPow (const BigIntegerBase<T_Impl> &power) const {
		BigIntegerBase<T_Impl> output;

		T_Impl::Pow(output, *this, power);

		return output;
	}

	/**
	@param power the exponent
	@return A new instance containing the integer raised to the specified power.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::GetPow (const long power) const {
		BigIntegerBase<T_Impl> output;

		T_Impl::Pow(output, *this, power);

		return output;
	}

	/**
	@param power the exponent
	@return A new instance containing the integer raised to the specified power.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::GetPow (const unsigned long power) const {
		BigIntegerBase<T_Impl> output;

		T_Impl::Pow(output, *this, power);

		return output;
	}

	/**
	@param power the exponent
	@return A new instance containing the integer raised to the specified power.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::GetPow (const int power) const {
		BigIntegerBase<T_Impl> output;

		T_Impl::Pow(output, *this, static_cast<long>(power));

		return output;
	}

	/**
	@param power the exponent
	@return A new instance containing the integer raised to the specified power.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::GetPow (const unsigned int power) const {
		BigIntegerBase<T_Impl> output;

		T_Impl::Pow(output, *this, static_cast<unsigned long>(power));

		return output;
	}

	/**
	@param power the exponent
	@param n the modulus
	@return A reference to the current instance raised to the specified power modulo n.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::PowModN (const BigIntegerBase<T_Impl> &power, const BigIntegerBase<T_Impl> &n) {
		T_Impl::PowModN(*this, *this, power, n);
		return *this;
	}

	/**
	@param power the exponent
	@param n the modulus
	@return A reference to the current instance raised to the specified power modulo n.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::PowModN (const long power, const BigIntegerBase<T_Impl> &n) {
		T_Impl::PowModN(*this, *this, power, n);
		return *this;
	}

	/**
	@param power the exponent
	@param n the modulus
	@return A reference to the current instance raised to the specified power modulo n.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::PowModN (const unsigned long power, const BigIntegerBase<T_Impl> &n) {
		T_Impl::PowModN(*this, *this, power, n);
		return *this;
	}

	/**
	@param power the exponent
	@param n the modulus
	@return A reference to the current instance raised to the specified power modulo n.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::PowModN (const int power, const BigIntegerBase<T_Impl> &n) {
		T_Impl::PowModN(*this, *this, static_cast<long>(power), n);
		return *this;
	}

	/**
	@param power the exponent
	@param n the modulus
	@return A reference to the current instance raised to the specified power modulo n.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::PowModN (const unsigned int power, const BigIntegerBase<T_Impl> &n) {
		T_Impl::PowModN(*this, *this, static_cast<unsigned long>(power), n);
		return *this;
	}

	/**
	@param power the exponent
	@param n the modulus
	@return A new instance containing the integer raised to the specified power modulo n.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::GetPowModN (const BigIntegerBase<T_Impl> &power, const BigIntegerBase<T_Impl> &n) const {
		BigIntegerBase<T_Impl> output;

		T_Impl::PowModN(output, *this, power, n);

		return output;
	}

	/**
	@param power the exponent
	@param n the modulus
	@return A new instance containing the integer raised to the specified power modulo n.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::GetPowModN (const long power, const BigIntegerBase<T_Impl> &n) const {
		BigIntegerBase<T_Impl> output;

		T_Impl::PowModN(output, *this, power, n);

		return output;
	}

	/**
	@param power the exponent
	@param n the modulus
	@return A new instance containing the integer raised to the specified power modulo n.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::GetPowModN (const unsigned long power, const BigIntegerBase<T_Impl> &n) const {
		BigIntegerBase<T_Impl> output;

		T_Impl::PowModN(output, *this, power, n);

		return output;
	}

	/**
	@param power the exponent
	@param n the modulus
	@return A new instance containing the integer raised to the specified power modulo n.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::GetPowModN (const int power, const BigIntegerBase<T_Impl> &n) const {
		BigIntegerBase<T_Impl> output;

		T_Impl::PowModN(output, *this, static_cast<long>(power), n);

		return output;
	}

	/**
	@param power the exponent
	@param n the modulus
	@return A new instance containing the integer raised to the specified power modulo n.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::GetPowModN (const unsigned int power, const BigIntegerBase<T_Impl> &n) const {
		BigIntegerBase<T_Impl> output;

		T_Impl::PowModN(output, *this, static_cast<unsigned long>(power), n);

		return output;
	}

	/**
	@param n the modulus
	@return A reference to the current instance inversed modulo n.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> &BigIntegerBase<T_Impl>::InvertModN (const BigIntegerBase<T_Impl> &n) {
		T_Impl::InvertModN(*this, *this, n);
		return *this;
	}

	/**
	@param n the modulus
	@return A new instance containing the integer inversed modulo n.
	*/
	template <typename T_Impl>
	inline BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::GetInverseModN (const BigIntegerBase<T_Impl> &n) const {
		BigIntegerBase<T_Impl> output;

		T_Impl::InvertModN(output, *this, n);

		return output;
	}

	/* /Utility methods */

	/* Static utility methods */

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	*/
	template <typename T_Impl>
	void BigIntegerBase<T_Impl>::Swap (BigIntegerBase<T_Impl> &lhs, BigIntegerBase<T_Impl> &rhs) {
		T_Impl::Swap(lhs, rhs);
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The greatest common divisor of lhs and rhs
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::Gcd (const BigIntegerBase<T_Impl> &lhs, const BigIntegerBase<T_Impl> &rhs) {
		BigIntegerBase<T_Impl> output;

		T_Impl::Gcd(output, lhs, rhs);

		return output;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The least common multiple of lhs and rhs
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> BigIntegerBase<T_Impl>::Lcm (const BigIntegerBase<T_Impl> &lhs, const BigIntegerBase<T_Impl> &rhs) {
		BigIntegerBase<T_Impl> output;

		T_Impl::Lcm(output, lhs, rhs);

		return output;
	}

	/* /Static utility methods */

	/* Conversion methods */

	/**
	@param base the base in which to represent the number before transforming it to string (defaults to 2)
	@return A std::string representation of the current instance in the specified base.
	*/
	template <typename T_Impl>
	std::string BigIntegerBase<T_Impl>::ToString (const unsigned int base) const {
		return T_Impl::ToString(*this, base);
	}

	/**
	@return An unsigned long containing the integer.
	*/
	template <typename T_Impl>
	unsigned long BigIntegerBase<T_Impl>::ToUnsignedLong () const {
		return T_Impl::ToUnsignedLong(*this);
	}

	/* /Conversion methods */

	/* Binary non-member operators */

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator+ (const long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs + lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator+ (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs + lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator+ (const int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs + lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator+ (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs + lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator- (const long lhs, const BigIntegerBase<T_Impl> &rhs) {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Subtract(output, BigIntegerBase<T_Impl>(lhs), rhs);

		return output;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator- (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs) {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Subtract(output, BigIntegerBase<T_Impl>(lhs), rhs);

		return output;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator- (const int lhs, const BigIntegerBase<T_Impl> &rhs) {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Subtract(output, BigIntegerBase<T_Impl>(lhs), rhs);

		return output;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator- (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs) {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Subtract(output, BigIntegerBase<T_Impl>(lhs), rhs);

		return output;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator* (const long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs * lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator* (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs * lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator* (const int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs * lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator* (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs * lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator/ (const long lhs, const BigIntegerBase<T_Impl> &rhs) {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Divide(output, BigIntegerBase<T_Impl>(lhs), rhs);

		return output;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator/ (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs) {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Divide(output, BigIntegerBase<T_Impl>(lhs), rhs);

		return output;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator/ (const int lhs, const BigIntegerBase<T_Impl> &rhs) {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Divide(output, BigIntegerBase<T_Impl>(lhs), rhs);

		return output;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator/ (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs) {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Divide(output, BigIntegerBase<T_Impl>(lhs), rhs);

		return output;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator% (const long lhs, const BigIntegerBase<T_Impl> &rhs) {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Modulo(output, BigIntegerBase<T_Impl>(lhs), rhs);

		return output;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator% (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs) {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Modulo(output, BigIntegerBase<T_Impl>(lhs), rhs);

		return output;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator% (const int lhs, const BigIntegerBase<T_Impl> &rhs) {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Modulo(output, BigIntegerBase<T_Impl>(lhs), rhs);

		return output;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return A new BigInteger instance containing the result.
	*/
	template <typename T_Impl>
	BigIntegerBase<T_Impl> operator% (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs) {
		BigIntegerBase<T_Impl> output;
		
		T_Impl::Modulo(output, BigIntegerBase<T_Impl>(lhs), rhs);

		return output;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator== (const long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs == lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator== (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs == lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator== (const int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs == lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator== (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs == lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator!= (const long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs != lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator!= (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs != lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator!= (const int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs != lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator!= (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs != lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator< (const long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs > lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator< (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs > lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator< (const int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs > lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator< (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs > lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator<= (const long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs >= lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator<= (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs >= lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator<= (const int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs >= lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator<= (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs >= lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator>= (const long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs <= lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator>= (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs <= lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator>= (const int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs <= lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator>= (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs <= lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator> (const long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs < lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator> (const unsigned long lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs < lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator> (const int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs < lhs;
	}

	/**
	@param lhs left hand side operand
	@param rhs right hand side operand
	@return The comparison result (bool).
	*/
	template <typename T_Impl>
	bool operator> (const unsigned int lhs, const BigIntegerBase<T_Impl> &rhs) {
		return rhs < lhs;
	}

	/* /Binary non-member operators */

}//namespace Core
}//namespace SeComLib

#endif//BIG_INTEGER_BASE_IMPLEMENTATION_GUARD