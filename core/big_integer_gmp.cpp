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
@file core/big_integer_gmp.cpp
@brief Implementation of class BigIntegerGmp.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "big_integer_gmp.h"

namespace SeComLib {
namespace Core {
	/**
	Calls the GMP mpz_init function. From the GMP Manual:
	<blockquote>
	Function: void mpz_init (mpz_t x)

    Initialize x, and set its value to 0.
	</blockquote>
	@param input uninitialized BigInteger
	*/
	void BigIntegerGmp::Initialize (BigIntegerBase<BigIntegerGmp> &input) {
		mpz_init(input.data);
	}
	
	/**
	@param input uninitialized BigInteger
	@param value BigInteger value 
	*/
	void BigIntegerGmp::Initialize (BigIntegerBase<BigIntegerGmp> &input, const BigIntegerBase<BigIntegerGmp> &value) {
		mpz_init_set(input.data, value.data);
	}
	
	/**
	@param input uninitialized BigInteger
	@param value long value 
	*/
	void BigIntegerGmp::Initialize (BigIntegerBase<BigIntegerGmp> &input, const long value) {
		mpz_init_set_si(input.data, value);
	}
	
	/**
	@param input uninitialized BigInteger
	@param value unsigned long value 
	*/
	void BigIntegerGmp::Initialize (BigIntegerBase<BigIntegerGmp> &input, const unsigned long value) {
		mpz_init_set_ui(input.data, value);
	}
	
	/**
	Initializes the internal mpz_t instance and sets it to the specified value scaled by the specified factor.

	Uses an intermediary mpf_t to scale and round the input value.

	@param input uninitialized BigInteger
	@param value double value
	@param scaling scaling factor
	@param truncate by default, after scaling, the remaining decimals are rounded to the nearest integer. Setting this to true discards them
	*/
	void BigIntegerGmp::Initialize (BigIntegerBase<BigIntegerGmp> &input, const double value, const BigIntegerBase<BigIntegerGmp> &scaling, const bool truncate) {
		mpz_init(input.data);

		mpf_set_default_prec(1024);//1024 is the default value and it should be more than enough

		//auxiliary big float used for applying scaling and rounding before exporting it to input.data
		mpf_t tempFloat;
		//we can't multiply mpf_t with mpz_t, so we need a temporary mpf_t for the scaling
		mpf_t tempScaling;
		//contains the value 0.5, used for the rounding procedure
		mpf_t zeroPointFive;

		//set the value
		mpf_init_set_d(tempFloat, value);
		
		//gmp_printf ("Value: %.*Ff\r\n", 30, tempFloat);

		//set the scaling
		mpf_init(tempScaling);
		mpf_set_z(tempScaling, scaling.data);

		//set 0.5
		mpf_init_set_d(zeroPointFive, 0.5);

		//apply the scaling
		mpf_mul(tempFloat, tempFloat, tempScaling);

		if (truncate) {
			//discard decimals
			mpf_trunc(tempFloat, tempFloat);
		}
		else {
			//round the value to the nearest (positive or negative) integer
			//input < 0.0 ? ceil(input - 0.5) : floor(input + 0.5));
			if (-1 == mpf_sgn(tempFloat)) {
				mpf_sub(tempFloat, tempFloat, zeroPointFive);
				mpf_ceil(tempFloat, tempFloat);
			}
			else {
				mpf_add(tempFloat, tempFloat, zeroPointFive);
				mpf_floor(tempFloat, tempFloat);
			}
		}

		//gmp_printf ("Value: %.*Ff\r\n", 30, tempFloat);

		//finally, transfer the value to our internal data
		mpz_set_f(input.data, tempFloat);
		
		//gmp_printf ("%Zd\r\n", this->data);

		//don't forget to clean up the memory
		mpf_clear(tempFloat);
		mpf_clear(tempScaling);
		mpf_clear(zeroPointFive);
	}
	
	/**
	Initializes the internal mpz_t instance and sets it to the specified value, scaled to preserve the specified number of digits

	Uses an intermediary mpf_t to scale and round the input value.

	@param input uninitialized BigInteger
	@param value double value
	@param numberOfDigits number of digits to preserve
	@param truncate by default, after scaling, the remaining decimals are rounded to the nearest integer. Setting this to true discards them
	*/
	void BigIntegerGmp::Initialize (BigIntegerBase<BigIntegerGmp> &input, const double value, const unsigned int numberOfDigits, const bool truncate) {
		mpz_init(input.data);

		mpf_set_default_prec(1024);//1024 is the default value and it should be more than enough

		//auxiliary big float used for applying scaling and rounding before exporting it to input.data
		mpf_t tempFloat;
		//we can't multiply mpf_t with mpz_t, so we need a temporary mpf_t for the scaling
		mpf_t tempScaling;
		//contains the value 0.5, used for the rounding procedure
		mpf_t zeroPointFive;

		//set the value
		mpf_init_set_d(tempFloat, value);
		
		//gmp_printf ("Value: %.*Ff\r\n", 30, tempFloat);

		//set the scaling
		if (numberOfDigits > 0) {
			mpf_init_set_si(tempScaling, 10);
			mpf_pow_ui(tempScaling, tempScaling, numberOfDigits);
		}
		else {
			mpf_init_set_si(tempScaling, 1);
		}

		//set 0.5
		mpf_init_set_d(zeroPointFive, 0.5);

		//apply the scaling
		mpf_mul(tempFloat, tempFloat, tempScaling);

		if (truncate) {
			//discard decimals
			mpf_trunc(tempFloat, tempFloat);
		}
		else {
			//round the value to the nearest (positive or negative) integer
			//input < 0.0 ? ceil(input - 0.5) : floor(input + 0.5));
			if (-1 == mpf_sgn(tempFloat)) {
				mpf_sub(tempFloat, tempFloat, zeroPointFive);
				mpf_ceil(tempFloat, tempFloat);
			}
			else {
				mpf_add(tempFloat, tempFloat, zeroPointFive);
				mpf_floor(tempFloat, tempFloat);
			}
		}

		//gmp_printf ("Value: %.*Ff\r\n", 30, tempFloat);

		//finally, transfer the value to our internal data
		mpz_set_f(input.data, tempFloat);
		
		//gmp_printf ("%Zd\r\n", this->data);

		//don't forget to clean up the memory
		mpf_clear(tempFloat);
		mpf_clear(tempScaling);
		mpf_clear(zeroPointFive);
	}
	
	/**
	Initializes the internal mpz_t instance and sets it to the value specified by the input string in the specified base.

	Calls the GMP mpz_init_set_str function

	From the GMP Manual:
	<blockquote>
	Set the value of rop from str, a null-terminated C string in base base. White space is allowed
	in the string, and is simply ignored.

	The base may vary from 2 to 62, or if base is 0, then the leading characters are used: 0x and
	0X for hexadecimal, 0b and 0B for binary, 0 for octal, or decimal otherwise.

	For bases up to 36, case is ignored; upper-case and lower-case letters have the same value. For
	bases 37 to 62, upper-case letter represent the usual 10..35 while lower-case letter represent 36..61.

	This function returns 0 if the entire string is a valid number in base base. Otherwise it returns -1.
	</blockquote>
	@param input uninitialized BigInteger
	@param value input string
	@param base the base in which the input number is represented (defaults to 0)
	@throws std::runtime_error the input string is not a valid number in the specified base
	*/
	void BigIntegerGmp::Initialize (BigIntegerBase<BigIntegerGmp> &input, const std::string &value, const int base) {
		if (0 != mpz_init_set_str(input.data, value.c_str(), base)) {
			throw std::runtime_error("The input string is not a valid number in the specified base.");
		}
	}

	/**
	@param input initialized BigInteger
	*/
	void BigIntegerGmp::Destroy (BigIntegerBase<BigIntegerGmp> &input) {
		mpz_clear(input.data);
	}

	/**
	@param input initialized BigInteger
	@param value BigInteger value 
	*/
	void BigIntegerGmp::Set (BigIntegerBase<BigIntegerGmp> &input, const BigIntegerBase<BigIntegerGmp> &value) {
		mpz_set(input.data, value.data);
	}
	
	/**
	@param input initialized BigInteger
	@param value long value 
	*/
	void BigIntegerGmp::Set (BigIntegerBase<BigIntegerGmp> &input, const long value) {
		mpz_set_si(input.data, value);
	}
	
	/**
	@param input initialized BigInteger
	@param value unsigned long value 
	*/
	void BigIntegerGmp::Set (BigIntegerBase<BigIntegerGmp> &input, const unsigned long value) {
		mpz_set_ui(input.data, value);
	}

	/**
	@param output BigInteger instance
	@param input BigInteger instance containing the original data
	*/
	void BigIntegerGmp::InvertSign (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input) {
		mpz_neg(output.data, input.data);
	}

	/**
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side BigInteger operand
	*/
	void BigIntegerGmp::Add (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs) {
		mpz_add(output.data, lhs.data, rhs.data);
	}
	
	/**
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side long operand
	*/
	void BigIntegerGmp::Add (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const long rhs) {
		if (rhs < 0) {
			mpz_sub_ui(output.data, lhs.data, -rhs);
		}
		else {
			mpz_add_ui(output.data, lhs.data, rhs);
		}
	}
	
	/**
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side unsigned long operand
	*/
	void BigIntegerGmp::Add (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const unsigned long rhs) {
		mpz_add_ui(output.data, lhs.data, rhs);
	}

	/**
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side BigInteger operand
	*/
	void BigIntegerGmp::Subtract (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs) {
		mpz_sub(output.data, lhs.data, rhs.data);
	}
	
	/**
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side long operand
	*/
	void BigIntegerGmp::Subtract (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const long rhs) {
		if (rhs < 0) {
			mpz_add_ui(output.data, lhs.data, -rhs);
		}
		else {
			mpz_sub_ui(output.data, lhs.data, rhs);
		}
	}
	
	/**
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side unsigned long operand
	*/
	void BigIntegerGmp::Subtract (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const unsigned long rhs) {
		mpz_sub_ui(output.data, lhs.data, rhs);
	}

	/**
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side BigInteger operand
	*/
	void BigIntegerGmp::Multiply (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs) {
		mpz_mul(output.data, lhs.data, rhs.data);
	}
	
	/**
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side long operand
	*/
	void BigIntegerGmp::Multiply (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const long rhs) {
		mpz_mul_si(output.data, lhs.data, rhs);
	}
	
	/**
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side unsigned long operand
	*/
	void BigIntegerGmp::Multiply (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const unsigned long rhs) {
		mpz_mul_ui(output.data, lhs.data, rhs);
	}

	/**
	Calls the GMP mpz_tdiv_q function, which applies "truncate" rounding after performing division.

	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side BigInteger operand
	*/
	void BigIntegerGmp::Divide (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs) {
		mpz_tdiv_q(output.data, lhs.data, rhs.data);
	}
	
	/**
	Calls the GMP mpz_tdiv_q_ui function, which applies "truncate" rounding after performing division.

	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side long operand
	*/
	void BigIntegerGmp::Divide (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const long rhs) {
		if (rhs < 0) {
			mpz_tdiv_q_ui(output.data, lhs.data, -rhs);
			mpz_neg(output.data, output.data);
		}
		else {
			mpz_tdiv_q_ui(output.data, lhs.data, rhs);
		}
	}
	
	/**
	Calls the GMP mpz_tdiv_q_ui function, which applies "truncate" rounding after performing division.

	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side unsigned long operand
	*/
	void BigIntegerGmp::Divide (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const unsigned long rhs) {
		mpz_tdiv_q_ui(output.data, lhs.data, rhs);
	}

	/**
	Calls the GMP mpz_mod function. From the GMP Manual:

	<blockquote>
	Set r to n mod d. The sign of the divisor is ignored; the result is always non-negative.
	</blockquote>
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side BigInteger operand
	*/
	void BigIntegerGmp::Modulo (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs) {
		mpz_mod(output.data, lhs.data, rhs.data);
	}
	
	/**
	Calls the GMP mpz_mod function. From the GMP Manual:

	<blockquote>
	Set r to n mod d. The sign of the divisor is ignored; the result is always non-negative.
	</blockquote>
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side long operand
	*/
	void BigIntegerGmp::Modulo (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const long rhs) {
		if (rhs < 0) {
			mpz_mod_ui(output.data, lhs.data, -rhs);
			mpz_neg(output.data, output.data);
		}
		else {
			mpz_mod_ui(output.data, lhs.data, rhs);
		}
	}
	
	/**
	Calls the GMP mpz_mod function. From the GMP Manual:

	<blockquote>
	Set r to n mod d. The sign of the divisor is ignored; the result is always non-negative.
	</blockquote>
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side unsigned long operand
	*/
	void BigIntegerGmp::Modulo (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const unsigned long rhs) {
		mpz_mod_ui(output.data, lhs.data, rhs);
	}

	/**
	Calls the GMP mpz_tdiv_q_2exp function, which applies "truncate" rounding after performing division.

	@param output BigInteger instance
	@param input BigInteger instance containing the original data
	@param numberOfBits The number of bits to shift input to the right
	*/
	void BigIntegerGmp::RightShift (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const unsigned long numberOfBits) {
		mpz_tdiv_q_2exp(output.data, input.data, numberOfBits);
	}
	
	/**
	@param output BigInteger instance
	@param input BigInteger instance containing the original data
	@param numberOfBits The number of bits to shift input to the left
	*/
	void BigIntegerGmp::LeftShift (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const unsigned long numberOfBits) {
		mpz_mul_2exp(output.data, input.data, numberOfBits);
	}

	/**
	@param lhs left hand side BigInteger operand
	@param rhs right hand side BigInteger operand
	@return A positive value if lhs > rhs, zero if lhs = rhs, or a negative value if lhs < rhs.
	*/
	int BigIntegerGmp::Compare (const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs) {
		return mpz_cmp(lhs.data, rhs.data);
	}
	
	/**
	@param lhs left hand side BigInteger operand
	@param rhs right hand side long operand
	@return A positive value if lhs > rhs, zero if lhs = rhs, or a negative value if lhs < rhs.
	*/
	int BigIntegerGmp::Compare (const BigIntegerBase<BigIntegerGmp> &lhs, const long rhs) {
		return mpz_cmp_si(lhs.data, rhs);
	}
	
	/**
	@param lhs left hand side BigInteger operand
	@param rhs right hand side unsigned long operand
	@return A positive value if lhs > rhs, zero if lhs = rhs, or a negative value if lhs < rhs.
	*/
	int BigIntegerGmp::Compare (const BigIntegerBase<BigIntegerGmp> &lhs, const unsigned long rhs) {
		return mpz_cmp_ui(lhs.data, rhs);
	}

	/**
	@param output BigInteger instance
	@param input BigInteger instance containing the original data
	*/
	void BigIntegerGmp::InvertBits (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input) {
		mpz_com(output.data, input.data);
	}

	/**
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side BigInteger operand
	*/
	void BigIntegerGmp::BitwiseAnd (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs) {
		mpz_and(output.data, lhs.data, rhs.data);
	}

	/**
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side BigInteger operand
	*/
	void BigIntegerGmp::BitwiseOr (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs) {
		mpz_ior(output.data, lhs.data, rhs.data);
	}

	/**
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side BigInteger operand
	*/
	void BigIntegerGmp::BitwiseXor (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs) {
		mpz_xor(output.data, lhs.data, rhs.data);
	}

	/**
	Calls the GMP mpz_nextprime function (deprecated in MPIR, which, at the moment, calls mpz_next_likely_prime from mpz_nextprime).

	From the GMP manual:
	<blockquote>
	This function uses a probabilistic algorithm to identify primes. For practical purposes it's
	adequate, the chance of a composite passing will be extremely small.
	</blockquote>
	@param output a BigInteger instance
	@param input the input value
	*/
	void BigIntegerGmp::GetNextPrime (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input) {
		mpz_nextprime(output.data, input.data);
	}

	/**
	Calls the mpz_probab_prime_p GMP function. This function will rarely (if ever?) return 2,
	so we only require it to not return 0, in which case the number would be definitely composite.

	Should MILLER_RABIN_PRIMALITY_TEST_COUNT be passed as a parameter?

	From the GMP manual:
	<blockquote>
	Determine whether n is prime. Return 2 if n is definitely prime, return 1 if n is probably
	prime (without being certain), or return 0 if n is definitely composite.

	This function does some trial divisions, then some Miller-Rabin probabilistic primality tests.
	reps controls how many such tests are done, 5 to 10 is a reasonable number, more will reduce
	the chances of a composite being returned as "probably prime".

	Miller-Rabin and similar tests can be more properly called compositeness tests. Numbers
	which fail are known to be composite but those which pass might be prime or might be
	composite. Only a few composites pass, hence those which pass are considered probably
	prime.
	</blockquote>
	@param input a BigInteger instance
	@return The test result (bool).
	*/
	bool BigIntegerGmp::IsPrime (const BigIntegerBase<BigIntegerGmp> &input) {
		if (0 != mpz_probab_prime_p(input.data, MILLER_RABIN_PRIMALITY_TEST_COUNT)) {
			return true;
		}
		
		return false;
	}

	/**
	@param input BigInteger instance
	@param index the position at which to set the bit in input. Indexing starts from 0
	*/
	void BigIntegerGmp::SetBit (BigIntegerBase<BigIntegerGmp> &input, const size_t index) {
		mpz_setbit(input.data, index);
	}

	/**
	If the instance is negative, then GetBit(input.GetSize()) = 1 (the sign bit) and GetBit(input.GetSize() + 1) = 0 and so on...

	@param input BigInteger instance
	@param index the position at which to get the bit in the current instance. Indexing starts from 0
	@return an int representing 1 or 0
	*/
	int BigIntegerGmp::GetBit (const BigIntegerBase<BigIntegerGmp> &input, const size_t index) {
		return mpz_tstbit(input.data, index);
	}

	/**
	Calls the GMP mpz_sizeinbase function. From the GMP Manual:
	<blockquote>
	Return the size of op measured in number of digits in the given base. base can vary from 2
	to 62. The sign of op is ignored, just the absolute value is used. The result will be either
	exact or 1 too big. If base is a power of 2, the result is always exact. If op is zero the return
	value is always 1.

	This function can be used to determine the space required when converting op to a string. The
	right amount of allocation is normally two more than the value returned by mpz_sizeinbase,
	one extra for a minus sign and one for the null-terminator.

	It will be noted that mpz_sizeinbase(op,2) can be used to locate the most significant 1 bit
	in op, counting from 1. (Unlike the bitwise functions which start from 0, See Section 5.11
	[Logical and Bit Manipulation Functions], page 38.)
	</blockquote>

	Please note that size(x) = size(-x)! I'm not sure if this is always the desired behavior...

	@param input BigInteger instance
	@param base the base in which to represent the number (defaults to 2)
	@return An unsigned int representing the size of the number in the specified base.
	*/
	size_t BigIntegerGmp::GetSize (const BigIntegerBase<BigIntegerGmp> &input, const unsigned int base) {
		return mpz_sizeinbase(input.data, base);
	}

	/**
	@param output BigInteger instance
	@param input BigInteger instance containing the original data
	@return A reference to the absolute value of the current instance.
	*/
	void BigIntegerGmp::Abs (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input) {
		mpz_abs(output.data, input.data);
	}

	/**
	Calls the GMP mpz_pow_ui function. From the GMP Manual:
	<blockquote>Set rop to @f$ base^{exp} @f$. The case @f$ 0^0 @f$ yields @f$ 1 @f$.</blockquote>
	@param output BigInteger instance
	@param input BigInteger instance containing the original data
	@param power the exponent
	@return A reference to the current instance raised to the specified power.
	*/
	void BigIntegerGmp::Pow (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const BigIntegerBase<BigIntegerGmp> &power) {
		mpz_pow_ui(output.data, input.data, power.ToUnsignedLong());
	}
	
	/**
	Calls the GMP mpz_pow_ui function. From the GMP Manual:
	<blockquote>Set rop to @f$ base^{exp} @f$. The case @f$ 0^0 @f$ yields @f$ 1 @f$.</blockquote>
	
	Negative powers always yield the value 0

	@param output BigInteger instance
	@param input BigInteger instance containing the original data
	@param power the exponent
	@return A reference to the current instance raised to the specified power.
	*/
	void BigIntegerGmp::Pow (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const long power) {
		if (power < 0) {
			mpz_set_si(output.data, 0);
		}
		else {
			mpz_pow_ui(output.data, input.data, power);
		}
	}
	
	/**
	Calls the GMP mpz_pow_ui function. From the GMP Manual:
	<blockquote>Set rop to @f$ base^{exp} @f$. The case @f$ 0^0 @f$ yields @f$ 1 @f$.</blockquote>

	@param output BigInteger instance
	@param input BigInteger instance containing the original data
	@param power the exponent
	@return A reference to the current instance raised to the specified power.
	*/
	void BigIntegerGmp::Pow (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const unsigned long power) {
		mpz_pow_ui(output.data, input.data, power);
	}

	/**
	Calls the GMP mpz_powm function. From the GMP Manual:

	<blockquote>
	Set rop to @f$ base^{exp} @f$ mod mod.

	Negative exp is supported if an inverse @f$ base^{-1} @f$ mod mod exists (see mpz_invert in Section 5.9
	[Number Theoretic Functions], page 35). If an inverse doesn't exist then a divide by zero is raised.
	</blockquote>

	Should we use mpz_powm_sec instead, in order to prevent side-channel attacks?

	@param output BigInteger instance
	@param input BigInteger instance containing the original data
	@param power the exponent
	@param n the modulus
	@return A reference to the current instance raised to the specified power modulo n.
	@throws Division by zero if the power is negative and an inverse doesn't exist.
	*/
	void BigIntegerGmp::PowModN (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const BigIntegerBase<BigIntegerGmp> &power, const BigIntegerBase<BigIntegerGmp> &n) {
		mpz_powm(output.data, input.data, power.data, n.data);
	}
	
	/**
	Calls BigIntegerGmp::PowModN (BigInteger &output, const BigInteger &input, const BigInteger &power, const BigInteger &n) if power is negative.
	
	Otherwise, calls the GMP mpz_powm_ui function. From the GMP Manual:

	<blockquote>
	Set rop to @f$ base^{exp} @f$ mod mod.

	Negative exp is supported if an inverse @f$ base^{-1} @f$ mod mod exists (see mpz_invert in Section 5.9
	[Number Theoretic Functions], page 35). If an inverse doesn't exist then a divide by zero is raised.
	</blockquote>

	Should we use mpz_powm_sec instead, in order to prevent side-channel attacks?

	@param output BigInteger instance
	@param input BigInteger instance containing the original data
	@param power the exponent
	@param n the modulus
	@return A reference to the current instance raised to the specified power modulo n.
	*/
	void BigIntegerGmp::PowModN (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const long power, const BigIntegerBase<BigIntegerGmp> &n) {
		if (power < 0) {
			BigIntegerGmp::PowModN (output, input, BigIntegerBase<BigIntegerGmp>(power), n);
		}
		else {
			mpz_powm_ui(output.data, input.data, power, n.data);
		}
	}
	
	/**
	Calls the GMP mpz_powm_ui function. From the GMP Manual:

	<blockquote>
	Set rop to @f$ base^{exp} @f$ mod mod.

	Negative exp is supported if an inverse @f$ base^{-1} @f$ mod mod exists (see mpz_invert in Section 5.9
	[Number Theoretic Functions], page 35). If an inverse doesn't exist then a divide by zero is raised.
	</blockquote>

	Should we use mpz_powm_sec instead, in order to prevent side-channel attacks?

	@param output BigInteger instance
	@param input BigInteger instance containing the original data
	@param power the exponent
	@param n the modulus
	@return A reference to the current instance raised to the specified power modulo n.
	*/
	void BigIntegerGmp::PowModN (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const unsigned long power, const BigIntegerBase<BigIntegerGmp> &n) {
		mpz_powm_ui(output.data, input.data, power, n.data);
	}

	/**
	Calls the GMP mpz_invert function. From the GMP Manual:

	<blockquote>
	Compute the inverse of op1 modulo @f$ op2 @f$ and put the result in @f$ rop @f$. If the inverse exists, the
	return value is non-zero and rop will satisfy @f$ 0 \leq rop < op2 @f$. If an inverse doesn't exist the
	return value is zero and rop is undefined.
	</blockquote>

	@param output BigInteger instance
	@param input BigInteger instance containing the original data
	@param n the modulus
	@throws std::runtime_error the inverse does not exist.
	*/
	void BigIntegerGmp::InvertModN (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &input, const BigIntegerBase<BigIntegerGmp> &n) {
		if (0 == mpz_invert(output.data, input.data, n.data)) {
			throw std::runtime_error("Failed to compute inverse modulo n.");
		}
	}

	/**
	@param lhs left hand side BigInteger operand
	@param rhs right hand side BigInteger operand
	*/
	void BigIntegerGmp::Swap (BigIntegerBase<BigIntegerGmp> &lhs, BigIntegerBase<BigIntegerGmp> &rhs) {
		mpz_swap(lhs.data, rhs.data);
	}

	/**
	Calls the GMP mpz_gcd function. From the GMP Manual:

	<blockquote>
	Set rop to the greatest common divisor of op1 and op2. The result is always positive even if
	one or both input operands are negative. Except if both inputs are zero; then this function
	defines gcd(0, 0) = 0.
	</blockquote>

	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side unsigned long operand
	*/
	void BigIntegerGmp::Gcd (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs) {
		mpz_gcd(output.data, lhs.data, rhs.data);
	}
	
	/**
	Calls the GMP mpz_lcm function. From the GMP Manual:

	<blockquote>
	Set rop to the least common multiple of op1 and op2. rop is always positive, irrespective of
	the signs of op1 and op2. rop will be zero if either op1 or op2 is zero.
	</blockquote>
	
	@param output BigInteger instance
	@param lhs left hand side BigInteger operand
	@param rhs right hand side unsigned long operand
	*/
	void BigIntegerGmp::Lcm (BigIntegerBase<BigIntegerGmp> &output, const BigIntegerBase<BigIntegerGmp> &lhs, const BigIntegerBase<BigIntegerGmp> &rhs) {
		mpz_lcm(output.data, lhs.data, rhs.data);
	}

	/**
	Calls the GMP mpz_get_str function. From the GMP Manual:

	<blockquote>
	Convert op to a string of digits in base base. The base argument may vary from 2 to 62 or from -2 to -36.

	For base in the range 2..36, digits and lower-case letters are used; for -2..-36, digits and
	upper-case letters are used; for 37..62, digits, upper-case letters, and lower-case letters (in that significance order) are used.

	If str is NULL, the result string is allocated using the current allocation function (see
	Chapter 14 [Custom Allocation], page 86). The block will be strlen(str)+1 bytes, that
	being exactly enough for the string and null-terminator.

	If str is not NULL, it should point to a block of storage large enough for the result, that being
	mpz_sizeinbase (op, base) + 2. The two extra bytes are for a possible minus sign, and the
	null-terminator.

	A pointer to the result string is returned, being either the allocated block, or the given str.
	</blockquote>

	@param input BigInteger instance containing the original data
	@param base the base in which to represent the number before transforming it to string (defaults to 2)
	@return A std::string representation of the underlying mpz_t in the specified base.
	*/
	std::string BigIntegerGmp::ToString (const BigIntegerBase<BigIntegerGmp> &input, const unsigned int base) {
		//get a pointer to GMP's internal memory deallocator function
		void (*deallocator)(void *, size_t);
		mp_get_memory_functions(NULL, NULL, &deallocator);

		//get the string representation of input
		char *data = mpz_get_str(NULL, base, input.data);

		std::string output(data);

		//deallocate data, including the terminator character
		//calling std::free on the char * returned by mpz_get_str is dangerous, because it is initialized internally by GMP
		(*deallocator)((void *)data, std::char_traits<char>::length(data) + 1);

		return output;
	}

	/**
	Calls the GMP mpz_get_ui function

	From the GMP Manual:
	<blockquote>
	If op is too big to fit an unsigned long then just the least significant bits that do fit are returned.
	The sign of op is ignored, only the absolute value is used.
	</blockquote>
	@param input BigInteger instance containing the original data
	@return An unsigned long containing the integer.
	*/
	unsigned long BigIntegerGmp::ToUnsignedLong (const BigIntegerBase<BigIntegerGmp> &input) {
		//if (0 == mpz_fits_ulong_p(input.data))
		//{
		//	throw std::runtime_error("The integer does not fit in an unsigned long.");
		//}

		return mpz_get_ui(input.data);
	}

}//namespace Core
}//namespace SeComLib