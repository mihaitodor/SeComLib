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
@file core/random_provider_gmp.cpp
@brief Implementation of class RandomProviderGmp.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "random_provider_gmp.h"

namespace SeComLib {
namespace Core {
	/**
	Obtains a truly random seed via platform dependent means.

	DO NOT use a function such as time(NULL) to generate it, because it does not provide a secure random seed (among other issues).

	Initializes the internal GMP random generator state via gmp_randinit_default.

	Seeds the random generator state with the random seed via gmp_randseed_ui.

	@param input uninitialized RandomProvider
	@throws std::runtime_error error encountered while trying to read the random seed
	*/
	void RandomProviderGmp::Initialize (RandomProviderBase<RandomProviderGmp> &input) {
		input.randomSeed = 0;

	#if _WIN32
		if (0 != rand_s(&input.randomSeed)) {
			throw std::runtime_error("Error calling rand_s.");
		}

	#else
		std::ifstream randomGeneratorFile("/dev/urandom", std::ios::binary);

		if (randomGeneratorFile.is_open()) {
			randomGeneratorFile.read((char *)&input.randomSeed, sizeof(input.randomSeed));
			randomGeneratorFile.close();
			//std::cout << this->randomSeed;
		}
		else {
			throw std::runtime_error("Error opening /dev/urandom.");
		}
	#endif

		gmp_randinit_default(input.randomGeneratorState);

		//initialize the random generator state
		//should seed be generated as unsigned long instead of unsigned int?
		//should use gmp_randseed instead? (with mpz_t seed)
		gmp_randseed_ui(input.randomGeneratorState, static_cast<unsigned long>(input.randomSeed));
	}

	/**
	@param randomProvider initialized RandomProvider
	*/
	void RandomProviderGmp::Destroy (RandomProviderBase<RandomProviderGmp> &randomProvider) {
		gmp_randclear(randomProvider.randomGeneratorState);
	}

	/**
	@param output BigInteger instance
	@param randomProvider initialized RandomProvider
	@param numberOfBits the maximum bit length of the generated random number
	*/
	void RandomProviderGmp::GetRandomInteger(BigIntegerBase<BigIntegerGmp> &output, RandomProviderBase<RandomProviderGmp> &randomProvider, const size_t numberOfBits) {
		mpz_urandomb(output.data, randomProvider.randomGeneratorState, (unsigned long)numberOfBits);
	}

	/**
	@param output BigInteger instance
	@param randomProvider initialized RandomProvider
	@param maximumValue the upper limit of the generated random number (non-inclusive)
	*/
	void RandomProviderGmp::GetRandomInteger(BigIntegerBase<BigIntegerGmp> &output, RandomProviderBase<RandomProviderGmp> &randomProvider, const BigIntegerBase<BigIntegerGmp> &maximumValue) {
		mpz_urandomm(output.data, randomProvider.randomGeneratorState, maximumValue.data);
	}

	/**
	Generates random numbers in the interval @f$ [0, 2^{numberOfBits - 1}) @f$.
	Shifts the integer to the interval @f$ [2^{numberOfBits - 1}, 2^{numberOfBits}) @f$ by setting the MSB.
	Repeats the process until the obtained number is prime.

	@param output BigInteger instance
	@param randomProvider initialized RandomProvider
	@param numberOfBits the bit length of the generated prime
	*/
	void RandomProviderGmp::GetMaxLengthRandomPrime(BigIntegerBase<BigIntegerGmp> &output, RandomProviderBase<RandomProviderGmp> &randomProvider, const size_t numberOfBits) {
		do {
			//generate a random number in the interval [0, 2^(numberOfBits - 1))
			output = randomProvider.GetRandomInteger(numberOfBits - 1);

			//shift number to the interval [2^(numberOfBits - 1), 2^numberOfBits)
			output.SetBit(numberOfBits - 1);
		}
		while (!output.IsPrime());

	#if 0//start disabled code block
		//My first version of the prime generator algorithm (faster but not the best approach)
		/*
		Algorithm logic:
		Generates a random integer in the interval @f$ [0, 2^{numberOfBits - 1}) @f$.
		Shifts the integer to the interval @f$ [2^{numberOfBits - 1}, 2^{numberOfBits}) @f$ by setting the MSB.
		Computes the first prime greater than the random integer.
		Repeats the process if the prime happns to end up in the interval @f$ [2^{numberOfBits}, 2^{numberOfBits + 1}) @f$

		The issue: primes are not evenly distributed, so there might be a bias towards certain primes

		mpz_nextprime first tests a number against a large quantity of small primes to see if they are a factor. If not, mpz_nextprime uses a probabilistic Miller-Rabin test.
		The number of Miller-Rabin tests varies between GMP (25) and MPIR (2), but they also use different ways to perform the small primes test
		(MPIR first checks if the primes smaller than 1000 are factors and then uses Miller-Rabin)
		*/
		bool retry = false;

		do {
			//generate a random number in the interval [0, 2^(numberOfBits - 1))
			output = randomProvider.GetRandomInteger(numberOfBits - 1);

			/*
			std::cout << output.GetSizeInBase() << std::endl;
			std::cout << output.ToString(16) << std::endl;
			*/

			//shift number to the interval [2^(numberOfBits - 1), 2^numberOfBits)
			//GMP counts the number of bits starting from bit 0...
			output.SetBit(numberOfBits - 1);

			/*
			std::cout << output.GetSizeInBase() << std::endl;
			std::cout << output.ToString(16) << std::endl;
			*/
		
			//generate prime number
			output = output.GetNextPrime();

			//it mustn't end up in the interval [2^numberOfBits, 2^(numberOfBits + 1))
			if (output.GetSize() != length) {
				retry = true;
			}
		}
		while (true == retry);
	#endif//end disabled code block
	}

}//namespace Core
}//namespace SeComLib