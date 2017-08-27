/*
SeComLib
Copyright 2012-2013 TU Delft, Information Security & Privacy Lab (http://isplab.tudelft.nl/)

Contributors:
Mihai Todor (todormihai@gmail.com)
Inald Lagendijk (R.L.Lagendijk@TUDelft.nl)
Zekeriya Erkin (z.erkin@tudelft.nl)
Thijs Veugen (P.J.M.Veugen@tudelft.nl)

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
@file 1_2_OT_RSA.cpp
@brief Simple implementation of an 1-2 oblivious transfer protocol based on RSA, as described here: http://en.wikipedia.org/wiki/Oblivious_transfer#1-2_oblivious_transfer
@author Mihai Todor (todormihai@gmail.com)
*/
#include "core/big_integer.h"
#include "core/random_provider.h"

int main () {
	try {
		while (true) {
			/// Alice

			//generate RSA keys
			BigInteger p = RandomProvider::GetInstance().GetMaxLengthRandomPrime(512);
			BigInteger q = RandomProvider::GetInstance().GetMaxLengthRandomPrime(512);
			BigInteger n = p * q;
			BigInteger e = 65537;
			BigInteger phi = (p - 1) * (q - 1);
			while (true) {
				if (BigInteger::Gcd(e, phi) == 1) {
					break;
				}
				else {
					e += 2;
				}
			}
			BigInteger d = e.GetInverseModN(phi);

			//choose two messages
			BigInteger m0 = RandomProvider::GetInstance().GetRandomInteger(n);
			BigInteger m1 = RandomProvider::GetInstance().GetRandomInteger(n);

			//generate two random primes
			BigInteger x0 = RandomProvider::GetInstance().GetRandomInteger(n);
			BigInteger x1 = RandomProvider::GetInstance().GetRandomInteger(n);

			/// Bob

			BigInteger b = RandomProvider::GetInstance().GetRandomInteger(1);
			BigInteger xb = b == 0 ? x0 : x1;

			BigInteger k = RandomProvider::GetInstance().GetRandomInteger(n);
			BigInteger v = (xb + k.GetPowModN(e, n)) % n;

			/// Alice

			BigInteger k0 = (v - x0).GetPowModN(d, n);
			BigInteger k1 = (v - x1).GetPowModN(d, n);

			BigInteger m0Prime = m0 + k0;
			BigInteger m1Prime = m1 + k1;

			/// Bob

			BigInteger mb;
			if (b == 0) {
				mb = m0Prime - k;
			}
			else {
				mb = m1Prime - k;
			}

			if (mb != (b == 0 ? m0 : m1)) {
				std::cout << "n: " << n.ToString(10) << std::endl;
				std::cout << "p: " << p.ToString(10) << std::endl;
				std::cout << "q: " << q.ToString(10) << std::endl;
				std::cout << "e: " << e.ToString(10) << std::endl;
				std::cout << "d: " << d.ToString(10) << std::endl;

				std::cout << "m0: " << m0.ToString(10) << std::endl;
				std::cout << "m1: " << m1.ToString(10) << std::endl;

				std::cout << "x0: " << x0.ToString(10) << std::endl;
				std::cout << "x1: " << x1.ToString(10) << std::endl;

				std::cout << "b: " << b.ToString(10) << std::endl;

				std::cout << "k: " << k.ToString(10) << std::endl;
				std::cout << "v: " << v.ToString(10) << std::endl;

				std::cout << "mb: " << mb.ToString(10) << std::endl;

				std::cout << std::endl << std::endl;

				std::cout << "===========================================" << std::endl;

				std::cout << std::endl << std::endl;
			}
		}
	}
	catch (const std::runtime_error &exception) {
		std::cout << exception.what() << std::endl;
	}
	catch (const std::exception &exception) {
		std::cout << exception.what() << std::endl;
	}
	//it won't catch low level exceptions, like division by 0, produced by GMP...
	catch (...) {
		std::cout << "Unexpected exception occured." << std::endl;
	}
	return 0;
}