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
@file main.cpp
@brief Sample application
@author Mihai Todor (todormihai@gmail.com)
*/
#include <iostream>

//include library headers
#include "core/big_integer.h"
#include "core/paillier.h"

using namespace SeComLib::Core;
using namespace SeComLib::Utils;

int main () {
	//it will require a config.xml file in the same directory as the executable
	Paillier privateCryptoProvider;
	privateCryptoProvider.GenerateKeys();

	Paillier publicCryptoProvider(privateCryptoProvider.GetPublicKey());

	std::cout << "Testing Paillier homomorphic operations:" << std::endl;

	BigInteger x(3);
	BigInteger y(-2);
	std::cout << "x = " << x.ToString(10) << std::endl;
	std::cout << "y = " << y.ToString(10) << std::endl;

	Paillier::Ciphertext encX = publicCryptoProvider.EncryptInteger(x);
	Paillier::Ciphertext encY = publicCryptoProvider.EncryptInteger(y);

	Paillier::Ciphertext sum = encX + encY;
	Paillier::Ciphertext inv = -encX;
	Paillier::Ciphertext dif = encX - encY;
	Paillier::Ciphertext prod = encX * y;

	std::cout << "x + y = " << privateCryptoProvider.DecryptInteger(sum).ToString(10) << std::endl;
	std::cout << "-x = " << privateCryptoProvider.DecryptInteger(inv).ToString(10) << std::endl;
	std::cout << "x - y = " << privateCryptoProvider.DecryptInteger(dif).ToString(10) << std::endl;
	std::cout << "x * y = " << privateCryptoProvider.DecryptInteger(prod).ToString(10) << std::endl;

	return 0;
}