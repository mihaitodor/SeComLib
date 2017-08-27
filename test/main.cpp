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
@file test/main.cpp
@brief Test main entry point.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "main.h"

/**
Application entry point.

Usage: Accepts one optional parameter: the full path to the configuration file. Otherwise, it tries to find "config.xml" in the current directory.

@param argc number of command line arguments
@param argv array containing the command line arguments
@return The process exit status
*/
int main (int argc, char *argv[]) {
	try {
		//the first command line parameter always contains the name of the application
		if (argc > 1) {
			//a custom configuration file was specified
			Utils::Config::SetConfigFile(std::string(argv[1]));
		}

		Paillier paillierCryptoProvider;
		OkamotoUchiyama okamotoUchiyamaCryptoProvider;
		Dgk dgkCryptoProvider(true);//pre-compute decryption map (keep Dgk.l reasonably small for this test)
		ElGamal elGamalCryptoProvider(true);//pre-compute decryption map (keep ElGamal.messageSpaceThresholdBitSize reasonably small for this test)

		std::cout << "Generating keys for every crypto provider." << std::endl;
		paillierCryptoProvider.GenerateKeys();
		okamotoUchiyamaCryptoProvider.GenerateKeys();
		dgkCryptoProvider.GenerateKeys();
		elGamalCryptoProvider.GenerateKeys();

		//encryption does not require the private key, so, if required, we can initialize new crypto providers, passing the public keys to the constructors

		std::cout << "Testing encryption / decryption of 0." << std::endl;
		assert(paillierCryptoProvider.DecryptInteger(paillierCryptoProvider.GetEncryptedZero()) == 0);
		assert(okamotoUchiyamaCryptoProvider.DecryptInteger(okamotoUchiyamaCryptoProvider.GetEncryptedZero()) == 0);
		assert(dgkCryptoProvider.DecryptInteger(dgkCryptoProvider.GetEncryptedZero()) == 0);
		assert(elGamalCryptoProvider.DecryptInteger(elGamalCryptoProvider.GetEncryptedZero()) == 0);

		std::cout << "Testing encryption / decryption of 1." << std::endl;
		assert(paillierCryptoProvider.DecryptInteger(paillierCryptoProvider.GetEncryptedOne()) == 1);
		assert(okamotoUchiyamaCryptoProvider.DecryptInteger(okamotoUchiyamaCryptoProvider.GetEncryptedOne()) == 1);
		assert(dgkCryptoProvider.DecryptInteger(dgkCryptoProvider.GetEncryptedOne()) == 1);
		assert(elGamalCryptoProvider.DecryptInteger(elGamalCryptoProvider.GetEncryptedOne()) == 1);

		std::cout << "Testing encryption / decryption of -1." << std::endl;
		assert(paillierCryptoProvider.DecryptInteger(paillierCryptoProvider.EncryptInteger(-1)) == -1);
		assert(okamotoUchiyamaCryptoProvider.DecryptInteger(okamotoUchiyamaCryptoProvider.EncryptInteger(-1)) == -1);
		assert(dgkCryptoProvider.DecryptInteger(dgkCryptoProvider.EncryptInteger(-1)) == -1);
		assert(elGamalCryptoProvider.DecryptInteger(elGamalCryptoProvider.EncryptInteger(-1)) == -1);

		std::cout << "Testing encryption / decryption of the positive / negative interval boundaries." << std::endl;
		assert(paillierCryptoProvider.DecryptInteger(paillierCryptoProvider.EncryptInteger(paillierCryptoProvider.GetPositiveNegativeBoundary())) == paillierCryptoProvider.GetPositiveNegativeBoundary());
		assert(paillierCryptoProvider.DecryptInteger(paillierCryptoProvider.EncryptInteger(paillierCryptoProvider.GetPositiveNegativeBoundary() + 1)) == -paillierCryptoProvider.GetPositiveNegativeBoundary());
		//Okamoto-Uchiyama does not allow us to publish the real upper bound of the message space, so this works only if we have the private key. See the note in OkamotoUchiyama::doPrecomputations()
		assert(okamotoUchiyamaCryptoProvider.DecryptInteger(okamotoUchiyamaCryptoProvider.EncryptInteger(okamotoUchiyamaCryptoProvider.GetPositiveNegativeBoundary())) == okamotoUchiyamaCryptoProvider.GetPositiveNegativeBoundary());
		assert(okamotoUchiyamaCryptoProvider.DecryptInteger(okamotoUchiyamaCryptoProvider.EncryptInteger(okamotoUchiyamaCryptoProvider.GetPositiveNegativeBoundary() + 1)) == -okamotoUchiyamaCryptoProvider.GetPositiveNegativeBoundary());
		assert(dgkCryptoProvider.DecryptInteger(dgkCryptoProvider.EncryptInteger(dgkCryptoProvider.GetPositiveNegativeBoundary())) == dgkCryptoProvider.GetPositiveNegativeBoundary());
		assert(dgkCryptoProvider.DecryptInteger(dgkCryptoProvider.EncryptInteger(dgkCryptoProvider.GetPositiveNegativeBoundary() + 1)) == -dgkCryptoProvider.GetPositiveNegativeBoundary());
		//ElGamal has a gap in the middle of the message space. We assign the left part to the positives and the right side the negatives
		assert(elGamalCryptoProvider.DecryptInteger(elGamalCryptoProvider.EncryptInteger(elGamalCryptoProvider.GetPositiveNegativeBoundary() - 1)) == elGamalCryptoProvider.GetPositiveNegativeBoundary() - 1);
		assert(elGamalCryptoProvider.DecryptInteger(elGamalCryptoProvider.EncryptInteger(elGamalCryptoProvider.GetMessageSpaceUpperBound() - elGamalCryptoProvider.GetPositiveNegativeBoundary() + 1)) == -elGamalCryptoProvider.GetPositiveNegativeBoundary() + 1);

		std::cout << "Testing DGK decryption of 0 without decryption map." << std::endl;
		Dgk dgkCryptoProviderNoDecryptionMap;
		dgkCryptoProviderNoDecryptionMap.GenerateKeys();
		assert(dgkCryptoProviderNoDecryptionMap.IsEncryptedZero(dgkCryptoProviderNoDecryptionMap.GetEncryptedZero()) == true);
		assert(dgkCryptoProviderNoDecryptionMap.IsEncryptedZero(dgkCryptoProviderNoDecryptionMap.GetEncryptedOne()) == false);

		std::cout << "Testing ElGamal decryption of 0 without decryption map." << std::endl;
		ElGamal elGamalCryptoProviderNoDecryptionMap;
		elGamalCryptoProviderNoDecryptionMap.GenerateKeys();
		assert(elGamalCryptoProviderNoDecryptionMap.IsEncryptedZero(elGamalCryptoProviderNoDecryptionMap.GetEncryptedZero()) == true);
		assert(elGamalCryptoProviderNoDecryptionMap.IsEncryptedZero(elGamalCryptoProviderNoDecryptionMap.GetEncryptedOne()) == false);

		BigInteger x = 2;
		BigInteger y = -1;
		std::cout << "Testing homomorphic addition, inverse, subtraction and multiplication." << std::endl;
		//Paillier
		{
			Paillier::Ciphertext encX = paillierCryptoProvider.EncryptInteger(x);
			Paillier::Ciphertext encY = paillierCryptoProvider.EncryptInteger(y);
			Paillier::Ciphertext sum = encX + encY;
			Paillier::Ciphertext inv = -encX;
			Paillier::Ciphertext dif = encX - encY;
			Paillier::Ciphertext prod = encX * y;
			assert(paillierCryptoProvider.DecryptInteger(sum) == x + y);
			assert(paillierCryptoProvider.DecryptInteger(inv) == -x);
			assert(paillierCryptoProvider.DecryptInteger(dif) == x - y);
			assert(paillierCryptoProvider.DecryptInteger(prod) == x * y);
		}
		//Okamoto-Uchiyama
		{
			OkamotoUchiyama::Ciphertext encX = okamotoUchiyamaCryptoProvider.EncryptInteger(x);
			OkamotoUchiyama::Ciphertext encY = okamotoUchiyamaCryptoProvider.EncryptInteger(y);
			OkamotoUchiyama::Ciphertext sum = encX + encY;
			OkamotoUchiyama::Ciphertext inv = -encX;
			OkamotoUchiyama::Ciphertext dif = encX - encY;
			OkamotoUchiyama::Ciphertext prod = encX * y;
			assert(okamotoUchiyamaCryptoProvider.DecryptInteger(sum) == x + y);
			assert(okamotoUchiyamaCryptoProvider.DecryptInteger(inv) == -x);
			assert(okamotoUchiyamaCryptoProvider.DecryptInteger(dif) == x - y);
			assert(okamotoUchiyamaCryptoProvider.DecryptInteger(prod) == x * y);
		}
		//DGK
		{
			Dgk::Ciphertext encX = dgkCryptoProvider.EncryptInteger(x);
			Dgk::Ciphertext encY = dgkCryptoProvider.EncryptInteger(y);
			Dgk::Ciphertext sum = encX + encY;
			Dgk::Ciphertext inv = -encX;
			Dgk::Ciphertext dif = encX - encY;
			Dgk::Ciphertext prod = encX * y;
			assert(dgkCryptoProvider.DecryptInteger(sum) == x + y);
			assert(dgkCryptoProvider.DecryptInteger(inv) == -x);
			assert(dgkCryptoProvider.DecryptInteger(dif) == x - y);
			assert(dgkCryptoProvider.DecryptInteger(prod) == x * y);
		}
		//ElGamal
		{
			ElGamal::Ciphertext encX = elGamalCryptoProvider.EncryptInteger(x);
			ElGamal::Ciphertext encY = elGamalCryptoProvider.EncryptInteger(y);
			ElGamal::Ciphertext sum = encX + encY;
			ElGamal::Ciphertext inv = -encX;
			ElGamal::Ciphertext dif = encX - encY;
			ElGamal::Ciphertext prod = encX * y;
			assert(elGamalCryptoProvider.DecryptInteger(sum) == x + y);
			assert(elGamalCryptoProvider.DecryptInteger(inv) == -x);
			assert(elGamalCryptoProvider.DecryptInteger(dif) == x - y);
			assert(elGamalCryptoProvider.DecryptInteger(prod) == x * y);
		}

		std::cout << "Testing Data Packing with Paillier." << std::endl;
		{
			//initialize the data packer
			DataPacker<Paillier> dataPacker(paillierCryptoProvider, 4, 1, 1);

			//generate some dummy vectors of data
			size_t bucketCount = 30;
			DataPacker<Paillier>::UnpackedData lhs, rhs;
			for (size_t i = 0; i < bucketCount; ++i)
			{
				DataPacker<Paillier>::DataBucket bucket;

				bucket.frontPadding = 1;
				bucket.data = BigInteger(2);
				bucket.backPadding = 1;
				lhs.emplace_back(bucket);

				bucket.frontPadding = 0;
				bucket.data = BigInteger(3);
				bucket.backPadding = 0;
				rhs.emplace_back(bucket);
			}

			//pack data vectors
			DataPacker<Paillier>::PackedData packedLhs = dataPacker.Pack(lhs);
			DataPacker<Paillier>::PackedData packedRhs = dataPacker.Pack(rhs);

			//perform homomorphic operations on the packed vectors
			DataPacker<Paillier>::PackedData sum = dataPacker.HomomorphicAdd(packedLhs, packedRhs);
			DataPacker<Paillier>::PackedData prod = dataPacker.HomomorphicMultiply(packedRhs, 2);

			//unpack data
			DataPacker<Paillier>::UnpackedData unpackedSum = dataPacker.Unpack(sum, bucketCount);
			DataPacker<Paillier>::UnpackedData unpackedProd = dataPacker.Unpack(prod, bucketCount);
			for (size_t i = 0; i < bucketCount; ++i)
			{
				assert(unpackedSum[i].frontPadding == 1);
				assert(unpackedSum[i].data == 5);
				assert(unpackedSum[i].backPadding == 1);

				assert(unpackedProd[i].frontPadding == 0);
				assert(unpackedProd[i].data == 6);
				assert(unpackedProd[i].backPadding == 0);
			}
		}

		std::cout << "Testing Paillier cryptoprovider construction from public and private key pairs." << std::endl;
		{
			PaillierPublicKey publicKeyClone;
			publicKeyClone.g = paillierCryptoProvider.GetPublicKey().g;
			publicKeyClone.n = paillierCryptoProvider.GetPublicKey().n;

			PaillierPrivateKey privateKeyClone;
			privateKeyClone.p = paillierCryptoProvider.GetPrivateKey().p;
			privateKeyClone.q = paillierCryptoProvider.GetPrivateKey().q;

			Paillier cryptoProviderClone(publicKeyClone, privateKeyClone);
			
			BigInteger plaintext = RandomProvider::GetInstance().GetRandomInteger(cryptoProviderClone.GetPositiveNegativeBoundary());
			assert(cryptoProviderClone.DecryptInteger(cryptoProviderClone.EncryptInteger(plaintext)) == plaintext);
			assert(cryptoProviderClone.DecryptInteger(cryptoProviderClone.EncryptInteger(-plaintext)) == -plaintext);
		}

		std::cout << "Testing Okamoto-Uchiyama cryptoprovider construction from public and private key pairs." << std::endl;
		{
			OkamotoUchiyamaPublicKey publicKeyClone;
			publicKeyClone.G = okamotoUchiyamaCryptoProvider.GetPublicKey().G;
			publicKeyClone.H = okamotoUchiyamaCryptoProvider.GetPublicKey().H;
			publicKeyClone.n = okamotoUchiyamaCryptoProvider.GetPublicKey().n;

			OkamotoUchiyamaPrivateKey privateKeyClone;
			privateKeyClone.p = okamotoUchiyamaCryptoProvider.GetPrivateKey().p;
			privateKeyClone.q = okamotoUchiyamaCryptoProvider.GetPrivateKey().q;
			privateKeyClone.gp = okamotoUchiyamaCryptoProvider.GetPrivateKey().gp;
			privateKeyClone.t = okamotoUchiyamaCryptoProvider.GetPrivateKey().t;

			OkamotoUchiyama cryptoProviderClone(publicKeyClone, privateKeyClone);
			
			BigInteger plaintext = RandomProvider::GetInstance().GetRandomInteger(cryptoProviderClone.GetPositiveNegativeBoundary());
			assert(cryptoProviderClone.DecryptInteger(cryptoProviderClone.EncryptInteger(plaintext)) == plaintext);
			assert(cryptoProviderClone.DecryptInteger(cryptoProviderClone.EncryptInteger(-plaintext)) == -plaintext);
		}

		std::cout << "Testing DGK cryptoprovider construction from public and private key pairs." << std::endl;
		{
			DgkPublicKey publicKeyClone;
			publicKeyClone.g = dgkCryptoProvider.GetPublicKey().g;
			publicKeyClone.h = dgkCryptoProvider.GetPublicKey().h;
			publicKeyClone.n = dgkCryptoProvider.GetPublicKey().n;
			publicKeyClone.u = dgkCryptoProvider.GetPublicKey().u;

			DgkPrivateKey privateKeyClone;
			privateKeyClone.p = dgkCryptoProvider.GetPrivateKey().p;
			privateKeyClone.q = dgkCryptoProvider.GetPrivateKey().q;
			privateKeyClone.vp = dgkCryptoProvider.GetPrivateKey().vp;
			privateKeyClone.vq = dgkCryptoProvider.GetPrivateKey().vq;

			Dgk cryptoProviderClone(publicKeyClone, privateKeyClone, true);//pre-compute decryption map (keep Dgk.l reasonably small for this test)
			
			BigInteger plaintext = RandomProvider::GetInstance().GetRandomInteger(cryptoProviderClone.GetPositiveNegativeBoundary());
			assert(cryptoProviderClone.DecryptInteger(cryptoProviderClone.EncryptInteger(plaintext)) == plaintext);
			assert(cryptoProviderClone.DecryptInteger(cryptoProviderClone.EncryptInteger(-plaintext)) == -plaintext);
		}

		std::cout << "Testing ElGamal cryptoprovider construction from public and private key pairs." << std::endl;
		{
			ElGamalPublicKey publicKeyClone;
			publicKeyClone.gq = elGamalCryptoProvider.GetPublicKey().gq;
			publicKeyClone.h = elGamalCryptoProvider.GetPublicKey().h;
			publicKeyClone.p = elGamalCryptoProvider.GetPublicKey().p;
			publicKeyClone.q = elGamalCryptoProvider.GetPublicKey().q;

			ElGamalPrivateKey privateKeyClone;
			privateKeyClone.s = elGamalCryptoProvider.GetPrivateKey().s;

			ElGamal cryptoProviderClone(publicKeyClone, privateKeyClone, true);//pre-compute decryption map (keep ElGamal.messageSpaceThresholdBitSize reasonably small for this test)
			
			BigInteger plaintext = RandomProvider::GetInstance().GetRandomInteger(cryptoProviderClone.GetPositiveNegativeBoundary());
			assert(cryptoProviderClone.DecryptInteger(cryptoProviderClone.EncryptInteger(plaintext)) == plaintext);
			assert(cryptoProviderClone.DecryptInteger(cryptoProviderClone.EncryptInteger(-plaintext)) == -plaintext);
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