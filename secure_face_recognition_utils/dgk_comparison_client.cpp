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
@file secure_face_recognition_utils/dgk_comparison_client.cpp
@brief Implementation of class DgkComparisonClient.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "dgk_comparison_client.h"
//avoid circular includes
#include "dgk_comparison_server.h"

namespace SeComLib {
namespace SecureFaceRecognitionUtils {
	/**
	@param paillierCryptoProvider the Paillier crypto provider
	@param dgkCryptoProvider the Dgk crypto provider
	@param configurationPath the configuration path
	*/
	DgkComparisonClient::DgkComparisonClient (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const std::string &configurationPath) :
		paillierCryptoProvider(paillierCryptoProvider),
		dgkCryptoProvider(dgkCryptoProvider),
		l(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".l")),
		encryptedMinusTwoPowL(paillierCryptoProvider.EncryptIntegerNonrandom(BigInteger(-1) << static_cast<unsigned long>(l))) {
	}

	/**
	@param hatD @f$ \hat{d} @f$
	*/
	void DgkComparisonClient::SetHatD (const BigInteger &hatD) {
		this->hatD = hatD;
	}

	/**
	@return The encrypted bits of @f$ \hat{d} @f$.
	*/
	std::deque<Dgk::Ciphertext> DgkComparisonClient::GetHatDBits () const {
		std::deque<Dgk::Ciphertext> hatDBits;

		/// Encrypt each bit of @f$ \hat{d} @f$ using DGK @f$ \Rightarrow \llbracket \hat{d} \rrbracket @f$
		for (size_t i = 0; i < this->l; ++i) {
			hatDBits.emplace_back(this->dgkCryptoProvider.EncryptInteger(BigInteger(static_cast<long>(this->hatD.GetBit(i)))));
		}

		return hatDBits;
	}
	 
	/**
	@param e vector containing @f$ l + 1 @f$ DGK encryptions
	@return @f$ \lambda @f$
	*/
	Paillier::Ciphertext DgkComparisonClient::ComputeLambda (const std::deque<Dgk::Ciphertext> &e) const {
		/// @warning Protocol 4.10 from Martin Franz' Master Thesis returns @f$ [\lambda] = [0] @f$ in case zeros are detected, but it should be the other way around, since detecting a [0] means that @f$ 2 \hat{r} > 2 \hat{d} + 1 @f$, which implies an underflow

		for (size_t i = 0; i < this->l + 1; ++i) {
			if (this->dgkCryptoProvider.IsEncryptedZero(e[i])) {
				/// If the input contains at least one encrypted zero, then @f$ [\lambda] = [-2^l] @f$ and we can stop scanning the rest of the values
				return this->paillierCryptoProvider.RandomizeCiphertext(this->encryptedMinusTwoPowL);
			}
		}

		/// If the input contains no encrypted zeros @f$ [\lambda] = [0] @f$ (@f$ 2 \hat{r} < 2 \hat{d} + 1 @f$ and no underflow has occured)
		return this->paillierCryptoProvider.GetEncryptedZero();
	}

	/**
	@param dgkComparisonServer a DgkComparisonServer instance
	*/
	void DgkComparisonClient::SetServer (const std::shared_ptr<DgkComparisonServer> &dgkComparisonServer) {
		this->dgkComparisonServer = dgkComparisonServer;
	}

	/**
	@param input a DGK encrypted integer
	*/
	void DgkComparisonClient::DebugDgkEncryption (const Dgk::Ciphertext &input) const {
		std::cout << !this->dgkCryptoProvider.IsEncryptedZero(input) << std::endl;
	}

}//namespace SecureFaceRecognitionUtils
}//namespace SeComLib