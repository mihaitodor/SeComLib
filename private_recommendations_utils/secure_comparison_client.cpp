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
@file private_recommendations_utils/secure_comparison_client.cpp
@brief Implementation of class SecureComparisonClient.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "secure_comparison_client.h"
//avoid circular includes
#include "secure_comparison_server.h"

namespace SeComLib {
namespace PrivateRecommendationsUtils {
	/**

	@param paillierCryptoProvider the Paillier crypto provider
	@param dgkCryptoProvider the Dgk crypto provider
	@param configurationPath the configuration path for parameters
	*/
	SecureComparisonClient::SecureComparisonClient (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const std::string &configurationPath) :
		paillierCryptoProvider(paillierCryptoProvider),
		dgkCryptoProvider(dgkCryptoProvider),
		dgkComparisonClient(std::make_shared<DgkComparisonClient>(paillierCryptoProvider, dgkCryptoProvider)),
		l(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".l")),
		twoPowL(BigInteger(2).GetPow(static_cast<unsigned long>(l))) {
	}

	/**
	@param z @f$ [z] @f$
	@return The encrypted result.
	*/
	Paillier::Ciphertext SecureComparisonClient::ComputeZDivTwoPowL (const Paillier::Ciphertext &z) const {
		BigInteger plaintextZ = this->paillierCryptoProvider.DecryptInteger(z);

		/// Persist the plaintext value of @f$ z \pmod {2^l} @f$ for the DGK comparison
		this->dgkComparisonClient->SetZModTwoPowL(plaintextZ % this->twoPowL);

		/// Compute @f$ [z \div 2^l] @f$
		return this->paillierCryptoProvider.EncryptInteger(plaintextZ / this->twoPowL);
	}

	/**
	@param secureComparisonServer a SecureComparisonServer instance
	*/
	void SecureComparisonClient::SetServer (const std::shared_ptr<SecureComparisonServer> &secureComparisonServer) {
		this->secureComparisonServer = secureComparisonServer;
		this->dgkComparisonClient->SetServer(secureComparisonServer->GetDgkComparisonServer());
	}

	/**
	@return The DgkComparisonClient instance.
	*/
	const std::shared_ptr<DgkComparisonClient> &SecureComparisonClient::GetDgkComparisonClient () const {
		return this->dgkComparisonClient;
	}

	/**
	@param input a Paillier encrypted integer
	*/
	void SecureComparisonClient::DebugPaillierEncryption (const Paillier::Ciphertext &input) const {
		std::cout << this->paillierCryptoProvider.DecryptInteger(input).ToString(10) << std::endl;
	}

}//namespace PrivateRecommendationsUtils
}//namespace SeComLib