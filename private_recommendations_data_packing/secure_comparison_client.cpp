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
@file private_recommendations_data_packing/secure_comparison_client.cpp
@brief Implementation of class SecureComparisonClient.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "secure_comparison_client.h"
//avoid circular includes
#include "secure_comparison_server.h"

namespace SeComLib {
namespace PrivateRecommendationsDataPacking {
	/**
	@param paillierCryptoProvider the Paillier crypto provider
	@param dgkCryptoProvider the Dgk crypto provider
	*/
	SecureComparisonClient::SecureComparisonClient (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider) :
		paillierCryptoProvider(paillierCryptoProvider),
		dgkCryptoProvider(dgkCryptoProvider),
		dgkComparisonClient(std::make_shared<DgkComparisonClient>(paillierCryptoProvider, dgkCryptoProvider)) {
	}

	/**
	@param z @f$ [z] @f$
	@param emptyBuckets @f$ (2^{l + 2})^i @f$
	@param encryptedBucketsCount the number of encrypted buckets in @f$ [z] @f$
	@return The encrypted result.
	*/
	void SecureComparisonClient::UnpackZ (const Paillier::Ciphertext &z, const std::deque<BigInteger> &emptyBuckets, const size_t encryptedBucketsCount) {
		BigInteger plaintextZ = this->paillierCryptoProvider.DecryptInteger(z);

		/// Make sure we clear the state each time this method is called!!!
		this->zi.clear();

		/// Compute @f$ z^{(i)} @f$ such that @f$ z \pmod {2^{N(l + 2)}} = \displaystyle\sum_{i = 0}^{N -1}{z^{(i)}(2^{l + 2})^i} @f$
		if (encryptedBucketsCount == emptyBuckets.size()) {
			for (size_t i = 0; i < emptyBuckets.size() - 1; ++i) {
				this->zi.emplace_back((plaintextZ % emptyBuckets[i + 1]) / emptyBuckets[i]);
			}
			this->zi.emplace_back(plaintextZ / emptyBuckets[emptyBuckets.size() - 1]);//emptyBuckets[i + 1] > plaintextZ
		}
		else {
			for (size_t i = 0; i < encryptedBucketsCount; ++i) {
				this->zi.emplace_back((plaintextZ % emptyBuckets[i + 1]) / emptyBuckets[i]);
			}
		}
	}

	/**
	Specifies which @f$ z^{(i)} @f$ to send to the dgkComparisonClient for the current comparison

	@param i the bit index
	*/
	void SecureComparisonClient::SetZi (const size_t i) const {
		/// Persist the plaintext value of @f$ z^{(i)} @f$ for the DGK comparison
		this->dgkComparisonClient->SetZModTwoPowL(this->zi[i]);
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
		std::cout << this->paillierCryptoProvider.DecryptInteger(input).ToString(2) << std::endl;
	}

}//namespace PrivateRecommendationsDataPacking
}//namespace SeComLib