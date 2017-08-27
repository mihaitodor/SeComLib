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
@file private_recommendations_data_packing/secure_comparison_server.cpp
@brief Implementation of class SecureComparisonServer.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "secure_comparison_server.h"
//avoid circular includes
#include "secure_comparison_client.h"

namespace SeComLib {
namespace PrivateRecommendationsDataPacking {
	/**
	@param paillierCryptoProvider the Paillier crypto provider
	@param dgkCryptoProvider the DGK crypto provider
	@param similarityTreshold the threshold to which similarity values will be compared
	@param l @f$ l = 2k + \lceil log_2(R) \rceil @f$
	@param bucketSize the size of the data buckets (in bits)
	@param maxPackedBuckets the maximum number of buckets that fit in one encryption
	@param emptyBuckets pre-computed empty buckets
	@param configurationPath the configuration path for parameters
	*/
	SecureComparisonServer::SecureComparisonServer (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const BigInteger &similarityTreshold, const size_t l, const size_t bucketSize, const size_t maxPackedBuckets, const std::deque<BigInteger> &emptyBuckets, const std::string &configurationPath) :
		paillierCryptoProvider(paillierCryptoProvider),
		dgkCryptoProvider(dgkCryptoProvider),
		blindingFactorCache(paillierCryptoProvider, ComparisonBlindingFactorCacheParameters(configurationPath + ".BlindingFactorCache", bucketSize * maxPackedBuckets, emptyBuckets)),
		l(l),
		emptyBuckets(emptyBuckets),
		maxPackedBuckets(maxPackedBuckets),
		//the dgkComparisonServer operates on l + 1 bit values (due to the empty bit at the beginning of each bucket)
		dgkComparisonServer(std::make_shared<DgkComparisonServer>(paillierCryptoProvider, dgkCryptoProvider, l + 1)) {
		/// Precompute @f$ \left[ \displaystyle\sum_{i = 0}^{N - 1}{(2^{l + 2})^i 2(2^l - \delta) } \right]  @f$, where N is the maximum number of packed buckets that fit in one encryption
		BigInteger twoTimestwoPowLMinusDelta = (BigInteger(2).GetPow(static_cast<unsigned long>(this->l)) - similarityTreshold) * 2;

		BigInteger one(1);
		BigInteger partialD = twoTimestwoPowLMinusDelta;
		for (size_t i = 1; i < maxPackedBuckets; ++i) {
			partialD += (one << (static_cast<unsigned long>(bucketSize * i))) * twoTimestwoPowLMinusDelta;//bucketSize = l + 2
		}

		this->encryptedPartialD = this->paillierCryptoProvider.EncryptIntegerNonrandom(partialD);
	}

	/**
	@param packedSimilarityValues packed similariy values
	@param similarityValueCountInLastEncryption number of packed similarity values in the last element of the packedSimilarityValues encryptions vector
	@return The encrypted similarity comparison results, @f$ [\gamma_i] @f$, for the current user
	*/
	SecureComparisonServer::EncryptedUserData SecureComparisonServer::Compare (const PackedData &packedSimilarityValues, const size_t similarityValueCountInLastEncryption) {
		EncryptedUserData gammaVector;

		/// Iterate over the @f$ [SIM_{user}^{Packed}] @f$ encryptions (if there are enough users, multiple encryptions will be required to pack all @f$ sim_{(user, j)} @f$ values)
		for (size_t encryptionIndex = 0; encryptionIndex < packedSimilarityValues.size(); ++encryptionIndex) {
			/**
			Compute @f$ [D] = \left[ \displaystyle\sum_{i = 0}^{N - 1}{(2^{l + 2})^i 2 \tilde{d}^{(i)}} \right] = [SIM_A^{Packed}] \left[ \displaystyle\sum_{i = 0}^{N - 1}{(2^{l + 2})^i 2(2^l - \delta) } \right] @f$
			where @f$ [\tilde{d}^{(i)}] = [2^l + sim_{(A, i)} - \delta] @f$
			*/
			Paillier::Ciphertext D = packedSimilarityValues[encryptionIndex] + this->encryptedPartialD;

			const BlindingFactorContainer &blindingFactorContainer = this->blindingFactorCache.Pop();

			/// @f$ [z] = [D] \cdot [r] @f$
			Paillier::Ciphertext z = D + blindingFactorContainer.encryptedR;

			//the last element of the packedSimilarityValues vector may contain fewer packed buckets
			size_t encryptedBucketsCount = encryptionIndex < packedSimilarityValues.size() - 1 ? this->maxPackedBuckets : similarityValueCountInLastEncryption;

			/// Ask the client to unpack @f$ [z] @f$
			this->secureComparisonClient.lock()->UnpackZ(z, this->emptyBuckets, encryptedBucketsCount);

			/// Compute @f$ [\gamma_{(user, i)}] @f$
			for (size_t i = 0; i < encryptedBucketsCount; ++i) {
				this->secureComparisonClient.lock()->SetZi(i);

				//std::cout << "r_i: " << blindingFactorContainer.ri[i].ToString() << std::endl;
				gammaVector.emplace_back(this->dgkComparisonServer->ComputeDi(blindingFactorContainer.ri[i]));

				//this->secureComparisonClient.lock()->DebugPaillierEncryption(gammaVector.back());
			}
		}

		return gammaVector;
	}

	/**
	@param index The index of the bucket
	@return a reference to the requested empty bucket
	*/
	const BigInteger &SecureComparisonServer::GetEmptyBucket (const size_t index) const {
		return this->emptyBuckets.at(index);
	}

	/**
	@param secureComparisonClient a SecureComparisonClient instance
	*/
	void SecureComparisonServer::SetClient (const std::shared_ptr<SecureComparisonClient> &secureComparisonClient) {
		this->secureComparisonClient = secureComparisonClient;
		this->dgkComparisonServer->SetClient(secureComparisonClient->GetDgkComparisonClient());
	}

	/**
	@return The DgkComparisonServer instance.
	*/
	const std::shared_ptr<DgkComparisonServer> &SecureComparisonServer::GetDgkComparisonServer () const {
		return this->dgkComparisonServer;
	}

}//namespace PrivateRecommendationsDataPacking
}//namespace SeComLib