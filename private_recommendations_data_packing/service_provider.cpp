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
@file private_recommendations_data_packing/service_provider.cpp
@brief Implementation of class ServiceProvider.
@details The Service Provider (SP) has a business interest in generating recommendations for his customers. He has resources for storage and processing.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "service_provider.h"
//avoid circular includes
#include "privacy_service_provider.h"

namespace SeComLib {
namespace PrivateRecommendationsDataPacking {
	/**
	Set the configuration path.
	*/
	const std::string ServiceProvider::configurationPath("PrivateRecommendationsDataPacking");

	/**
	@f$ \delta @f$ needs to be scaled with @f$ s^2 @f$, because @f$ sim_{(A, B)} @f$ is the dot product of two scaled vectors

	@param paillierPublicKey The Paillier public key
	@param dgkPublicKey The DGK public key
	*/
	ServiceProvider::ServiceProvider (const PaillierPublicKey &paillierPublicKey, const DgkPublicKey &dgkPublicKey) :
		paillierCryptoProvider(paillierPublicKey),
		dgkCryptoProvider(dgkPublicKey),
		userCount(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".userCount")),
		itemCount(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".itemCount")),
		denselyRatedItemCount(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".denselyRatedItemCount")),
		scaledNormalizedRatingBitSize(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".scaledNormalizedRatingBitSize")),
		digitsToPreserve(Utils::Config::GetInstance().GetParameter<unsigned int>(configurationPath + ".digitsToPreserve")),
		kappa(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".BlindingFactorCache.kappa")),
		//the similarity threshold needs to be scaled twice as much as the normalized ratings, due to the way the similarity values are computed
		similarityTreshold(BigInteger(Utils::Config::GetInstance().GetParameter<double>(configurationPath + ".similarityTreshold"), 2 * digitsToPreserve)) {
		/// Each bucket must have @f$ 2k + \lceil log_2(R) \rceil + 2 @f$ bits
		unsigned long ceilLogBaseTwoR = static_cast<unsigned long>(std::ceil(std::log(static_cast<double>(this->denselyRatedItemCount)) / std::log(2.0)));//change base from e to 2 and round up to the nearest integer
		size_t l = 2 * this->scaledNormalizedRatingBitSize + ceilLogBaseTwoR;
		this->bucketSize = l + 2;

		/**
		We need to reserve @f$ \kappa @f$ extra bits in each encryption in order to perform secure blinding
		In order not to cause overflows during secure blinding, we reserve another 2 extra bits at the top of each encryption, such that if size(r) = size(message space) - 2, then r + d < message space
		*/
		this->maxPackedBuckets = (this->paillierCryptoProvider.GetMessageSpaceSize() - this->kappa - 2) / this->bucketSize;

		/// Pre-compute the empty buckets @f$ 2^{i * bucketSize} @f$
		BigInteger one(1);
		for (size_t i = 0; i < this->maxPackedBuckets; ++i) {
			this->emptyBuckets.emplace_back(one << (static_cast<unsigned long>(i * this->bucketSize)));
		}
		
		//initialize the secureComparisonServer
		this->secureComparisonServer = std::make_shared<SecureComparisonServer>(this->paillierCryptoProvider, this->dgkCryptoProvider, this->similarityTreshold, l, this->bucketSize, this->maxPackedBuckets, this->emptyBuckets, this->configurationPath);
		this->secureMultiplicationServer = std::make_shared<SecureMultiplicationServer<Paillier>>(this->paillierCryptoProvider, l, configurationPath);
	}

	/**
	Computes @f$ [v_{(user, j)}^c] @f$

	@param normalizedScaledRatings @f$ [\tilde{V}_i^d] @f$
	*/
	void ServiceProvider::GenerateDummyDatabase (const EncryptedUserDataContainer &normalizedScaledRatings) {
		/**
		Pack the densely related item ratings for every user

		@f$ [V_{(user, j)}^{c}] = [\tilde{v}_{(0, j)}^d | \tilde{v}_{(1, j)}^d | ... | \tilde{v}_{(N - 2, j)}^d] = \left[\displaystyle\sum_{i=0, i \neq user}^{N - 2}{2 \tilde{v}_{(i, j)}^d (2^{2k + \lceil log_2(R) \rceil + 2})^i} \right] = \displaystyle\prod_{i=0, i \neq user}^{N - 2}{[\tilde{v}_{(i, j)}]^{2(2^{2k + \lceil log_2(R) \rceil + 2})^i}} @f$
		*/
		BigInteger two(2);
	#ifdef FIRST_USER_ONLY
		std::cout << "Warning: running simulation for a single user." << std::endl << std::endl;
		for (size_t user = 0; user < 1; ++user) {
	#else
		for (size_t user = 0; user < this->userCount; ++user) {
	#endif
			//measure the time it takes to generate the packed densely related items for each user
			Utils::CpuTimer userTimer;

			PackedItems userPackedDenselyRelatedItems;
			for (size_t item = 0; item < this->denselyRatedItemCount; ++item) {
				/// @f$ [v_{(user, item)}^c] @f$
				PackedData packedItems;
				
				Paillier::Ciphertext packedBuckets;
				size_t bucketCount = 0;
				for (size_t i = 0; i < this->userCount; ++i) {
					//sim(i, i) does not exist and sim(A, B) = sim(B, A), so we compute only sim(A, B) (the upper triangle of the matrix, without the diagonal)
					if (i > user) {
						/// All empty buckets have one empty zero bit at the bottom and one at the top. We want to insert the normalizedScaledRatings in the middle of each bucket, which explains the shift by one

						//the encryption is empty, so we assign to it the next value
						if (0 == bucketCount) {
							/*
							this->privacyServiceProvider.lock()->DebugPaillierEncryption(this->normalizedScaledRatings[i][item]);
							std::cout << this->emptyBuckets[bucketCount].ToString() << std::endl << std::endl;
							*/
							packedBuckets = normalizedScaledRatings[i][item] * (this->emptyBuckets[bucketCount] << 1);
							//this->privacyServiceProvider.lock()->DebugPaillierEncryption(packedBuckets);
						}
						//the encryption is not empty, so we add values to it using homomorphic addition
						else {
							/*
							this->privacyServiceProvider.lock()->DebugPaillierEncryption(this->normalizedScaledRatings[i][item]);
							std::cout << this->emptyBuckets[bucketCount].ToString() << std::endl << std::endl;
							*/
							packedBuckets = packedBuckets + normalizedScaledRatings[i][item] * (this->emptyBuckets[bucketCount] << 1);
							//this->privacyServiceProvider.lock()->DebugPaillierEncryption(packedBuckets);
						}

						//if all the buckets inside the encryption are full, persist the encryption and reset the bucket counter
						if (bucketCount == this->maxPackedBuckets - 1) {
							packedItems.emplace_back(packedBuckets);
							bucketCount = 0;
						}
						else {
							++bucketCount;
						}
					}
				}

				//store the last packed buckets for the current item
				if (bucketCount > 0) {
					packedItems.emplace_back(packedBuckets);
				}

				/// Store @f$ [v_{(user, item)}^c] @f$
				if (packedItems.size() > 0) {
					userPackedDenselyRelatedItems.emplace_back(packedItems);
				}
			}

			std::cout << "Packed items for user " << user << " in " << userTimer.ToString() << std::endl;

			if (userPackedDenselyRelatedItems.size() > 0) {
				this->packedNormalizedScaledRatings.emplace_back(userPackedDenselyRelatedItems);
			}
		}
	}

	/**
	Computes @f$ [SIM^{Packed}] = ([SIM_0^{Packed}], ... [SIM_{N - 1}^{Packed}]) @f$, where @f$ [SIM_A^{Packed}] = [sim_{(A, 0)} | sim_{(A, 1)} | ... | sim_{(A, N - 1)}] = \left[ \displaystyle\sum_{j = 0}^{R - 1}{v_{A, j}^c \tilde{v}_{A, j}^d} \right] = \displaystyle\prod_{j = 0}^{R - 1}{[v_{A, j}^c \tilde{v}_{A, j}^d]} = \displaystyle\prod_{j = 0}^{R - 1}{[v_{A, j}^c] \otimes [\tilde{v}_{A, j}^d]} @f$

	@param normalizedScaledRatings @f$ [\tilde{V}_i^d] @f$
	*/
	void ServiceProvider::ComputeSimilarityValues (const EncryptedUserDataContainer &normalizedScaledRatings) {
		//the packedNormalizedScaledRatings contain only the upper triangle of the similarity matrix (excluding the diagonal) because sim(A, B) = sim(B, A)
	#ifdef FIRST_USER_ONLY
		for (size_t user = 0; user < 1; ++user) {
	#else
		for (size_t user = 0; user < this->packedNormalizedScaledRatings.size(); ++user) {
	#endif
			//measure the time it takes to compute the similarity values for each user
			Utils::CpuTimer similarityTimer;

			/// Initialize @f$ [SIM_{user}^{Packed}] @f$ with @f$ [v_{user, 0}^c] \otimes [\tilde{v}_{user, 0}^d] @f$
			PackedData packedSimilarityValues;
			for (size_t i = 0; i < this->packedNormalizedScaledRatings[user][0].size(); ++i) {
				packedSimilarityValues.emplace_back(this->secureMultiplicationServer->Multiply(this->packedNormalizedScaledRatings[user][0][i], normalizedScaledRatings[user][0]));
				
				//this->privacyServiceProvider.lock()->DebugPaillierEncryption(userPackedSimilarityValues.back());
			}

			/// Compute @f$ [SIM_{user}^{Packed}] = [SIM_{user}^{Packed}] \displaystyle\prod_{j = 1}^{R - 1}{[v_{A, j}^c] \otimes [\tilde{v}_{A, j}^d]} @f$
			for (size_t item = 1; item < this->denselyRatedItemCount; ++item) {
				for (size_t i = 0; i < this->packedNormalizedScaledRatings[user][item].size(); ++i) {
					packedSimilarityValues[i] = packedSimilarityValues[i] + (this->secureMultiplicationServer->Multiply(this->packedNormalizedScaledRatings[user][item][i], normalizedScaledRatings[user][item]));

					//this->privacyServiceProvider.lock()->DebugPaillierEncryption(userPackedSimilarityValues.back());
				}
			}

			std::cout << "Similarity processing: " << similarityTimer.ToString();

			//measure the time it takes to compute the gamma values for each user
			Utils::CpuTimer gammaTimer;

			/// Compute @f$ [\gamma_{(user)}] @f$
			/*
			for each user, we have userCount - 1 similarity values, and, since sim(A, A) does not exist and sim(A, B) = sim(B, A), we need to compute fewer by one similarity values for each user.
			The number of buckets in the last encryption of packedSimilarityValues is: (rowSimilarityCount) % maxPackedBuckets
			*/
			size_t rowSimilarityCount = this->userCount - 1 - user;
			this->gamma.emplace_back(this->secureComparisonServer->Compare(packedSimilarityValues, rowSimilarityCount % this->maxPackedBuckets));

			std::cout << " Gamma processing (" << this->gamma.back().size() << " values): " << gammaTimer.ToString() << " for user " << user << std::endl;
		}
	}
	
	/**
	Computes @f$ [L] @f$ and @f$ [UR_{sum}] @f$ for each user

	@f$ [L] = \left[\displaystyle\sum_{i = 0}^{N - 2}{\gamma_{(A, i)}}\right] = \displaystyle\prod_{i=0}^{N - 2}{[\gamma_{(A, i)}]} @f$

	@f$ [UR_{user}^{sum}] = \left[\displaystyle\sum_{i = 0, \gamma_{(A, i)} == 1}^{N - 2}{V_i^{Packed}}\right] = \prod_{i = 0}^{N - 2}{[UR_i^{Packed}]} @f$, where @f$ [UR_i^{Packed}] = [V_i^{Packed}] \otimes [\gamma_{(A, i)}] @f$

	@param sparseRatings @f$ [V_i^{Packed}] @f$
	*/
	void ServiceProvider::ComputeUserRecommendations (const PackedItems &sparseRatings) {
	#ifdef FIRST_USER_ONLY
		for (size_t user = 0; user < 1; ++user) {
	#else
		for (size_t user = 0; user < this->userCount; ++user) {
	#endif
			//measure the time it takes to compute L and URSum for each user
			Utils::CpuTimer recommendationsTimer;

			/// Initialize @f$ L @f$ with the first value
			Paillier::Ciphertext L = this->gamma[0][user == 0 ? user : user - 1];//gamma(i, 0) = gamma(0, i)

			/// Initialize @f$ [UR_{user}^{sum}] @f$ with @f$ [V_0^{Packed}] \otimes [\gamma_{(user, 0)}] @f$
			PackedData userURSum;
			for (size_t encryptionIndex = 0; encryptionIndex < sparseRatings[user].size(); ++encryptionIndex) {
				//gamma(i, 0) = gamma(0, i)
				userURSum.emplace_back(this->secureMultiplicationServer->Multiply(sparseRatings[user == 0 ? 1 : 0][encryptionIndex], this->gamma[0][user == 0 ? user : user - 1]));//gamma(i, 0) = gamma(0, i)
			}

			/**
			Compute the rest of @f$ [L] @f$: @f$ \left[\displaystyle\sum_{i = 1}^{N - 2}{\gamma_{(A, i)}}\right] @f$
			Compute the rest of @f$ [UR_{user}^{sum}] @f$: @f$ \left[\displaystyle\sum_{i = 1, \gamma_{(A, i)} == 1}^{N - 2}{V_i^{Packed}}\right] @f$
			*/
			for (size_t i = (user == 0 ? 2 : 1); i < this->userCount; ++i) {
				if (i != user) {
					//compute the row and column indices for gamma (gamma(A, B) = gamma(B, A), and this->gamma contains only gamma(A, B), where A != B)
					size_t gammaRow = user < i ? user : i;
					size_t gammaColumn = user < i ? i - 1 - user : user - 1 - i;

					L = L + this->gamma[gammaRow][gammaColumn];

					for (size_t encryptionIndex = 0; encryptionIndex < sparseRatings[i].size(); ++encryptionIndex) {
						userURSum[encryptionIndex] = userURSum[encryptionIndex] + this->secureMultiplicationServer->Multiply(sparseRatings[i][encryptionIndex], this->gamma[gammaRow][gammaColumn]);
					}
				}
			}
			this->LValues.push_back(L);
			this->URSumContainer.emplace_back(userURSum);

			std::cout << "Generated recommendations for user " << user << " in " << recommendationsTimer.ToString() << std::endl;
			//this->privacyServiceProvider.lock()->DebugPaillierEncryption(this->LValues.back());
		}
	}

	/**
	@param userId The index of the user
	@return @f$ [L_{user}] @f$
	*/
	const Paillier::Ciphertext &ServiceProvider::GetEncryptedL (const size_t userId) const {
		return this->LValues.at(userId);
	}

	/**
	@param userId The index of the user
	@return @f$ [UR_{sum}^{user}] @f$
	*/
	const ServiceProvider::PackedData &ServiceProvider::GetEncryptedURSum (const size_t userId) const {
		return this->URSumContainer.at(userId);
	}

#if 0
	/**
	This method should be called whenever URSum needs to be recomputed. For now, we assume that Lhat is configured to be large enough such that this is not required.

	@param userId The index of the user
	@param userPackedSparseRatings the re-packed sparse ratings
	@return @f$ [UR_{sum}^{user}] @f$
	*/
	const ServiceProvider::PackedData ServiceProvider::ComputeURSum (const size_t userId, const PackedData &userPackedSparseRatings) const {
		// We need to recompute the packedSparseRatings for all users first...
		PackedData output;

		/// Initialize @f$ [UR_{user}^{sum}] @f$ with @f$ [V_0^{Packed}] \otimes [\gamma_{(user, 0)}] @f$
		for (size_t encryptionIndex = 0; encryptionIndex < userPackedSparseRatings.size(); ++encryptionIndex) {
			output.emplace_back(this->secureMultiplicationServer->Multiply(userPackedSparseRatings[encryptionIndex], this->gamma[userId][0]));
		}

		/// Compute the rest of @f$ [UR_{user}^{sum}] @f$: @f$ \left[\displaystyle\sum_{i = 1, \gamma_{(A, i)} == 1}^{N - 2}{V_i^{Packed}}\right] @f$
		for (size_t i = 1; i < this->gamma[userId].size(); ++i) {
			for (size_t encryptionIndex = 0; encryptionIndex < userPackedSparseRatings.size(); ++encryptionIndex) {
				output[encryptionIndex] = output[encryptionIndex] + this->secureMultiplicationServer->Multiply(userPackedSparseRatings[encryptionIndex], this->gamma[userId][i]);
			}
		}

		return output;
	}
#endif

	/**
	@param privacyServiceProvider a PrivacyServiceProvider instance
	*/
	void ServiceProvider::SetPrivacyServiceProvider (const std::shared_ptr<const PrivacyServiceProvider> &privacyServiceProvider) {
		this->privacyServiceProvider = privacyServiceProvider;
		this->secureComparisonServer->SetClient(privacyServiceProvider->GetSecureComparisonClient());
		this->secureMultiplicationServer->SetClient(privacyServiceProvider->GetSecureMultiplicationClient());
	}

	/**
	@return the data bucket size
	*/
	size_t ServiceProvider::GetBucketSize () const {
		return this->bucketSize;
	}

	/**
	@return the maximum number of data buckets that can be placed in one encryption
	*/
	size_t ServiceProvider::GetMaxPackedBuckets () const {
		return this->maxPackedBuckets;
	}

	/**
	@return The SecureComparisonServer instance.
	*/
	const std::shared_ptr<SecureComparisonServer> &ServiceProvider::GetSecureComparisonServer () const {
		return this->secureComparisonServer;
	}

	/**
	@return The SecureMultiplicationServer instance.
	*/
	const std::shared_ptr<SecureMultiplicationServer<Paillier>> &ServiceProvider::GetSecureMultiplicationServer () const {
		return this->secureMultiplicationServer;
	}

}//namespace PrivateRecommendationsDataPacking
}//namespace SeComLib