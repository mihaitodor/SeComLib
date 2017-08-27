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
@file private_recommendations_data_packing/client.cpp
@brief Implementation of class Client.
@details A test client that wants to receive recommendations
@author Mihai Todor (todormihai@gmail.com)
*/

#include "client.h"

namespace SeComLib {
namespace PrivateRecommendationsDataPacking {
	/**
	Set the configuration path.
	*/
	const std::string Client::configurationPath("PrivateRecommendationsDataPacking");

	/**
	Assumes that the client has a secure channel to the PrivacyServiceProvider.

	@param serviceProvider a ServiceProvider instance
	@param privacyServiceProvider a PrivacyServiceProvider instance
	@param publicKey the Paillier public key of the PrivacyServiceProvider

	@throws std::runtime_error the ratings file can't be opened
	*/
	Client::Client (const std::shared_ptr<ServiceProvider> &serviceProvider, const std::shared_ptr<PrivacyServiceProvider> &privacyServiceProvider, const PaillierPublicKey &publicKey) :
		serviceProvider(serviceProvider),
		privacyServiceProvider(privacyServiceProvider),
		paillierCryptoProvider(publicKey),
		userCount(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".userCount")),
		itemCount(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".itemCount")),
		denselyRatedItemCount(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".denselyRatedItemCount")),
		ratingBitSize(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".t")),
		scaledNormalizedRatingBitSize(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".scaledNormalizedRatingBitSize")),
		digitsToPreserve(Utils::Config::GetInstance().GetParameter<unsigned int>(configurationPath + ".digitsToPreserve")),
		kappa(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".BlindingFactorCache.kappa")),
		hatL(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".hatL")),
		ratingsFilePath(Utils::Config::GetInstance().GetParameter<std::string>(configurationPath + ".ratingsFilePath")),
		LdecryptionBlindingFactorCache(paillierCryptoProvider, BlindingFactorCacheParameters(configurationPath + ".BlindingFactorCache", BigInteger(static_cast<unsigned long>(userCount - 1)).GetSize())),//compute the number of bits required to store the maximum value for L
		URSumDecryptionBlindingFactorCache(paillierCryptoProvider, BlindingFactorCacheParameters(configurationPath + ".BlindingFactorCache", serviceProvider->GetMaxPackedBuckets() * serviceProvider->GetBucketSize())) {
		/// Compute the empty buckets first
		this->emptyBuckets = this->computeEmptyBuckets(this->hatL);

		/// Load ratings from file
		std::ifstream ratingsFile(this->ratingsFilePath);
		if (!ratingsFile.is_open()) {
			throw std::runtime_error("Can't open the ratings file.");
		}
		std::string line;
		//foreach user
		while (std::getline(ratingsFile, line)) {
			std::istringstream lineStream(line);

			ServiceProvider::EncryptedUserData userNormalizedScaledRatings;
			std::deque<unsigned long> userRatings;
			double squaredSum = 0.0;

			for (size_t item = 0; item < this->denselyRatedItemCount; ++item) {
				//fetch the value
				unsigned long rating;
				lineStream >> rating;

				squaredSum += static_cast<double>(rating * rating);

				userRatings.emplace_back(rating);
			}

			double denominator = std::sqrt(squaredSum);
			for (size_t item = 0; item < this->denselyRatedItemCount; ++item) {
				double normalizedValue = static_cast<double>(userRatings[item]) / denominator;
				//truncate the remaining digits after scaling
				userNormalizedScaledRatings.emplace_back(this->paillierCryptoProvider.EncryptInteger(BigInteger(normalizedValue, this->digitsToPreserve, true)));
			}
			this->normalizedScaledRatings.emplace_back(userNormalizedScaledRatings);

			std::deque<unsigned long> userPlaintextSparseRatings;

			//fetch the value
			unsigned long rating;
			while (lineStream >> rating) {
				userPlaintextSparseRatings.emplace_back(rating);
			}
			this->plaintextSparseRatings.emplace_back(userPlaintextSparseRatings);

			/// Pack the sparse ratings
			this->sparseRatings.emplace_back(this->packUserSparseRatings(this->plaintextSparseRatings.back(), this->emptyBuckets));
		}

	#if 0//auto-generate ratings
		/// Generate user data
		for (size_t user = 0; user < this->userCount; ++user) {
			ServiceProvider::EncryptedUserData userNormalizedScaledRatings;
			std::deque<unsigned long> userRatings;
			double squaredSum = 0.0;
			for (size_t item = 0; item < this->denselyRatedItemCount; ++item) {
				//insert random values > 0 and <= max
				BigInteger random;
				do {
					random = RandomProvider::GetInstance().GetRandomInteger(ratingBitSize);
				}
				while (random == 0);
				unsigned long randomValue = random.ToUnsignedLong();

				squaredSum += static_cast<double>(randomValue * randomValue);

				userRatings.emplace_back(randomValue);
			}

			double denominator = std::sqrt(squaredSum);
			for (size_t item = 0; item < this->denselyRatedItemCount; ++item) {
				double normalizedValue = static_cast<double>(userRatings[item]) / denominator;
				//truncate the remaining digits after scaling
				userNormalizedScaledRatings.emplace_back(this->paillierCryptoProvider.EncryptInteger(BigInteger(normalizedValue, this->digitsToPreserve, true)));
			}
			this->normalizedScaledRatings.emplace_back(userNormalizedScaledRatings);

			std::deque<unsigned long> userPlaintextSparseRatings;
			for (size_t item = this->denselyRatedItemCount; item < this->itemCount; ++item) {
				//generate random values >= 0 and <= max
				userPlaintextSparseRatings.emplace_back(RandomProvider::GetInstance().GetRandomInteger(ratingBitSize).ToUnsignedLong());
			}
			this->plaintextSparseRatings.emplace_back(userPlaintextSparseRatings);

			/// Pack the sparse ratings
			this->sparseRatings.emplace_back(this->packUserSparseRatings(this->plaintextSparseRatings.back(), this->emptyBuckets));
		}
	#endif

	}

	/**
	@return @f$ [\tilde{V}_i^d] @f$ 
	*/
	const ServiceProvider::EncryptedUserDataContainer &Client::GetNormalizedScaledRatings () const {
		return this->normalizedScaledRatings;
	}

	/**
	@return @f$ [V_i^{Packed}] @f$
	*/
	const ServiceProvider::PackedItems &Client::GetSparseRatings () const {
		return this->sparseRatings;
	}

	/**
	Fetches encrypted values from the Service Provider, blinds them and sends them to the Privacy Service Provider for decryption.
	*/
	void Client::ComputeRecommendations () {
	#ifdef FIRST_USER_ONLY
		for (size_t user = 0; user < 1; ++user) {
	#else
		for (size_t user = 0; user < this->userCount; ++user) {
	#endif
			//measure the time it takes to decrypt the recommendations for each user
			Utils::CpuTimer recommendationsProcessingTimer;

			/*
			std::cout << "User " << user << ":" << std::endl << std::endl;
			*/

			/// Fetch @f$ [L] @f$ and @f$ [UR_{sum}] @f$ from the Service Provider
			Paillier::Ciphertext encryptedL = this->serviceProvider->GetEncryptedL(user);

			const BlindingFactorContainer &LBlindingFactor = this->LdecryptionBlindingFactorCache.Pop();

			/// @f$ L = Dec([L][r]) - r @f$
			unsigned long L = (this->privacyServiceProvider->SecureDecryption(encryptedL + LBlindingFactor.encryptedR) - LBlindingFactor.r).ToUnsignedLong();

			/*
			std::cout << "L: " << L << std::endl;
			*/

			ServiceProvider::PackedData encryptedURSum;
			std::deque<BigInteger> userEmptyBuckets = this->emptyBuckets;
			if (L == 0) {
				std::cout << "No similar users found." << std::endl;
				continue;
			}
			/// If @f$ L < \hat{L} @f$ the server computed the proper recommendations
			else if (L < this->hatL) {
				encryptedURSum = this->serviceProvider->GetEncryptedURSum(user);
			}
			/// If @f$ L >= \hat{L} @f$ the sparse ratings need to be repacked and sent to the server in order to recompute the recommendations
			else {
				std::cout << "hatL is too small!" << std::endl;
				continue;
				/*
				/// Re-compute the empty buckets
				userEmptyBuckets = this->computeEmptyBuckets(L);

				/// Re-pack the sparse ratings
				this->sparseRatings[user] = this->packUserSparseRatings(this->plaintextSparseRatings[user], userEmptyBuckets);

				/// Re-compute the recommendations
				encryptedURSum = this->serviceProvider->ComputeURSum(user, this->sparseRatings[user]);
				*/
			}

			/// Unpack @f$ UR_{sum} @f$
			std::vector<unsigned long> URSum;
			size_t bucketCount = 0;
			for (ServiceProvider::PackedData::iterator encryptedURSumIterator = encryptedURSum.begin(); encryptedURSumIterator != encryptedURSum.end(); ++encryptedURSumIterator) {
				const BlindingFactorContainer &URSumBlindingFactor = this->URSumDecryptionBlindingFactorCache.Pop();

				/// @f$ UR_{sum} = Dec([UR_{sum}][r]) - r @f$
				BigInteger packedURSum = this->privacyServiceProvider->SecureDecryption(*encryptedURSumIterator + URSumBlindingFactor.encryptedR) - URSumBlindingFactor.r;

				/// There are (items - denselyRelatedItems) packed buckets in total, so the last encryption may have unpopulated buckets, which we ignore
				for (size_t bucketIndex = 0; bucketIndex < userEmptyBuckets.size() && bucketCount < this->itemCount - this->denselyRatedItemCount; ++bucketIndex) {
					if (bucketIndex < userEmptyBuckets.size() - 1) {
						URSum.push_back(((packedURSum % userEmptyBuckets[bucketIndex + 1]) / userEmptyBuckets[bucketIndex]).ToUnsignedLong());
					}
					else {
						URSum.push_back((packedURSum / userEmptyBuckets[bucketIndex]).ToUnsignedLong());
					}
					++bucketCount;
				}
			}

			/*
			std::cout << "UR_sum:" << std::endl;
			for (std::vector<unsigned long>::const_iterator URSumIterator = URSum.begin(); URSumIterator != URSum.end(); ++URSumIterator) {
				std::cout << *URSumIterator << std::endl;
			}

			std::cout << "Recommendations:" << std::endl;
			for (std::vector<unsigned long>::const_iterator URSumIterator = URSum.begin(); URSumIterator != URSum.end(); ++URSumIterator) {
				std::cout << static_cast<double>(*URSumIterator) / static_cast<double>(L) << std::endl;
			}
			*/

			std::cout << "Processed recommendations for user " << user << " in " << recommendationsProcessingTimer.ToString() << std::endl;
		}
	}

	/**
	@param L the number of similar users
	@return the empty buckets
	*/
	std::deque<BigInteger> Client::computeEmptyBuckets (const size_t L) const {
		std::deque<BigInteger> output;

		/// Precompute @f$ \lceil log_2(\hat{L}) \rceil @f$ and initialize the sparse ratings data packer
		unsigned long ceilLogBaseTwoHatL = static_cast<unsigned long>(std::ceil(std::log(static_cast<double>(L)) / std::log(2.0)));//change base from e to 2 and round up to the nearest integer

		/// @f$ t + \lceil\log{\hat{L}}\rceil @f$
		size_t bucketSize = this->ratingBitSize + ceilLogBaseTwoHatL;

		/**
		We need to reserve @f$ \kappa @f$ extra bits in each encryption in order to perform secure blinding
		In order not to cause overflows during secure blinding, we reserve another 2 extra bits at the top of each encryption, such that if size(r) = size(message space) - 2, then r + d < message space
		*/
		size_t maxPackedBuckets = (this->paillierCryptoProvider.GetMessageSpaceSize() - this->kappa - 2) / bucketSize;

		/// Pre-compute the empty buckets @f$ 2^{i * bucketSize} @f$
		BigInteger one(1);
		for (size_t i = 0; i < maxPackedBuckets; ++i) {
			output.emplace_back(one << (static_cast<unsigned long>(i * bucketSize)));
		}

		return output;
	}

	/**
	@param userPlaintextSparseRatings the plaintext sparse ratings
	@param userEmptyBuckets the empty buckets
	@return packed user sparse ratings
	*/
	ServiceProvider::PackedData Client::packUserSparseRatings (const std::deque<unsigned long> &userPlaintextSparseRatings, const std::deque<BigInteger> &userEmptyBuckets) const {
		ServiceProvider::PackedData userSparseRatings;
		BigInteger packedBuckets;
		size_t bucketCount = 0;
		for (std::deque<unsigned long>::const_iterator rating = userPlaintextSparseRatings.begin(); rating != userPlaintextSparseRatings.end(); ++rating) {
			//the bucket container is empty, so we assign to it the next value
			if (0 == bucketCount) {
				packedBuckets = *rating;
			}
			//the bucket container is not empty, so we add buckets to it
			else {
				packedBuckets += userEmptyBuckets[bucketCount] * (*rating);
			}

			//if all the buckets inside the container are full, encrypt it and reset the bucket counter
			if (bucketCount == userEmptyBuckets.size() - 1) {
				userSparseRatings.emplace_back(this->paillierCryptoProvider.EncryptInteger(packedBuckets));
				bucketCount = 0;
			}
			else {
				++bucketCount;
			}
		}
		//store the last packed buckets
		if (bucketCount > 0) {
			userSparseRatings.emplace_back(this->paillierCryptoProvider.EncryptInteger(packedBuckets));
		}

		return userSparseRatings;
	}

}//namespace PrivateRecommendationsDataPacking
}//namespace SeComLib