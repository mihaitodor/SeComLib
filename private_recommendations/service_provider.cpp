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
@file private_recommendations/service_provider.cpp
@brief Implementation of class ServiceProvider.
@details The Service Provider (SP) has a business interest in generating recommendations for his customers. He has resources for storage and processing.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "service_provider.h"
//avoid circular includes
#include "privacy_service_provider.h"

namespace SeComLib {
namespace PrivateRecommendations {
	/**
	Set the configuration path.
	*/
	const std::string ServiceProvider::configurationPath("PrivateRecommendations");

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
		ratingBitSize(Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".t")),
		digitsToPreserve(Utils::Config::GetInstance().GetParameter<unsigned int>(configurationPath + ".digitsToPreserve")),
		//the similarity threshold needs to be scaled twice as much as the normalized ratings, due to the way the similarity values are computed
		similarityTreshold(BigInteger(Utils::Config::GetInstance().GetParameter<double>(configurationPath + ".similarityTreshold"), 2 * digitsToPreserve)),
		ratingsFilePath(Utils::Config::GetInstance().GetParameter<std::string>(configurationPath + ".ratingsFilePath")),
		secureComparisonServer(std::make_shared<SecureComparisonServer>(paillierCryptoProvider, dgkCryptoProvider, similarityTreshold, configurationPath)),
		secureMultiplicationServer(std::make_shared<SecureMultiplicationServer<Paillier>>(paillierCryptoProvider, Utils::Config::GetInstance().GetParameter<size_t>(configurationPath + ".l"), configurationPath)) {
	}

	/**
	Generates @f$ M @f$ item ratings for each of the @f$ N @f$ users and scales them.
	
	Encrypts the scaled normalized densely related ratings: @f$ [\tilde{V}_i^d] = ([\tilde{v}_{(i, 0)}^d], ..., [\tilde{v}_{(i, R - 1)}^d])^T @f$
	and the sparse ratings for the rest of the items: @f$ [V_i^p] = ([v_{(i, 0)}^p], ..., [v_{(i, M - R - 1)}^p])^T @f$.
	
	@throws std::runtime_error the ratings file can't be opened
	*/
	void ServiceProvider::GenerateDummyDatabase () {
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

			EncryptedUserData userSparseRatings;
			//fetch the value
			unsigned long rating;
			while (lineStream >> rating) {
				userSparseRatings.emplace_back(this->paillierCryptoProvider.EncryptInteger(rating));
			}
			this->sparseRatings.emplace_back(userSparseRatings);
		}

	#if 0//auto-generate ratings
		for (size_t user = 0; user < this->userCount; ++user) {
			EncryptedUserData userNormalizedScaledRatings;
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

			EncryptedUserData userSparseRatings;
			for (size_t item = this->denselyRatedItemCount; item < this->itemCount; ++item) {
				//insert random values >= 0 and <= max
				userSparseRatings.emplace_back(this->paillierCryptoProvider.EncryptInteger(RandomProvider::GetInstance().GetRandomInteger(ratingBitSize)));
			}
			this->sparseRatings.emplace_back(userSparseRatings);
		}
	#endif
	}

	/**
	Computes @f$ [sim_{(A, B)}] = \prod_{r = 0}^{R-1}{[\tilde{v}_{(A, r)}^d \tilde{v}_{(B, r)}^d]} = \prod_{r = 0}^{R-1}{([\tilde{v}_{(A, r)}^d] \otimes [\tilde{v}_{(B, r)}^d])} @f$, where @f$ A < B @f$, because @f$ [sim_{(A, B)}] = [sim_{(B, A)}] @f$

	Computes the @f$ [\Gamma] @f$ vector for each user, where @f$ [\Gamma_A] = ([\gamma_{(A, 0)}], [\gamma_{(A, 1)}], ..., [\gamma_{(A, N - 2)}])^T @f$, where @f$ [\gamma_{(A, i)}] = sim_{(A, i)} >= \delta ? [1] : [0] @f$
	*/
	void ServiceProvider::ComputeSimilarityValues () {
	#ifdef FIRST_USER_ONLY
		for (size_t i = 0; i < 1; ++i) {
	#else
		for (size_t i = 0; i < this->userCount; ++i) {
	#endif
			//measure the time it takes to compute the similarity values for each user
			Utils::CpuTimer similarityTimer;

			EncryptedUserData userSimilarityValues;
			for (size_t j = 0; j < this->userCount; ++j) {
				//sim(i, i) does not exist and sim(A, B) = sim(B, A), so we compute only sim(A, B) (the upper triangle of the matrix, without the diagonal)
				if (j > i) {
					//initialize the sum with the first item (saves one homomorphic addition)
					userSimilarityValues.emplace_back(this->secureMultiplicationServer->Multiply(this->normalizedScaledRatings[i][0], this->normalizedScaledRatings[j][0]));

					for (size_t item = 1; item < this->denselyRatedItemCount; ++item) {
						userSimilarityValues.back() = userSimilarityValues.back() + this->secureMultiplicationServer->Multiply(this->normalizedScaledRatings[i][item], this->normalizedScaledRatings[j][item]);
					}

					/*
					std::cout << "sim(" << i << "," << j << "): ";
					this->privacyServiceProvider.lock()->DebugPaillierEncryption(userSimilarityValues.back());
					*/
				}
			}

			std::cout << "Similarity processing: " << similarityTimer.ToString();

			//measure the time it takes to compute the gamma values for each user
			Utils::CpuTimer gammaTimer;

			for (EncryptedUserData::const_iterator similarity = userSimilarityValues.begin(); similarity != userSimilarityValues.end(); ++similarity) {
				this->gammaValues.emplace_back(this->secureComparisonServer->Compare(*similarity));

				/*
				std::cout << "gamma(" << i << "," << j << "): ";
				this->privacyServiceProvider.lock()->DebugPaillierEncryption(this->gammaValues.back());
				*/
			}

			std::cout << " Gamma processing (" << userSimilarityValues.size() << " values): " << gammaTimer.ToString() << " for user " << i << std::endl;
		}
	}
	
	/**
	Computes @f$ [L] @f$ and @f$ [UR_{sum}] @f$ for each user

	@f$ [L] = \left[ \displaystyle\sum_{i = 0}^{N - 2}{\gamma_{(A, i)}} \right] = \displaystyle\prod_{i=0}^{N - 2}{[\gamma_{(A, i)}]} @f$

	@f$ [UR_i] := ([\gamma_{(A, i)}] \otimes [v_{(i, 0)}^p], ..., [\gamma_{(A, i)}] \otimes [v_{(i, M - R - 1)}^p])^T = ([\gamma_{(A, i)} v_{(i, 0)}^p], ..., [\gamma_{(A, i)} v_{(i, M - R - 1)}^p])^T = ([UR_{(i, 0)}], ..., [UR_{(i, M - R - 1)}])^T @f$

	where @f$ [UR_i] = \left\{ \begin{array}{lc} [V_{(i, j)}^p], & if \; \gamma_{(A, i)} \; is \; 1 \\ ([0], ..., [0])^T, & if \; \gamma_{(A, i)} \; is \; 0 \end{array} \right. @f$

	@f$ [UR_{user}^{sum}] = \left( \displaystyle\prod_{i = 0}^{N - 2}{[UR_{(i, 0)}]}, ..., \displaystyle\prod_{i = 0}^{N - 2}{[UR_{(i, M - R - 1)}]} \right)^T = \left( \left[ \displaystyle\sum_{i = 0}^{N - 2}{UR_{(i, 0)}} \right], ..., \left[\displaystyle\sum_{i = 0}^{N - 2}{UR_{(i, M - R - 1)}}\right] \right)^T @f$
	*/
	void ServiceProvider::ComputeUserRecommendations () {
	#ifdef FIRST_USER_ONLY
		for (size_t user = 0; user < 1; ++user) {
	#else
		for (size_t user = 0; user < this->userCount; ++user) {
	#endif
			//measure the time it takes to compute L and URSum for each user
			Utils::CpuTimer recommendationsTimer;

			/// Initialize L with the first gamma value (note that @f$ \gamma_{(A, B)} = \gamma_{(B, A)} @f$)
			/*
			for user 0, the first value is gamma(0, 1) = gammaValues[0]
			for user 1, gamma(1, 0) = gamma(0, 1) = gammaValues[0]
			for user 2, gamma(2, 0) = gamma(0, 2) = gammaValues[1]
			...
			*/
			Paillier::Ciphertext userLValue = this->gammaValues[user == 0 ? 0 : user - 1];

			EncryptedUserData userURSum;
			/// Compute @f$ \left( [UR_{(0, 0)}], ..., [UR_{(0, M - R - 1)}] \right) @f$
			for (size_t item = 0; item < this->itemCount - this->denselyRatedItemCount; ++item) /* //item < M - R */ {
				userURSum.emplace_back(this->secureMultiplicationServer->Multiply(this->gammaValues[user == 0 ? 0 : user - 1], this->sparseRatings[user == 0 ? 1 : 0][item]));
			}

			/// Compute the rest: @f$ \left( \displaystyle\prod_{i = 1}^{N - 2}{[UR_{(i, 0)}]}, ..., \displaystyle\prod_{i = 1}^{N - 2}{[UR_{(i, M - R - 1)}]} \right) @f$
			for (size_t i = (user == 0 ? 2 : 1); i < this->userCount; ++i) {
				if (i != user) {
					/// Compute the gammaValues vector index from the matrix indices
					size_t gammaIndex;
					if (user < i)
						gammaIndex = user * this->userCount + i - (user + 1) * (user + 2) / 2;
					else
						gammaIndex = i * this->userCount + user - (i + 1) * (i + 2) / 2;

					userLValue = userLValue + this->gammaValues[gammaIndex];

					/// Compute @f$ \displaystyle\prod_{i = 0}^{N - 2}{[UR_{(i, j)}]} @f$
					for (size_t item = 0; item < this->itemCount - this->denselyRatedItemCount; ++item)/* item < M - R */ {
						userURSum[item] = userURSum[item] + this->secureMultiplicationServer->Multiply(this->gammaValues[gammaIndex], this->sparseRatings[i][item]);
					}
				}
			}

			this->LValues.emplace_back(userLValue);

			this->URSumContainer.emplace_back(userURSum);

			/*
			std::cout << "L(" << user << "): ";
			this->privacyServiceProvider.lock()->DebugPaillierEncryption(userLValue);
			*/

			std::cout << "Generated recommendations for user " << user << " in " << recommendationsTimer.ToString() << std::endl;
		}
	}

	/**
	@param userId The index of the user
	@return @f$ [L] @f$
	*/
	const Paillier::Ciphertext &ServiceProvider::GetEncryptedL (size_t userId) const {
		return this->LValues.at(userId);
	}

	/**
	@param userId The index of the user
	@return @f$ [UR_{user}^{sum}] @f$
	*/
	const ServiceProvider::EncryptedUserData &ServiceProvider::GetEncryptedURSum (size_t userId) const {
		return this->URSumContainer.at(userId);
	}

	/**
	@param privacyServiceProvider a PrivacyServiceProvider instance
	*/
	void ServiceProvider::SetPrivacyServiceProvider (const std::shared_ptr<const PrivacyServiceProvider> &privacyServiceProvider) {
		this->privacyServiceProvider = privacyServiceProvider;
		this->secureComparisonServer->SetClient(privacyServiceProvider->GetSecureComparisonClient());
		this->secureMultiplicationServer->SetClient(privacyServiceProvider->GetSecureMultiplicationClient());
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

}//namespace PrivateRecommendations
}//namespace SeComLib