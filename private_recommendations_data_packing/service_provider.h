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
@file private_recommendations_data_packing/service_provider.h
@brief Definition of class ServiceProvider.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SERVICE_PROVIDER_HEADER_GUARD
#define SERVICE_PROVIDER_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "utils/cpu_timer.h"
#include "core/big_integer.h"
#include "core/random_provider.h"
#include "core/paillier.h"
#include "core/secure_multiplication_server.h"

#include "secure_comparison_server.h"


//include C++ libraries
#include <string>
#include <deque>
#include <stdexcept>

namespace SeComLib {
using namespace Core;
using namespace PrivateRecommendationsUtils;

//hackish way of computing everything for only a single user (see also client.h)
#define FIRST_USER_ONLY

namespace PrivateRecommendationsDataPacking {
	//forward-declare required classes
	class PrivacyServiceProvider;

	/**
	@brief Service Provider
	*/
	class ServiceProvider {
	public:
		/// Encrypted user data
		typedef std::deque<Paillier::Ciphertext> EncryptedUserData;

		/// Container for encrypted user data
		typedef std::deque<EncryptedUserData> EncryptedUserDataContainer;

		/// Packed data
		typedef std::deque<Paillier::Ciphertext> PackedData;

		/// Packed items
		typedef std::deque<PackedData> PackedItems;

		/// Container for packed items
		typedef std::deque<PackedItems> PackedItemContainer;

		/// Constructor
		ServiceProvider (const PaillierPublicKey &paillierPublicKey, const DgkPublicKey &dgkPublicKey);

		/// Destructor - void implementation
		~ServiceProvider () {}

		/// Generates a dummy database for the users
		void GenerateDummyDatabase (const EncryptedUserDataContainer &normalizedScaledRatings);

		/// Computes the similarity values between each pair of users for the first @f$ R @f$ items
		void ComputeSimilarityValues (const EncryptedUserDataContainer &normalizedScaledRatings);

		/// Computes @f$ [\Gamma] @f$, @f$ [L] @f$ and @f$ [UR_{sum}] @f$ for each user
		void ComputeUserRecommendations (const PackedItems &sparseRatings);

		/// Returns the @f$ [L] @f$ value for the specified user
		const Paillier::Ciphertext &GetEncryptedL (const size_t userId) const;

		/// Returns the @f$ [UR_{sum}] @f$ vector for the specified user
		const PackedData &GetEncryptedURSum (const size_t userId) const;

	#if 0
		/// Re-computes the @f$ [UR_{sum}] @f$ vector for the specified user
		const PackedData ComputeURSum (const size_t userId, const PackedData &userPackedSparseRatings) const;
	#endif

		/// Sets a reference to the Privacy Service Provider
		void SetPrivacyServiceProvider (const std::shared_ptr<const PrivacyServiceProvider> &privacyServiceProvider);

		/// Getter for the data bucket size
		size_t GetBucketSize () const;

		/// Getter for the maximum number of packed data buckets
		size_t GetMaxPackedBuckets () const;

		/// Getter for this->secureComparisonClient
		const std::shared_ptr<SecureComparisonServer> &GetSecureComparisonServer () const;

		/// Getter for this->secureMultiplicationServer
		const std::shared_ptr<SecureMultiplicationServer<Paillier>> &GetSecureMultiplicationServer () const;

	private:
		/// A reference to the PrivacyServiceProvider
		std::weak_ptr<const PrivacyServiceProvider> privacyServiceProvider;

		/// Paillier crypto provider
		Paillier paillierCryptoProvider;

		/// DGK crypto provider
		Dgk dgkCryptoProvider;

		/// Number of users who need recommendations
		size_t userCount;

		/// Number of ratings per user
		size_t itemCount;

		/// Number of densely rated items
		size_t denselyRatedItemCount;

		/// k - The size of the scaled normalized ratings (in bits) (should be l / 2?)
		size_t scaledNormalizedRatingBitSize;

		/// Number of digits preserved from the normalized user ratings
		unsigned int digitsToPreserve;

		/// The security parameter for the secure comparison protocol (in bits)
		size_t kappa;

		/// @f$ s^2 \delta @f$ - Scaled public threshold value for the similarity values
		BigInteger similarityTreshold;

		/// The size of the data buckets (in bits)
		size_t bucketSize;

		/// The maximum number of buckets that fit in one encryption
		size_t maxPackedBuckets;

		/// Empty buckets @f$ (2^{l + 2})^i @f$
		std::deque<BigInteger> emptyBuckets;

		/// @f$ [V^c] = {[V_0^c], [V_1^c], ..., [V_{N - 1}^c]} @f$, where @f$ [V_A^c] = ([v_{(A, 0)}^c], ..., [v_{(A, R - 1)}^c])^T @f$, @f$ A \in [0, N - 1] @f$
		PackedItemContainer packedNormalizedScaledRatings;

		/// @f$ [\Gamma_i] @f$ - the encrypted gamma values for every user (the upper triangle of the matrix, excluding the diagonal)
		EncryptedUserDataContainer gamma;

		/// Vector of @f$ [L] @f$ values, where L is the number of users similar to a given user
		EncryptedUserData LValues;

		/// Contains the @f$ [UR_{sum}] @f$ vectors for each user
		PackedItems URSumContainer;

		/// A reference to the SecureComparisonServer
		std::shared_ptr<SecureComparisonServer> secureComparisonServer;

		/// A reference to the SecureMultiplicationServer
		std::shared_ptr<SecureMultiplicationServer<Paillier>> secureMultiplicationServer;

		/// Service Provider configuration path
		static const std::string configurationPath;

		/// Copy constructor - not implemented
		ServiceProvider (ServiceProvider const &);

		/// Copy assignment operator - not implemented
		ServiceProvider operator= (ServiceProvider const &);
	};
}//namespace PrivateRecommendationsDataPacking
}//namespace SeComLib

#endif//SERVICE_PROVIDER_HEADER_GUARD