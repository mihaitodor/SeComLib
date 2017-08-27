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
@file private_recommendations/service_provider.h
@brief Definition of class ServiceProvider.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SERVICE_PROVIDER_HEADER_GUARD
#define SERVICE_PROVIDER_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "utils/date_time.h"
#include "utils/cpu_timer.h"
#include "core/big_integer.h"
#include "core/random_provider.h"
#include "core/paillier.h"
#include "core/dgk.h"
#include "core/secure_multiplication_server.h"

#include "private_recommendations_utils/secure_comparison_server.h"


//include C++ libraries
#include <fstream>
#include <string>
#include <sstream>
#include <deque>
#include <stdexcept>

namespace SeComLib {

using namespace Core;
using namespace PrivateRecommendationsUtils;

//hackish way of computing everything for only a single user (see also client.h)
#define FIRST_USER_ONLY

namespace PrivateRecommendations {
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

		/// Constructor
		ServiceProvider (const PaillierPublicKey &paillierPublicKey, const DgkPublicKey &dgkPublicKey);

		/// Destructor - void implementation
		~ServiceProvider () {}

		/// Generates a dummy database for the users
		void GenerateDummyDatabase ();

		/// Computes the similarity values between each pair of users for the first @f$ R @f$ items
		void ComputeSimilarityValues ();

		/// Computes @f$ [\Gamma] @f$, @f$ [L] @f$ and @f$ [UR_{sum}] @f$ for each user
		void ComputeUserRecommendations ();

		/// Returns the @f$ [L] @f$ value for the specified user
		const Paillier::Ciphertext &GetEncryptedL (size_t userId) const;

		/// Returns the @f$ [UR_{sum}] @f$ vector for the specified user
		const EncryptedUserData &GetEncryptedURSum (size_t userId) const;

		/// Sets a reference to the Privacy Service Provider
		void SetPrivacyServiceProvider (const std::shared_ptr<const PrivacyServiceProvider> &privacyServiceProvider);

		/// Getter for this->secureComparisonServer
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

		/// The size of the user ratings (in bits)
		size_t ratingBitSize;

		/// Number of digits preserved from the normalized user ratings
		unsigned int digitsToPreserve;

		/// @f$ s^2 \delta @f$ - Scaled public threshold value for the similarity values
		BigInteger similarityTreshold;

		/// The path to the file containing precomputed ratings
		std::string ratingsFilePath;

		/// @f$ [\tilde{V}_i^d] @f$
		EncryptedUserDataContainer normalizedScaledRatings;

		/// @f$ [V_i^p] @f$
		EncryptedUserDataContainer sparseRatings;

		/// @f$ [\Gamma] @f$
		EncryptedUserData gammaValues;

		/// Vector of @f$ [L] @f$ values, where L is the number of users similar to a given user
		EncryptedUserData LValues;

		/// Contains the @f$ [UR_{sum}] @f$ vectors for each user
		EncryptedUserDataContainer URSumContainer;

		/// A reference to the SecureComparisonServer
		const std::shared_ptr<SecureComparisonServer> secureComparisonServer;

		/// A reference to the SecureMultiplicationServer
		std::shared_ptr<SecureMultiplicationServer<Paillier>> secureMultiplicationServer;

		/// Service Provider configuration path
		static const std::string configurationPath;

		/// Copy constructor - not implemented
		ServiceProvider (ServiceProvider const &);

		/// Copy assignment operator - not implemented
		ServiceProvider operator= (ServiceProvider const &);
	};
}//namespace PrivateRecommendations
}//namespace SeComLib

#endif//SERVICE_PROVIDER_HEADER_GUARD