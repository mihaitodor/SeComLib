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
@file private_recommendations_data_packing/client.h
@brief Definition of class Client.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef CLIENT_HEADER_GUARD
#define CLIENT_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "utils/date_time.h"
#include "utils/cpu_timer.h"
#include "core/paillier.h"
#include "core/randomizer_cache.h"
#include "core/blinding_factor_cache_parameters.h"

#include "private_recommendations_utils/decryption_blinding_factor_container.h"
#include "service_provider.h"
#include "privacy_service_provider.h"

//include C++ libraries
#include <fstream>
#include <string>
#include <sstream>
#include <deque>
#include <stdexcept>

namespace SeComLib {
using namespace Core;
using namespace PrivateRecommendationsUtils;

//hackish way of computing everything for only a single user (see also service_provider.h)
#define FIRST_USER_ONLY

namespace PrivateRecommendationsDataPacking {
	/**
	@brief Client
	*/
	class Client {
	public:

		/// Constructor
		Client (const std::shared_ptr<ServiceProvider> &serviceProvider, const std::shared_ptr<PrivacyServiceProvider> &privacyServiceProvider, const PaillierPublicKey &publicKey);

		/// Destructor - void implementation
		~Client () {}

		/// Get @f$ [\tilde{V}_i^d] @f$ 
		const ServiceProvider::EncryptedUserDataContainer &GetNormalizedScaledRatings () const;

		/// Get @f$ [V_i^{Packed}] @f$
		const ServiceProvider::PackedItems &GetSparseRatings () const;

		/// Interact with the server(s) to extract the recommendations for every user
		void ComputeRecommendations ();

	private:
		/// Alias for the blinding factor container
		typedef DecryptionBlindingFactorContainer<Paillier, BlindingFactorCacheParameters> BlindingFactorContainer;

		/// A reference to the ServiceProvider
		const std::shared_ptr<ServiceProvider> serviceProvider;

		/// A reference to the PrivacyServiceProvider
		const std::shared_ptr<PrivacyServiceProvider> privacyServiceProvider;

		/// Paillier crypto provider
		Paillier paillierCryptoProvider;

		/// Service Provider configuration path
		static const std::string configurationPath;

		/// Number of users who need recommendations
		size_t userCount;

		/// Number of ratings per user
		size_t itemCount;

		/// Number of densely rated items
		size_t denselyRatedItemCount;

		/// The size of the user ratings (in bits)
		size_t ratingBitSize;

		/// k - The size of the scaled normalized ratings (in bits)
		size_t scaledNormalizedRatingBitSize;

		/// Number of digits preserved from the normalized user ratings
		unsigned int digitsToPreserve;

		/// The security parameter for the secure comparison protocol (in bits)
		size_t kappa;

		/// The upper bound of most similar users (@f$ \hat{L} > L @f$)
		size_t hatL;

		/// Empty buckets @f$ (2^{t + \lceil\log{\hat{L}}\rceil})^i @f$, where @f$ t @f$ is the bit size of the ratings
		std::deque<BigInteger> emptyBuckets;

		/// The path to the file containing precomputed ratings
		std::string ratingsFilePath;

		/// @f$ [\tilde{V}_i^d] @f$
		ServiceProvider::EncryptedUserDataContainer normalizedScaledRatings;

		/// @f$ V_i^p @f$
		std::deque<std::deque<unsigned long>> plaintextSparseRatings;

		/// @f$ [V_i^{Packed}] @f$
		ServiceProvider::PackedItems sparseRatings;

		/// @f$ L @f$ decryption blinding factor cache instance
		RandomizerCache<BlindingFactorContainer> LdecryptionBlindingFactorCache;

		/// @f$ UR^{sum} @f$ decryption blinding factor cache instance
		RandomizerCache<BlindingFactorContainer> URSumDecryptionBlindingFactorCache;

		/// Computes the empty buckets @f$ 2^{i * bucketSize} @f$
		std::deque<BigInteger> computeEmptyBuckets (const size_t L) const;

		/// Pack the sparse ratings for one user
		ServiceProvider::PackedData packUserSparseRatings (const std::deque<unsigned long> &userPlaintextSparseRatings, const std::deque<BigInteger> &userEmptyBuckets) const;

		/// Copy constructor - not implemented
		Client (Client const &);

		/// Copy assignment operator - not implemented
		Client operator= (Client const &);
	};
}//namespace PrivateRecommendationsDataPacking
}//namespace SeComLib

#endif//CLIENT_HEADER_GUARD