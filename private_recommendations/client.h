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
@file private_recommendations/client.h
@brief Definition of class Client.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef CLIENT_HEADER_GUARD
#define CLIENT_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "utils/cpu_timer.h"
#include "core/paillier.h"
#include "core/randomizer_cache.h"
#include "core/blinding_factor_cache_parameters.h"

#include "private_recommendations_utils/decryption_blinding_factor_container.h"
#include "service_provider.h"
#include "privacy_service_provider.h"

//include C++ libraries
#include <string>
#include <deque>
#include <stdexcept>

namespace SeComLib {

using namespace Core;
using namespace PrivateRecommendationsUtils;

//hackish way of computing everything for only a single user (see also service_provider.h)
#define FIRST_USER_ONLY

namespace PrivateRecommendations {
	/**
	@brief Client
	*/
	class Client {
	public:

		/// Constructor
		Client (const std::shared_ptr<ServiceProvider> &serviceProvider, const std::shared_ptr<PrivacyServiceProvider> &privacyServiceProvider, const PaillierPublicKey &publicKey);

		/// Destructor - void implementation
		~Client () {}

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

		/// Blinding factor cache instance
		RandomizerCache<BlindingFactorContainer> blindingFactorCache;

		/// Service Provider configuration path
		static const std::string configurationPath;

		/// Number of users who need recommendations
		size_t userCount;

		/// Copy constructor - not implemented
		Client (Client const &);

		/// Copy assignment operator - not implemented
		Client operator= (Client const &);
	};
}//namespace PrivateRecommendations
}//namespace SeComLib

#endif//CLIENT_HEADER_GUARD