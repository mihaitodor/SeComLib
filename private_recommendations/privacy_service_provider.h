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
@file private_recommendations/privacy_service_provider.h
@brief Definition of class PrivacyServiceProvider.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef PRIVACY_SERVICE_PROVIDER_HEADER_GUARD
#define PRIVACY_SERVICE_PROVIDER_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "core/big_integer.h"
#include "core/random_provider.h"
#include "core/paillier.h"
#include "core/dgk.h"
#include "core/secure_multiplication_client.h"

#include "private_recommendations_utils/secure_comparison_client.h"

//include C++ libraries
#include <string>
#include <deque>
#include <stdexcept>

namespace SeComLib {

using namespace Core;
using namespace PrivateRecommendationsUtils;

namespace PrivateRecommendations {
	//forward-declare required classes
	class ServiceProvider;

	/**
	@brief Privacy Service Provider
	*/
	class PrivacyServiceProvider {
	public:
		/// Container for encrypted user rating vectors
		typedef std::deque<std::deque<Paillier::Ciphertext>> EncryptedRatings;

		/// Default constructor
		PrivacyServiceProvider ();

		/// Destructor - void implementation
		~PrivacyServiceProvider () {}

		/// Decrypts a blinded Paillier ciphertext
		BigInteger SecureDecryption (const Paillier::Ciphertext &input) const;

		/// Sets a reference to the Privacy Service Provider
		void SetServiceProvider (const std::shared_ptr<const ServiceProvider> &serviceProvider);

		/// Getter for this->secureComparisonClient
		const std::shared_ptr<SecureComparisonClient> &GetSecureComparisonClient () const;

		/// Getter for this->secureMultiplicationClient
		const std::shared_ptr<SecureMultiplicationClient<Paillier>> &GetSecureMultiplicationClient () const;

		/// Getter for the Paillier crypto provider public key
		const PaillierPublicKey &GetPaillierPublicKey () const;

		/// Getter for the DGK crypto provider public key
		const DgkPublicKey &GetDgkPublicKey () const;

		/// Decrypts and prints a Paillier encrypted integer
		void DebugPaillierEncryption (const Paillier::Ciphertext &input) const;

	private:
		/// The Paillier crypto provider
		Paillier paillierCryptoProvider;

		/// The DGK crypto provider
		Dgk dgkCryptoProvider;

		/// A reference to the ServiceProvider
		std::shared_ptr<const ServiceProvider> serviceProvider;

		/// A reference to the SecureComparisonClient
		std::shared_ptr<SecureComparisonClient> secureComparisonClient;

		/// A reference to the SecureMultiplicationClient
		std::shared_ptr<SecureMultiplicationClient<Paillier>> secureMultiplicationClient;

		/// Service Provider configuration path
		static const std::string configurationPath;

		/// Copy constructor - not implemented
		PrivacyServiceProvider (PrivacyServiceProvider const &);

		/// Copy assignment operator - not implemented
		PrivacyServiceProvider operator= (PrivacyServiceProvider const &);
	};
}//namespace PrivateRecommendations
}//namespace SeComLib

#endif//PRIVACY_SERVICE_PROVIDER_HEADER_GUARD