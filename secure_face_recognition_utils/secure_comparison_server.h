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
@file secure_face_recognition_utils/secure_comparison_server.h
@brief Definition of class SecureComparisonServer.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SECURE_COMPARISON_SERVER_HEADER_GUARD
#define SECURE_COMPARISON_SERVER_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "core/big_integer.h"
#include "core/random_provider.h"
#include "core/paillier.h"
#include "core/dgk.h"
#include "core/randomizer_cache.h"

#include "comparison_blinding_factor_container.h"
#include "comparison_blinding_factor_cache_parameters.h"
#include "dgk_comparison_server.h"

namespace SeComLib {
using namespace Core;

namespace SecureFaceRecognitionUtils {
	//forward-declare required classes
	class SecureComparisonClient;

	/**
	@brief Secure Comparison Server
	*/
	class SecureComparisonServer {
	public:
		/// Constructor
		SecureComparisonServer (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const std::string &configurationPath);

		/// Destructor - void implementation
		~SecureComparisonServer () {}

		/// Interactive secure comparison
		Paillier::Ciphertext Compare (const Paillier::Ciphertext &a, const Paillier::Ciphertext &b);

		/// Setter for this->secureComparisonClient
		void SetClient (const std::shared_ptr<SecureComparisonClient> & secureComparisonClient);

		/// Getter for this->dgkComparisonServer
		const std::shared_ptr<DgkComparisonServer> &GetDgkComparisonServer () const;

	private:
		/// Alias for the blinding factor container
		typedef ComparisonBlindingFactorContainer<Paillier, ComparisonBlindingFactorCacheParameters> BlindingFactorContainer;

		/// Reference to the Paillier crypto provider
		const Paillier &paillierCryptoProvider;

		/// Reference to the DGK crypto provider
		const Dgk &dgkCryptoProvider;

		/// A reference to the SecureComparisonClient
		std::weak_ptr<const SecureComparisonClient> secureComparisonClient;

		/// A reference to the DgkComparisonServer
		const std::shared_ptr<DgkComparisonServer> dgkComparisonServer;

		/// Bitsize of comparison operands
		size_t l;

		/// @f$ 2^l @f$
		BigInteger twoPowL;

		/// @f$ 2^{-l} \pmod n @f$
		BigInteger twoPowMinusLModN;

		/// @f$ [2^l] @f$
		Paillier::Ciphertext encryptedTwoPowL;

		/// Blinding factor cache instance
		RandomizerCache<BlindingFactorContainer> blindingFactorCache;

		/// Copy constructor - not implemented
		SecureComparisonServer (SecureComparisonServer const &);

		/// Copy assignment operator - not implemented
		SecureComparisonServer operator= (SecureComparisonServer const &);
	};
}//namespace SecureFaceRecognitionUtils
}//namespace SeComLib

#endif//SERVICE_PROVIDER_HEADER_GUARD