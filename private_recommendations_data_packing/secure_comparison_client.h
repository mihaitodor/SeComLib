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
@file private_recommendations_data_packing/secure_comparison_client.h
@brief Definition of class SecureComparisonClient.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SECURE_COMPARISON_CLIENT_HEADER_GUARD
#define SECURE_COMPARISON_CLIENT_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "core/big_integer.h"
#include "core/random_provider.h"
#include "core/paillier.h"
#include "core/dgk.h"

#include "private_recommendations_utils/dgk_comparison_client.h"

//include C++ headers
#include <deque>

namespace SeComLib {
using namespace Core;
using namespace PrivateRecommendationsUtils;

namespace PrivateRecommendationsDataPacking {
	//forward-declare required classes
	class SecureComparisonServer;

	/**
	@brief Secure Comparison Client
	*/
	class SecureComparisonClient {
	public:
		/// Constructor
		SecureComparisonClient (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider);

		/// Destructor - void implementation
		~SecureComparisonClient () {}

		/// Computes @f$ z^{(i)} @f$
		void UnpackZ (const Paillier::Ciphertext &z, const std::deque<BigInteger> &emptyBuckets, const size_t encryptedBucketsCount);

		/// Specifies which @f$ z^{(i)} @f$ to send to the dgkComparisonClient for the current comparison
		void SetZi (const size_t i) const;

		/// Setter for this->secureComparisonServer
		void SetServer (const std::shared_ptr<SecureComparisonServer> &secureComparisonServer);

		/// Getter for this->dgkComparisonClient
		const std::shared_ptr<DgkComparisonClient> &GetDgkComparisonClient () const;

		/// Decrypts and prints a Paillier encrypted integer
		void DebugPaillierEncryption (const Paillier::Ciphertext &input) const;

	private:
		/// Reference to the Paillier crypto provider
		const Paillier &paillierCryptoProvider;

		/// Reference to the DGK crypto provider
		const Dgk &dgkCryptoProvider;

		/// A reference to the SecureComparisonServer
		std::shared_ptr<const SecureComparisonServer> secureComparisonServer;

		/// A reference to the DgkComparisonClient
		const std::shared_ptr<DgkComparisonClient> dgkComparisonClient;

		/// @f$ z^{(i)} @f$
		std::deque<BigInteger> zi;

		/// Copy constructor - not implemented
		SecureComparisonClient (SecureComparisonClient const &);

		/// Copy assignment operator - not implemented
		SecureComparisonClient operator= (SecureComparisonClient const &);
	};
}//namespace PrivateRecommendationsDataPacking
}//namespace SeComLib

#endif//SECURE_COMPARISON_CLIENT_HEADER_GUARD