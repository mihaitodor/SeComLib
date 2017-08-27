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
@file private_recommendations_utils/dgk_comparison_server.h
@brief Definition of class DgkComparisonServer.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef DGK_COMPARISON_SERVER_HEADER_GUARD
#define DGK_COMPARISON_SERVER_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "core/big_integer.h"
#include "core/random_provider.h"
#include "core/paillier.h"
#include "core/dgk.h"

namespace SeComLib {
using namespace Core;

namespace PrivateRecommendationsUtils {
	//forward-declare required classes
	class DgkComparisonClient;

	/**
	@brief DGK Comparison Server
	*/
	class DgkComparisonServer {
	public:
		/// Constructor
		DgkComparisonServer (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const size_t l);

		/// Destructor - void implementation
		~DgkComparisonServer () {}

		/// Interactive secure comparison
		Paillier::Ciphertext Compare (const BigInteger &rModTwoPowL) const;

		/// Computes @f$ d_{l + 1}^{(i)} = r_{l + 1}^{(i)} \oplus z_{l + 1}^{(i)} \oplus C_{i(l + 2) + (l + 1)} @f$
		Paillier::Ciphertext ComputeDi (const BigInteger &rModTwoPowL) const;

		/// Returns the bit position of the MSB of the operands (since l is not available for the dgkComparisonClient)
		size_t GetMSBPosition () const;

		/// Setter for this->dgkComparisonClient
		void SetClient (const std::shared_ptr<DgkComparisonClient> &dgkComparisonClient);

	private:
		/// Reference to the Paillier crypto provider
		const Paillier &paillierCryptoProvider;

		/// Reference to the DGK crypto provider
		const Dgk &dgkCryptoProvider;

		/// A reference to the DgkComparisonClient
		std::weak_ptr<const DgkComparisonClient> dgkComparisonClient;

		/// Bitsize of comparison operands
		size_t l;

		/// Computes the encrypted additive share of the client
		Dgk::Ciphertext computeTau (const BigInteger &a, const BigInteger &tSP) const;

		/// Copy constructor - not implemented
		DgkComparisonServer (DgkComparisonServer const &);

		/// Copy assignment operator - not implemented
		DgkComparisonServer operator= (DgkComparisonServer const &);
	};
}//namespace PrivateRecommendationsUtils
}//namespace SeComLib

#endif//DGK_COMPARISON_SERVER_HEADER_GUARD