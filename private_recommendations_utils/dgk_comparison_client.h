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
@file private_recommendations_utils/dgk_comparison_client.h
@brief Definition of class DgkComparisonClient.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef DGK_COMPARISON_CLIENT_HEADER_GUARD
#define DGK_COMPARISON_CLIENT_HEADER_GUARD

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
	class DgkComparisonServer;

	/**
	@brief DGK Comparison Client
	*/
	class DgkComparisonClient {
	public:
		/// Constructor
		DgkComparisonClient (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider);

		/// Destructor - void implementation
		~DgkComparisonClient () {}

		/// Set @f$ z \pmod 2^l @f$ before the comparison protocol is initiated
		void SetZModTwoPowL (const BigInteger &zModTwoPowL);
		
		/// Computes @f$ \llbracket tb \rrbracket @f$ for @f$ \llbracket b_i \rrbracket @f$
		Dgk::Ciphertext GetTb (const Dgk::Ciphertext &tau, const size_t i) const;

		/// Extracts bit i from @f$ [z \pmod 2^l] @f$ and encrypts it
		Dgk::Ciphertext GetBi (const size_t i) const;

		/// Converts @f$ \llbracket \tau \rrbracket @f$ to @f$ [\tau] @f$
		Paillier::Ciphertext ConvertToPaillier (const Dgk::Ciphertext &dgkCiphertext) const;

		/// Computes @f$ [d_{l + 1}^{(i, PSP)}] = [z_{l + 1}^{(i)} \oplus C_{i(l + 2) + (l + 1)}^{PSP}] @f$
		Paillier::Ciphertext ComputeDiPSP (const Dgk::Ciphertext &CiPSP) const;

		/// Setter for this->dgkComparisonServer
		void SetServer (const std::shared_ptr<DgkComparisonServer> &dgkComparisonServer);

		/// Prints 0 if the received encryption is [0] and 1 otherwise
		void DebugDgkEncryption (const Dgk::Ciphertext &input) const;

	private:
		/// Reference to the Paillier crypto provider
		const Paillier &paillierCryptoProvider;

		/// Reference to the DGK crypto provider
		const Dgk &dgkCryptoProvider;

		/// The @f$ b @f$ term of the comparison
		BigInteger b;

		/// A reference to the DgkComparisonServer
		std::shared_ptr<const DgkComparisonServer> dgkComparisonServer;

		/// Copy constructor - not implemented
		DgkComparisonClient (DgkComparisonClient const &);

		/// Copy assignment operator - not implemented
		DgkComparisonClient operator= (DgkComparisonClient const &);
	};
}//namespace PrivateRecommendationsUtils
}//namespace SeComLib

#endif//DGK_COMPARISON_CLIENT_HEADER_GUARD