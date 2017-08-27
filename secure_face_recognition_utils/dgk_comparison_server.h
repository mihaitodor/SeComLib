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
@file secure_face_recognition_utils/dgk_comparison_server.h
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
#include "core/secure_permutation.h"

#include "dgk_comparison_blinding_factor_container.h"
#include "dgk_comparison_blinding_factor_cache_parameters.h"

//include C++ headers
#include <deque>

namespace SeComLib {
using namespace Core;

namespace SecureFaceRecognitionUtils {
	//forward-declare required classes
	class DgkComparisonClient;

	/**
	@brief DGK Comparison Server
	*/
	class DgkComparisonServer {
	public:
		/// Constructor
		DgkComparisonServer (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const std::string &configurationPath);

		/// Destructor - void implementation
		~DgkComparisonServer () {}

		/// Compute @f$ \lambda @f$
		Paillier::Ciphertext ComputeLambda (const std::deque<long> &hatRBits, const BigInteger &s);

		/// Setter for this->dgkComparisonClient
		void SetClient (const std::shared_ptr<DgkComparisonClient> & dgkComparisonClient);

	private:
		/// Alias for the blinding factor container
		typedef DgkComparisonBlindingFactorContainer<Dgk, DgkComparisonBlindingFactorCacheParameters> BlindingFactorContainer;

		/// Reference to the Paillier crypto provider
		const Paillier &paillierCryptoProvider;

		/// Reference to the DGK crypto provider
		const Dgk &dgkCryptoProvider;

		/// A reference to the DgkComparisonClient
		std::weak_ptr<const DgkComparisonClient> dgkComparisonClient;

		/// Bitsize of comparison operands
		size_t l;

		/// @f$ [-2^l] @f$
		Paillier::Ciphertext encryptedMinusTwoPowL;

		/// Blinding factor cache instance
		RandomizerCache<BlindingFactorContainer> blindingFactorCache;

		/// Copy constructor - not implemented
		DgkComparisonServer (DgkComparisonServer const &);

		/// Copy assignment operator - not implemented
		DgkComparisonServer operator= (DgkComparisonServer const &);
	};
}//namespace SecureFaceRecognitionUtils
}//namespace SeComLib

#endif//DGK_COMPARISON_SERVER_HEADER_GUARD