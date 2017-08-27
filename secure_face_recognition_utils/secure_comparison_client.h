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
@file secure_face_recognition_utils/secure_comparison_client.h
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

#include "dgk_comparison_client.h"

namespace SeComLib {
using namespace Core;

namespace SecureFaceRecognitionUtils {
	//forward-declare required classes
	class SecureComparisonServer;

	/**
	@brief Secure Comparison Client
	*/
	class SecureComparisonClient {
	public:
		/// Constructor
		SecureComparisonClient (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const std::string &configurationPath);

		/// Destructor - void implementation
		~SecureComparisonClient () {}

		/// Computes @f$ [-(d \pmod {2^l})] @f$
		Paillier::Ciphertext ComputeMinusDModTwoPowL (const Paillier::Ciphertext &d) const;

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

		/// Bitsize of comparison operands
		size_t l;

		/// @f$ 2^l @f$
		BigInteger twoPowL;

		/// Copy constructor - not implemented
		SecureComparisonClient (SecureComparisonClient const &);

		/// Copy assignment operator - not implemented
		SecureComparisonClient operator= (SecureComparisonClient const &);
	};
}//namespace SecureFaceRecognitionUtils
}//namespace SeComLib

#endif//SECURE_COMPARISON_CLIENT_HEADER_GUARD