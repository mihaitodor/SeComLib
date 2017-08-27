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
@file core/secure_extremum_selection_client.h
@brief Definition of template class SecureExtremumSelectionClient.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SECURE_EXTREMUM_SELECTION_CLIENT_HEADER_GUARD
#define SECURE_EXTREMUM_SELECTION_CLIENT_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "big_integer.h"
#include "random_provider.h"
#include "randomizer_cache.h"
#include "paillier.h"
#include "dgk.h"
#include "secure_multiplication_server.h"

#include "secure_extremum_selection_server.h"

namespace SeComLib {
namespace Core {
	//forward-declare required classes
	template <typename T_SecureComparisonServer, typename T_SecureComparisonClient>
	class SecureExtremumSelectionServer;

	/**
	@brief Secure Extremum Selection Client
	@tparam T_SecureComparisonServer The Comparison Server
	@tparam T_SecureComparisonClient The Comparison Client
	*/
	template <typename T_SecureComparisonServer, typename T_SecureComparisonClient>
	class SecureExtremumSelectionClient {
	public:
		/// Constructor
		SecureExtremumSelectionClient (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const std::string &configurationPath);

		/// Destructor - void implementation
		~SecureExtremumSelectionClient () {}

		/// Setter for this->secureExtremumSelectionServer
		void SetServer (const std::shared_ptr<SecureExtremumSelectionServer<T_SecureComparisonServer, T_SecureComparisonClient>> &secureExtremumSelectionServer);

		/// Getter for this->secureComparisonClient
		const std::shared_ptr<T_SecureComparisonClient> &GetSecureComparisonClient () const;

		/// Getter for this->secureMultiplicationClient
		const std::shared_ptr<SecureMultiplicationClient<Paillier>> &GetSecureMultiplicationClient () const;

	private:
		/// Reference to the Paillier crypto provider
		const Paillier &paillierCryptoProvider;

		/// Reference to the DGK crypto provider
		const Dgk &dgkCryptoProvider;

		/// A reference to the SecureExtremumSelectionServer
		std::shared_ptr<const SecureExtremumSelectionServer<T_SecureComparisonServer, T_SecureComparisonClient>> secureExtremumSelectionServer;

		/// A reference to the SecureComparisonClient
		const std::shared_ptr<T_SecureComparisonClient> secureComparisonClient;

		/// A reference to the SecureMultiplicationClient
		const std::shared_ptr<SecureMultiplicationClient<Paillier>> secureMultiplicationClient;

		/// Copy constructor - not implemented
		SecureExtremumSelectionClient (SecureExtremumSelectionClient const &);

		/// Copy assignment operator - not implemented
		SecureExtremumSelectionClient operator= (SecureExtremumSelectionClient const &);
	};
}//namespace Core
}//namespace SeComLib

//Separate the implementation from the declaration of template methods
#include "secure_extremum_selection_client.hpp"

#endif//SECURE_EXTREMUM_SELECTION_CLIENT_HEADER_GUARD