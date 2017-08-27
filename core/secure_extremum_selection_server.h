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
@file core/secure_extremum_selection_server.h
@brief Definition of template class SecureExtremumSelectionServer.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SECURE_EXTREMUM_SELECTION_SERVER_HEADER_GUARD
#define SECURE_EXTREMUM_SELECTION_SERVER_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "big_integer.h"
#include "random_provider.h"
#include "randomizer_cache.h"
#include "paillier.h"
#include "dgk.h"
#include "secure_multiplication_server.h"

#include "secure_extremum_selection_client.h"

namespace SeComLib {
namespace Core {
	//forward-declare required classes
	template <typename T_SecureComparisonServer, typename T_SecureComparisonClient>
	class SecureExtremumSelectionClient;

	/**
	@brief Secure Extremum Selection Server
	@tparam T_SecureComparisonServer The Comparison Server
	@tparam T_SecureComparisonClient The Comparison Client
	*/
	template <typename T_SecureComparisonServer, typename T_SecureComparisonClient>
	class SecureExtremumSelectionServer {
	public:
		/// Alias for the item container
		typedef std::vector<Paillier::Ciphertext> ItemContainer;

		/// Constructor
		SecureExtremumSelectionServer (const Paillier &paillierCryptoProvider, const Dgk &dgkCryptoProvider, const std::string &configurationPath);

		/// Destructor - void implementation
		~SecureExtremumSelectionServer () {}

		/// Interactive secure minimum selection
		Paillier::Ciphertext GetMinimum (const ItemContainer &items) const;

		/// Interactive secure maximum selection
		Paillier::Ciphertext GetMaximum (const ItemContainer &items) const;

		/// Setter for this->secureExtremumSelectionClient
		void SetClient (const std::shared_ptr<SecureExtremumSelectionClient<T_SecureComparisonServer, T_SecureComparisonClient>> &secureExtremumSelectionClient);

		/// Getter for this->secureComparisonServer
		const std::shared_ptr<T_SecureComparisonServer> &GetSecureComparisonServer () const;

		/// Getter for this->secureMultiplicationServer
		const std::shared_ptr<SecureMultiplicationServer<Paillier>> &GetSecureMultiplicationServer () const;

	private:
		/// Reference to the Paillier crypto provider
		const Paillier &paillierCryptoProvider;

		/// Reference to the DGK crypto provider
		const Dgk &dgkCryptoProvider;

		/// A reference to the SecureExtremumSelectionClient
		std::weak_ptr<const SecureExtremumSelectionClient<T_SecureComparisonServer, T_SecureComparisonClient>> secureExtremumSelectionClient;

		/// A reference to the SecureComparisonServer
		const std::shared_ptr<T_SecureComparisonServer> secureComparisonServer;

		/// A reference to the SecureMultiplicationServer
		const std::shared_ptr<SecureMultiplicationServer<Paillier>> secureMultiplicationServer;

		/// Copy constructor - not implemented
		SecureExtremumSelectionServer (SecureExtremumSelectionServer const &);

		/// Copy assignment operator - not implemented
		SecureExtremumSelectionServer operator= (SecureExtremumSelectionServer const &);
	};
}//namespace Core
}//namespace SeComLib

//Separate the implementation from the declaration of template methods
#include "secure_extremum_selection_server.hpp"

#endif//SECURE_EXTREMUM_SELECTION_SERVER_HEADER_GUARD