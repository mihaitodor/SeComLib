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
@file core/secure_multiplication_server.h
@brief Definition of template class SecureMultiplicationServer.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SECURE_MULTIPLICATION_SERVER_HEADER_GUARD
#define SECURE_MULTIPLICATION_SERVER_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "big_integer.h"
#include "random_provider.h"
#include "randomizer_cache.h"
#include "blinding_factor_cache_parameters.h"
#include "secure_multiplication_blinding_factor_container.h"
#include "secure_multiplication_client.h"

namespace SeComLib {
namespace Core {
	//forward-declare required classes
	template <typename T_CryptoProvider>
	class SecureMultiplicationClient;

	/**
	@brief Secure Multiplication Server
	@tparam T_CryptoProvider The type of the crypto provider, which must be derived from template class CryptoProvider
	*/
	template <typename T_CryptoProvider>
	class SecureMultiplicationServer {
	public:
		/// Constructor
		SecureMultiplicationServer (const T_CryptoProvider &cryptoProvider, const size_t l, const std::string &configurationPath);

		/// Destructor - void implementation
		~SecureMultiplicationServer () {}

		/// Interactive secure multiplication
		typename T_CryptoProvider::Ciphertext Multiply (const typename T_CryptoProvider::Ciphertext &lhs, const typename T_CryptoProvider::Ciphertext &rhs);

		/// Setter for this->secureMultiplicationClient
		void SetClient (const std::shared_ptr<SecureMultiplicationClient<T_CryptoProvider>> &secureMultiplicationClient);

	private:
		/// Alias for the blinding factor container
		typedef SecureMultiplicationBlindingFactorContainer<T_CryptoProvider, BlindingFactorCacheParameters> BlindingFactorContainer;

		/// Reference to the crypto provider
		const T_CryptoProvider &cryptoProvider;

		/// Blinding factor cache instance
		RandomizerCache<BlindingFactorContainer> blindingFactorCache;

		/// A reference to the SecureMultiplicationClient
		std::weak_ptr<const SecureMultiplicationClient<T_CryptoProvider>> secureMultiplicationClient;

		/// Copy constructor - not implemented
		SecureMultiplicationServer (SecureMultiplicationServer const &);

		/// Copy assignment operator - not implemented
		SecureMultiplicationServer operator= (SecureMultiplicationServer const &);
	};
}//namespace Core
}//namespace SeComLib

//Separate the implementation from the declaration of template methods
#include "secure_multiplication_server.hpp"

#endif//SECURE_MULTIPLICATION_SERVER_HEADER_GUARD