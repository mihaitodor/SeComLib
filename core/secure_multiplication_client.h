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
@file core/secure_multiplication_client.h
@brief Definition of template class SecureMultiplicationClient.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SECURE_MULTIPLICATION_CLIENT_HEADER_GUARD
#define SECURE_MULTIPLICATION_CLIENT_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "big_integer.h"
#include "random_provider.h"
#include "secure_multiplication_server.h"

namespace SeComLib {
namespace Core {
	//forward-declare required classes
	template <typename T_CryptoProvider>
	class SecureMultiplicationServer;

	/**
	@brief Secure Multiplication Client
	@tparam T_CryptoProvider The type of the crypto provider, which must be derived from template class CryptoProvider
	*/
	template <typename T_CryptoProvider>
	class SecureMultiplicationClient {
	public:
		/// Constructor
		SecureMultiplicationClient (const T_CryptoProvider &cryptoProvider);

		/// Destructor - void implementation
		~SecureMultiplicationClient () {}

		/// Computes the encrypted product
		typename T_CryptoProvider::Ciphertext Multiply (const typename T_CryptoProvider::Ciphertext &lhs, const typename T_CryptoProvider::Ciphertext &rhs) const;

		/// Setter for this->secureMultiplicationServer
		void SetServer (const std::shared_ptr<SecureMultiplicationServer<T_CryptoProvider>> &secureMultiplicationServer);

	private:
		/// Reference to the crypto provider
		const T_CryptoProvider &cryptoProvider;

		/// A reference to the SecureMultiplicationServer
		std::shared_ptr<const SecureMultiplicationServer<T_CryptoProvider>> secureMultiplicationServer;

		/// Copy constructor - not implemented
		SecureMultiplicationClient (SecureMultiplicationClient const &);

		/// Copy assignment operator - not implemented
		SecureMultiplicationClient operator= (SecureMultiplicationClient const &);
	};
}//namespace Core
}//namespace SeComLib

//Separate the implementation from the declaration of template methods
#include "secure_multiplication_client.hpp"

#endif//SECURE_MULTIPLICATION_CLIENT_HEADER_GUARD