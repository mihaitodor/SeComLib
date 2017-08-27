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
@file core/secure_multiplication_client.hpp
@brief Implementation of template members from class SecureMultiplicationClient. To be included in secure_multiplication_client.h
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SECURE_MULTIPLICATION_CLIENT_IMPLEMENTATION_GUARD
#define SECURE_MULTIPLICATION_CLIENT_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Core {
	/**
	@param cryptoProvider the crypto provider
	*/
	template <typename T_CryptoProvider>
	SecureMultiplicationClient<T_CryptoProvider>::SecureMultiplicationClient (const T_CryptoProvider &cryptoProvider) :
		cryptoProvider(cryptoProvider) {
	}

	/**
	@param lhs left hand side operand (encrypted integer)
	@param rhs right hand side operand (encrypted integer)
	@return The encrypted product of lhs and rhs
	*/
	template <typename T_CryptoProvider>
	typename T_CryptoProvider::Ciphertext SecureMultiplicationClient<T_CryptoProvider>::Multiply (const typename T_CryptoProvider::Ciphertext &lhs, const typename T_CryptoProvider::Ciphertext &rhs) const {
		BigInteger a = this->cryptoProvider.DecryptInteger(lhs);
		BigInteger b = this->cryptoProvider.DecryptInteger(rhs);

		return this->cryptoProvider.EncryptInteger(a * b);
	}

	/**
	@param secureMultiplicationServer a SecureMultiplicationServer instance
	*/
	template <typename T_CryptoProvider>
	void SecureMultiplicationClient<T_CryptoProvider>::SetServer (const std::shared_ptr<SecureMultiplicationServer<T_CryptoProvider>> &secureMultiplicationServer) {
		this->secureMultiplicationServer = secureMultiplicationServer;
	}

}//namespace Core
}//namespace SeComLib

#endif//SECURE_MULTIPLICATION_CLIENT_IMPLEMENTATION_GUARD