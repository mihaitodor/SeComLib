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
@file core/secure_multiplication_server.hpp
@brief Implementation of template members from class SecureMultiplicationServer. To be included in secure_multiplication_server.h
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SECURE_MULTIPLICATION_SERVER_IMPLEMENTATION_GUARD
#define SECURE_MULTIPLICATION_SERVER_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Core {
	/**
	@param cryptoProvider the Paillier crypto provider
	@param l bitsize of the multiplication operands
	@param configurationPath the configuration path for parameters
	*/
	template <typename T_CryptoProvider>
	SecureMultiplicationServer<T_CryptoProvider>::SecureMultiplicationServer (const T_CryptoProvider &cryptoProvider, const size_t l, const std::string &configurationPath) :
		cryptoProvider(cryptoProvider),
		blindingFactorCache(cryptoProvider, BlindingFactorCacheParameters(configurationPath + ".BlindingFactorCache", l)) {
	}

	/**
	Computes @f$ [\tilde{v}_{(A, r)}^d] \otimes [\tilde{v}_{(B, r)}^d] @f$.

	Algorithm:
	- @f$ [\tilde{a}] = [a] [-r_1] = [a - r_1]; [\tilde{b}] = [b] [-r_2] = [b - r_2] @f$
	- send @f$ [\tilde{a}] and [\tilde{b}] @f$ to PSP
	- PSP decrypts @f$ [\tilde{a}] @f$ and @f$ [\tilde{b}] @f$ and sends @f$ [\tilde{a} \tilde{b}] @f$ back to PS
	- PS computes @f$ [a b] = [\tilde{a} \tilde{b}] [a]^{r_2} [b]^{r_1} [-r_1 r_2] = [\tilde{a} \tilde{b} + a r_2 + b r_1 - r_1 r_2] @f$

	@param lhs left hand side operand (Paillier encrypted integer)
	@param rhs right hand side operand (Paillier encrypted integer)
	@return The encrypted product of lhs and rhs
	*/
	template <typename T_CryptoProvider>
	typename T_CryptoProvider::Ciphertext SecureMultiplicationServer<T_CryptoProvider>::Multiply (const typename T_CryptoProvider::Ciphertext &lhs, const typename T_CryptoProvider::Ciphertext &rhs) {
		const BlindingFactorContainer &blindingFactorContainer = this->blindingFactorCache.Pop();

		typename T_CryptoProvider::Ciphertext blindedVTildeA = lhs + blindingFactorContainer.encryptedMinusR1;
		typename T_CryptoProvider::Ciphertext blindedVTildeB = rhs + blindingFactorContainer.encryptedMinusR2;

		//interact with the server
		typename T_CryptoProvider::Ciphertext output = this->secureMultiplicationClient.lock()->Multiply(blindedVTildeA, blindedVTildeB);
		
		output = output + lhs * blindingFactorContainer.r2 + rhs * blindingFactorContainer.r1 + blindingFactorContainer.encryptedMinusR1R2;

		return output;
	}

	/**
	@param secureMultiplicationClient a SecureMultiplicationClient instance
	*/
	template <typename T_CryptoProvider>
	void SecureMultiplicationServer<T_CryptoProvider>::SetClient (const std::shared_ptr<SecureMultiplicationClient<T_CryptoProvider>> &secureMultiplicationClient) {
		this->secureMultiplicationClient = secureMultiplicationClient;
	}

}//namespace Core
}//namespace SeComLib

#endif//SECURE_MULTIPLICATION_SERVER_IMPLEMENTATION_GUARD